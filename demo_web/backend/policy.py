from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .models import Decision, PolicyTrace, ScanSummary, Severity


DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "admission_policy.yaml"
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.SAFE: 5,
    Severity.UNKNOWN: 6,
}


class PolicyConfigurationError(RuntimeError):
    """Raised when the local admission policy cannot be trusted."""


class DecisionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    block_severities: set[Severity] = Field(min_length=1)
    review_severities: set[Severity] = Field(min_length=1)
    allow_severities: set[Severity] = Field(min_length=1)
    fail_closed: bool = True

    @model_validator(mode="after")
    def validate_partition(self) -> "DecisionPolicy":
        groups = [self.block_severities, self.review_severities, self.allow_severities]
        if any(Severity.UNKNOWN in group for group in groups):
            raise ValueError("UNKNOWN 必须由失败闭锁分支处理，不能放入普通严重度集合")
        if not self.fail_closed:
            raise ValueError("供应链准入策略必须启用 fail_closed")
        if any(groups[left] & groups[right] for left in range(3) for right in range(left + 1, 3)):
            raise ValueError("block/review/allow 严重度集合不能重叠")
        expected = set(Severity) - {Severity.UNKNOWN}
        configured = set().union(*groups)
        if configured != expected:
            missing = sorted((item.value for item in expected - configured))
            extra = sorted((item.value for item in configured - expected))
            raise ValueError(f"严重度集合必须完整覆盖；missing={missing}, extra={extra}")
        return self


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    policy_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str = ""
    decision: DecisionPolicy


class PolicyEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    trace: PolicyTrace


def parse_severity(value: Any) -> Severity:
    try:
        return Severity(str(value or Severity.UNKNOWN.value).upper())
    except ValueError:
        return Severity.UNKNOWN


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> PolicyConfig:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("YAML 顶层必须是对象")
        return PolicyConfig.model_validate(payload)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as exc:
        raise PolicyConfigurationError(f"准入策略配置无效：{exc}") from exc


def _sorted_severities(severities: set[Severity]) -> list[Severity]:
    return sorted(severities, key=lambda item: SEVERITY_ORDER[item])


def _matching_finding_ids(
    findings: list[dict[str, Any]], matched: set[Severity]
) -> list[str]:
    result: list[str] = []
    for index, finding in enumerate(findings, start=1):
        if parse_severity(finding.get("severity")) in matched:
            result.append(str(finding.get("id") or f"finding-{index}"))
    return result


def _format_counts(severities: list[Severity]) -> str:
    counts: dict[Severity, int] = {}
    for severity in severities:
        counts[severity] = counts.get(severity, 0) + 1
    return "、".join(
        f"{severity.value} {counts[severity]} 条"
        for severity in _sorted_severities(set(counts))
    )


def evaluate_findings(
    findings: list[dict[str, Any]], policy: PolicyConfig | None = None
) -> PolicyEvaluation:
    selected = policy or load_policy()
    severities = [parse_severity(item.get("severity")) for item in findings]
    configured = selected.decision

    block_matches = set(severities) & configured.block_severities
    if block_matches:
        decision = Decision.BLOCK
        rule_id = "POLICY_BLOCK_SEVERITY"
        reason = f"命中阻断严重度：{_format_counts([item for item in severities if item in block_matches])}。"
        matched = block_matches
    elif Severity.UNKNOWN in severities:
        decision = Decision.UNKNOWN
        rule_id = "POLICY_UNKNOWN_SEVERITY"
        unknown_count = severities.count(Severity.UNKNOWN)
        reason = f"存在 UNKNOWN 严重度 {unknown_count} 条，按照失败闭锁策略不放行。"
        matched = {Severity.UNKNOWN}
    else:
        review_matches = set(severities) & configured.review_severities
        if review_matches:
            decision = Decision.REVIEW
            rule_id = "POLICY_REVIEW_SEVERITY"
            reason = f"命中人工复核严重度：{_format_counts([item for item in severities if item in review_matches])}。"
            matched = review_matches
        else:
            decision = Decision.ALLOW
            rule_id = "POLICY_ALLOW"
            reason = "扫描成功，所有发现均处于允许严重度集合，准入策略允许继续。"
            matched = set(severities) & configured.allow_severities

    trace = PolicyTrace(
        policy_id=selected.policy_id,
        policy_version=selected.version,
        rule_id=rule_id,
        reason=reason,
        matched_severities=_sorted_severities(matched),
        matched_finding_ids=_matching_finding_ids(findings, matched),
        fail_closed=configured.fail_closed,
    )
    return PolicyEvaluation(decision=decision, trace=trace)


def pending_policy_trace(path: Path = DEFAULT_POLICY_PATH) -> PolicyTrace:
    try:
        selected = load_policy(path)
        return PolicyTrace(
            policy_id=selected.policy_id,
            policy_version=selected.version,
            rule_id="PENDING_SCAN",
            reason="扫描尚未完成，暂未执行准入策略。",
            fail_closed=selected.decision.fail_closed,
        )
    except PolicyConfigurationError as exc:
        return PolicyTrace(
            policy_id="unavailable",
            policy_version="unavailable",
            rule_id="POLICY_CONFIGURATION_ERROR",
            reason=str(exc),
            fail_closed=True,
        )


def failure_policy_trace(rule_id: str, reason: str) -> PolicyTrace:
    pending = pending_policy_trace()
    return PolicyTrace(
        policy_id=pending.policy_id,
        policy_version=pending.policy_version,
        rule_id=rule_id,
        reason=reason,
        fail_closed=True,
    )


def decision_from_findings(
    findings: list[dict[str, Any]], policy: PolicyConfig | None = None
) -> str:
    return evaluate_findings(findings, policy).decision.value


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = ScanSummary(total_findings=len(findings))
    counts = summary.model_dump()
    for finding in findings:
        severity = parse_severity(finding.get("severity"))
        key = severity.value.lower()
        if key in counts:
            counts[key] += 1
    return ScanSummary.model_validate(counts).model_dump()
