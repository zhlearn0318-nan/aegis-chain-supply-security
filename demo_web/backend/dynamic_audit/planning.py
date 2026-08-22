from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Literal


TargetKind = Literal["skill", "mcp"]
CorrelationStatus = Literal["potential", "observed", "confirmed", "inconclusive"]


PROFILE_HINTS: dict[str, tuple[str, ...]] = {
    "official_document": ("sensitive", "document", "file", "path", "公文", "文件", "目录"),
    "personal_identity": ("personal", "identity", "pii", "身份证", "个人信息"),
    "database_credential": ("credential", "secret", "password", "database", "凭据", "口令"),
    "internal_endpoint": ("network", "http", "url", "socket", "ssrf", "endpoint", "网络", "外传"),
    "ops_token": ("token", "api_key", "environment", "shell", "command", "令牌", "命令"),
}

ACTION_HINTS: dict[str, tuple[str, ...]] = {
    "observe_sensitive_file_read": ("file", "path", "document", "credential", "secret"),
    "observe_loopback_sink": ("network", "http", "url", "socket", "outbound", "exfil"),
    "observe_process_tree": ("exec", "shell", "command", "process", "subprocess"),
    "observe_filesystem_diff": ("persist", "startup", "cron", "service", "write", "delete"),
    "lift_materialized_instructions": ("decode", "archive", "payload", "instruction", "markdown"),
}


@dataclass(frozen=True)
class TriggerStep:
    step_id: str
    action: str
    purpose: str
    static_finding_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "action": self.action,
            "purpose": self.purpose,
            "static_finding_ids": list(self.static_finding_ids),
        }


@dataclass(frozen=True)
class DynamicTriggerPlan:
    schema_version: str
    plan_id: str
    target_id: str
    target_kind: TargetKind
    static_finding_ids: tuple[str, ...]
    marker_profiles: tuple[str, ...]
    steps: tuple[TriggerStep, ...]
    max_attempts: int
    policy_effect: Literal["none"] = "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "static_finding_ids": list(self.static_finding_ids),
            "marker_profiles": list(self.marker_profiles),
            "steps": [step.to_dict() for step in self.steps],
            "max_attempts": self.max_attempts,
            "policy_effect": self.policy_effect,
            "static_decision_changed": False,
        }


@dataclass(frozen=True)
class DynamicCorrelation:
    schema_version: str
    correlation_id: str
    plan_id: str
    status: CorrelationStatus
    static_finding_ids: tuple[str, ...]
    observed_event_types: tuple[str, ...]
    marker_witness_ids: tuple[str, ...]
    reason: str
    policy_effect: Literal["none"] = "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "correlation_id": self.correlation_id,
            "plan_id": self.plan_id,
            "status": self.status,
            "static_finding_ids": list(self.static_finding_ids),
            "observed_event_types": list(self.observed_event_types),
            "marker_witness_ids": list(self.marker_witness_ids),
            "reason": self.reason,
            "policy_effect": self.policy_effect,
            "static_decision_changed": False,
        }


def _normalized_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for index, finding in enumerate(findings):
        finding_id = str(finding.get("id") or "").strip()
        if not finding_id or len(finding_id) > 128:
            raise ValueError(f"static finding at index {index} has no bounded id")
        fields = {
            "id": finding_id,
            "rule_id": str(finding.get("rule_id") or "")[:128],
            "category": str(finding.get("category") or "")[:128],
            "title": str(finding.get("title") or "")[:256],
        }
        normalized.append(fields)
    return normalized


def _matches(text: str, hints: Iterable[str]) -> bool:
    return any(hint in text for hint in hints)


def build_trigger_plan(
    *,
    target_id: str,
    target_kind: TargetKind,
    static_findings: Iterable[dict[str, Any]],
    max_attempts: int = 3,
) -> DynamicTriggerPlan:
    if target_kind not in {"skill", "mcp"}:
        raise ValueError("target_kind must be skill or mcp")
    if not target_id or len(target_id) > 128:
        raise ValueError("target_id must be a non-empty bounded value")
    if not 1 <= max_attempts <= 5:
        raise ValueError("max_attempts must be 1-5")

    findings = _normalized_findings(static_findings)
    finding_ids = tuple(sorted({finding["id"] for finding in findings}))
    searchable = " ".join(
        value.lower()
        for finding in findings
        for key, value in finding.items()
        if key != "id"
    )
    profiles = tuple(sorted(
        profile for profile, hints in PROFILE_HINTS.items() if _matches(searchable, hints)
    ))
    actions = {
        action for action, hints in ACTION_HINTS.items() if _matches(searchable, hints)
    }
    actions.add("launch_with_resource_limits")
    if target_kind == "skill":
        actions.add("inventory_skill_runtime_closure")
    else:
        actions.update({"enumerate_mcp_tools", "invoke_schema_valid_tools"})

    purposes = {
        "launch_with_resource_limits": "验证目标能否在固定资源和失败闭锁边界内启动。",
        "inventory_skill_runtime_closure": "记录 Skill 全目录，并发现运行时新增的指令、脚本和配置。",
        "enumerate_mcp_tools": "通过 MCP 协议枚举工具及输入 Schema。",
        "invoke_schema_valid_tools": "生成结构合法输入并执行有界工具调用。",
        "observe_sensitive_file_read": "观察政企诱饵文件是否被目标读取。",
        "observe_loopback_sink": "只使用本地汇点观察数据是否到达网络输出。",
        "observe_process_tree": "记录实际创建的进程及参数证据。",
        "observe_filesystem_diff": "记录运行前后文件系统变化。",
        "lift_materialized_instructions": "把运行时新增指令纳入后续有界触发。",
    }
    ordered_actions = tuple(sorted(actions))
    steps = tuple(
        TriggerStep(
            step_id=f"step-{index:02d}",
            action=action,
            purpose=purposes[action],
            static_finding_ids=finding_ids,
        )
        for index, action in enumerate(ordered_actions, start=1)
    )
    identity = json.dumps(
        {
            "target_id": target_id,
            "target_kind": target_kind,
            "finding_ids": finding_ids,
            "profiles": profiles,
            "actions": ordered_actions,
            "max_attempts": max_attempts,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    plan_id = f"dynamic-plan-{hashlib.sha256(identity).hexdigest()[:16]}"
    return DynamicTriggerPlan(
        schema_version="1.0",
        plan_id=plan_id,
        target_id=target_id,
        target_kind=target_kind,
        static_finding_ids=finding_ids,
        marker_profiles=profiles,
        steps=steps,
        max_attempts=max_attempts,
    )


def correlate_dynamic_evidence(
    plan: DynamicTriggerPlan,
    *,
    execution_status: str,
    observed_event_types: Iterable[str],
    marker_witnesses: Iterable[dict[str, Any]],
) -> DynamicCorrelation:
    events = tuple(sorted({str(event) for event in observed_event_types if event}))
    witnesses = list(marker_witnesses)
    relevant_witnesses = [
        witness
        for witness in witnesses
        if str(witness.get("profile") or "") in plan.marker_profiles
    ]
    witness_ids = tuple(sorted({
        str(witness.get("marker_id"))
        for witness in relevant_witnesses
        if witness.get("marker_id")
    }))
    if execution_status != "completed":
        status: CorrelationStatus = "inconclusive"
        reason = "动态运行未完整完成，不能把未观察到的行为解释为安全。"
    elif witness_ids:
        status = "confirmed"
        reason = "至少一个政企诱饵标记从指定敏感源到达受控汇点，已形成源到汇证据。"
    elif witnesses:
        status = "observed"
        reason = "观察到源到汇标记，但其类型不属于本静态 Trigger Plan，暂不标为静动态确认。"
    elif events:
        status = "observed"
        reason = "观察到运行时行为，但尚未形成敏感源到汇证据。"
    else:
        status = "potential"
        reason = "仅保留静态潜在风险，当前动态触发没有产生可确认行为。"

    identity = json.dumps(
        {
            "plan_id": plan.plan_id,
            "status": status,
            "events": events,
            "witness_ids": witness_ids,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return DynamicCorrelation(
        schema_version="1.0",
        correlation_id=f"dynamic-correlation-{hashlib.sha256(identity).hexdigest()[:16]}",
        plan_id=plan.plan_id,
        status=status,
        static_finding_ids=plan.static_finding_ids,
        observed_event_types=events,
        marker_witness_ids=witness_ids,
        reason=reason,
    )
