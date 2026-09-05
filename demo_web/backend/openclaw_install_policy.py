from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .adapters import ProcessRunner, SkillScannerAdapter
from .models import Decision, Severity
from .policy import PolicyConfigurationError, evaluate_findings
from .plugin_static_pipeline import run_plugin_static_pipeline
from .runtime_paths import runtime_path_entries
from .semantic_model import configured_semantic_provider
from .skill_static_pipeline import run_skill_static_pipeline


PROTOCOL_VERSION = 1
MAX_TEXT_LENGTH = 1_000
MAX_REASON_LENGTH = 300
MAX_FINDING_RULE_LENGTH = 120
MAX_FINDING_MESSAGE_LENGTH = 160
MAX_FINDING_FILE_LENGTH = 180
MAX_FINDING_EVIDENCE_LENGTH = 200
MAX_FINDINGS = 3
DEFAULT_SCAN_TIMEOUT_SECONDS = 60
REVIEW_MODE_ENV = "AEGIS_OPENCLAW_REVIEW_MODE"
DYNAMIC_SKILL_MODE_ENV = "AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY"
DYNAMIC_SKILL_CONFIG = Path(__file__).resolve().parents[1] / "config" / "skill_dynamic_sandbox_v2.json"
DEMO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SKILL_RUNTIME = REPOSITORY_ROOT / ".runtime_skill"
SKILL_SCANNER = SKILL_RUNTIME / "Scripts" / "skill-scanner.exe"


class InstallPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    protocol_version: int = Field(alias="protocolVersion")
    openclaw_version: str = Field(alias="openclawVersion", min_length=1, max_length=100)
    target_type: str = Field(alias="targetType", min_length=1, max_length=32)
    target_name: str = Field(alias="targetName", min_length=1, max_length=240)
    source_path: str = Field(alias="sourcePath", min_length=1, max_length=32_767)
    source_path_kind: str = Field(alias="sourcePathKind", min_length=1, max_length=32)
    source: dict[str, Any] | None = None
    origin: dict[str, Any] | None = None
    request: dict[str, Any] | None = None


@dataclass(frozen=True)
class SourceTreeLimits:
    # Browser admission and the OpenClaw install hook intentionally share the
    # same boundary so an upload cannot pass preflight and fail only because
    # the install-time tree validator uses a smaller, hidden limit.
    max_files: int = 5_000
    max_total_bytes: int = 200 * 1024 * 1024
    max_file_bytes: int = 50 * 1024 * 1024


class SourceTreeRejected(RuntimeError):
    """Raised when staged source cannot be inspected within the safe boundary."""


SkillScan = Callable[[Path], dict[str, Any]]
PluginScan = Callable[[Path], dict[str, Any]]
DynamicSkillScan = Callable[[Path], dict[str, Any]]
TreeHasher = Callable[[Path], str]
AuditRecorder = Callable[[Any, dict[str, Any], str | None, int], str]


def _bounded_text(value: Any, fallback: str = "", limit: int = MAX_TEXT_LENGTH) -> str:
    text = "".join(character for character in str(value or "") if ord(character) >= 32)
    text = " ".join(text.split()).strip()
    return (text or fallback)[:limit]


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SourceTreeRejected(f"无法读取暂存源码元数据：{exc}") from exc
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return path.is_symlink() or bool(attributes & reparse_flag)


def validate_source_path(raw_path: str) -> Path:
    source = Path(raw_path)
    if not source.is_absolute():
        raise SourceTreeRejected("sourcePath 必须为绝对路径")
    if _is_reparse_point(source):
        raise SourceTreeRejected("sourcePath 不能是符号链接或目录联接")
    try:
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise SourceTreeRejected(f"sourcePath 不存在或无法解析：{exc}") from exc
    if not resolved.is_dir():
        raise SourceTreeRejected("sourcePath 必须指向目录")
    return resolved


def hash_source_tree(
    root: Path,
    limits: SourceTreeLimits = SourceTreeLimits(),
) -> str:
    """Hash a bounded source tree without following links or retaining content."""
    root = validate_source_path(str(root))
    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0
    pending = [root]

    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise SourceTreeRejected(f"无法枚举暂存源码目录：{exc}") from exc

        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if entry.is_symlink() or _is_reparse_point(path):
                raise SourceTreeRejected(f"暂存源码包含符号链接或目录联接：{relative}")
            try:
                if entry.is_dir(follow_symlinks=False):
                    digest.update(f"D\0{relative}\0".encode("utf-8"))
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise SourceTreeRejected(f"暂存源码包含不支持的文件类型：{relative}")
                before = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise SourceTreeRejected(f"无法读取暂存源码：{relative}: {exc}") from exc

            file_count += 1
            total_bytes += before.st_size
            if file_count > limits.max_files:
                raise SourceTreeRejected(f"暂存源码文件数超过上限 {limits.max_files}")
            if before.st_size > limits.max_file_bytes:
                raise SourceTreeRejected(
                    f"暂存源码包含超大文件：{relative}（上限 {limits.max_file_bytes} 字节）"
                )
            if total_bytes > limits.max_total_bytes:
                raise SourceTreeRejected(
                    f"暂存源码总大小超过上限 {limits.max_total_bytes} 字节"
                )

            digest.update(f"F\0{relative}\0{before.st_size}\0".encode("utf-8"))
            try:
                with path.open("rb") as handle:
                    while chunk := handle.read(64 * 1024):
                        digest.update(chunk)
                after = path.stat()
            except OSError as exc:
                raise SourceTreeRejected(f"无法读取暂存源码文件：{relative}: {exc}") from exc
            if (
                before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
            ):
                raise SourceTreeRejected(f"暂存源码在哈希期间发生变化：{relative}")

    digest.update(f"COUNT\0{file_count}\0BYTES\0{total_bytes}\0".encode("ascii"))
    return digest.hexdigest()


def _scan_timeout_seconds() -> int:
    raw = os.getenv("AEGIS_OPENCLAW_SCAN_TIMEOUT_SECONDS", str(DEFAULT_SCAN_TIMEOUT_SECONDS))
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_SCAN_TIMEOUT_SECONDS
    return min(max(value, 1), 120)


def default_skill_scan(skill_path: Path) -> dict[str, Any]:
    runner = ProcessRunner(
        timeout_seconds=_scan_timeout_seconds(),
        cache_root=DEMO_ROOT / "data" / "openclaw-install-policy" / "cache",
        extra_path=runtime_path_entries(SKILL_RUNTIME),
    )
    adapter = SkillScannerAdapter(scanner=SKILL_SCANNER, runner=runner)
    return run_skill_static_pipeline(
        skill_path,
        adapter,
        semantic_provider=configured_semantic_provider(),
    )


def default_plugin_scan(plugin_path: Path) -> dict[str, Any]:
    return run_plugin_static_pipeline(plugin_path)


def default_dynamic_skill_scan(skill_path: Path) -> dict[str, Any]:
    from .dynamic_audit.skill_sandbox_multiruntime import run_skill_sandbox_v2

    return run_skill_sandbox_v2(DYNAMIC_SKILL_CONFIG, skill_path)


def _dynamic_skill_mode() -> str:
    mode = os.getenv(DYNAMIC_SKILL_MODE_ENV, "disabled").strip().lower()
    if mode not in {"disabled", "required"}:
        raise ValueError(f"{DYNAMIC_SKILL_MODE_ENV} 仅支持 disabled 或 required")
    return mode


def _dynamic_failure_finding(error_name: str) -> dict[str, Any]:
    return {
        "id": "dynamic-aegis_dynamic_execution_inconclusive",
        "rule_id": "AEGIS_DYNAMIC_EXECUTION_INCONCLUSIVE",
        "title": "Skill 隔离试运行未可靠完成",
        "category": "execution_failure",
        "severity": "MEDIUM",
        "analyzer": "aegis-skill-sandbox-v1",
        "location": {"object": "dynamic-sandbox", "type": "runtime"},
        "evidence": f"failure_type={_bounded_text(error_name, 'unknown', 80)}",
        "description": "动态设施、入口或证据完整性未满足准入合同。",
        "remediation": "修复动态执行环境并重新扫描；不得将未验证解释为安全。",
    }


def _dynamic_clean_finding(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("backend_id") not in {
        "aegis-python-skill-sandbox-v1",
        "aegis-multiruntime-skill-sandbox-v2",
    }:
        raise RuntimeError("动态流水线身份无法验证")
    if result.get("status") != "clean":
        raise RuntimeError("动态流水线状态与 ALLOW 不一致")
    plan = result.get("entrypoint_plan")
    runs = result.get("runs")
    if not isinstance(plan, dict) or not isinstance(runs, list):
        raise RuntimeError("动态流水线缺少执行证据")
    entrypoints = plan.get("entrypoints")
    if result.get("execution_kind") == "pure_instruction":
        attestation = result.get("instruction_attestation")
        if (
            entrypoints != []
            or runs != []
            or not isinstance(attestation, dict)
            or attestation.get("scenarios") != ["typical", "edge", "adversarial"]
            or attestation.get("raw_content_retained") is not False
            or attestation.get("model_may_block_alone") is not False
        ):
            raise RuntimeError("纯指令动态语义证明无效")
        return {
            "id": "dynamic-aegis_instruction_scenarios_clean",
            "rule_id": "AEGIS_DYNAMIC_INSTRUCTION_SCENARIOS_CLEAN",
            "title": "纯指令 Skill 已完成三类语义场景检查",
            "category": "instruction_attestation",
            "severity": "INFO",
            "analyzer": "aegis-skill-sandbox-v2",
            "location": {"object": "SKILL.md", "type": "instruction"},
            "evidence": "scenarios=typical,edge,adversarial; raw_content_retained=false; model_block_alone=false",
            "description": "无代码入口的 Skill 不执行脚本，使用确定性规则和可选模型完成语义场景检查。",
            "remediation": "无需处理；该证据不代表未来所有输入均安全。",
        }
    if (
        not isinstance(entrypoints, list)
        or not entrypoints
        or len(entrypoints) > 3
        or len(runs) != len(entrypoints)
    ):
        raise RuntimeError("动态流水线入口证据无效")

    event_count = 0
    for run in runs:
        if not isinstance(run, dict) or run.get("success") is not True:
            raise RuntimeError("动态流水线执行未成功")
        cleanup = run.get("cleanup")
        runner = run.get("runner")
        inspect_gates = run.get("inspect_gates")
        image_gates = run.get("image_gates")
        if (
            not isinstance(cleanup, dict)
            or cleanup.get("removed") is not True
            or cleanup.get("residual") is not False
            or not isinstance(runner, dict)
            or runner.get("telemetry_complete") is not True
            or str(runner.get("execution_status") or "").casefold()
            not in {"completed", "clean"}
            or not isinstance(inspect_gates, dict)
            or not inspect_gates
            or not all(value is True for value in inspect_gates.values())
            or not isinstance(image_gates, dict)
            or not image_gates
            or not all(value is True for value in image_gates.values())
        ):
            raise RuntimeError("动态流水线安全门或遥测证据不完整")
        events = runner.get("events")
        if not isinstance(events, list):
            raise RuntimeError("动态流水线事件证据无效")
        event_count += len(events)
        if result.get("backend_id") == "aegis-multiruntime-skill-sandbox-v2":
            rounds = runner.get("rounds")
            if (
                not isinstance(rounds, list)
                or [item.get("id") for item in rounds if isinstance(item, dict)]
                != ["typical", "edge", "adversarial"]
            ):
                raise RuntimeError("动态流水线缺少三轮定向输入证明")

    return {
        "id": "dynamic-aegis_dynamic_execution_clean",
        "rule_id": "AEGIS_DYNAMIC_EXECUTION_CLEAN",
        "title": "Skill 已完成容器隔离试运行",
        "category": "execution_attestation",
        "severity": "INFO",
        "analyzer": "aegis-skill-sandbox-v1",
        "location": {"object": "dynamic-sandbox", "type": "runtime"},
        "evidence": (
            f"entrypoints={len(entrypoints)}; events={event_count}; "
            "telemetry_complete=true; cleanup=verified"
        ),
        "description": "固定镜像和安全门已验证，执行遥测完整且容器无残留。",
        "remediation": "无需处理；该证据只证明本次受控输入下未观察到阻断行为。",
    }


def _apply_required_dynamic_scan(
    source_root: Path,
    static_decision: Decision,
    static_reason: str,
    static_findings: list[dict[str, Any]],
    dynamic_skill_scan: DynamicSkillScan,
) -> tuple[Decision, str, list[dict[str, Any]]]:
    if static_decision in {Decision.BLOCK, Decision.UNKNOWN}:
        return Decision.BLOCK, static_reason, static_findings
    try:
        result = dynamic_skill_scan(source_root)
        if not isinstance(result, dict):
            raise RuntimeError("动态流水线没有返回对象")
        dynamic_findings = result.get("findings")
        if not isinstance(dynamic_findings, list) or not all(
            isinstance(item, dict) for item in dynamic_findings
        ):
            raise RuntimeError("动态流水线没有返回 Finding 列表")
        dynamic_decision = Decision(str(result.get("decision") or "UNKNOWN").upper())
        dynamic_reason = _bounded_text(
            result.get("reason"), "隔离试运行需要人工复核。", MAX_REASON_LENGTH
        )
        if dynamic_decision == Decision.ALLOW:
            dynamic_findings = [_dynamic_clean_finding(result), *dynamic_findings]
    except Exception as exc:
        dynamic_decision = Decision.REVIEW
        dynamic_reason = "Skill 隔离试运行未可靠完成，需要人工复核。"
        dynamic_findings = [_dynamic_failure_finding(type(exc).__name__)]

    ranks = {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.BLOCK: 2}
    final_decision = (
        dynamic_decision
        if ranks[dynamic_decision] > ranks[static_decision]
        else static_decision
    )
    reason = (
        dynamic_reason
        if final_decision != static_decision
        or (static_decision == Decision.ALLOW and dynamic_decision == Decision.ALLOW)
        else static_reason
    )
    return final_decision, reason, [*dynamic_findings, *static_findings]


def block_response(rule_id: str, reason: str) -> dict[str, Any]:
    safe_rule_id = _bounded_text(
        rule_id, "AEGIS_POLICY_FAILURE", MAX_FINDING_RULE_LENGTH
    )
    safe_reason = _bounded_text(
        reason,
        "安装前安全扫描失败，已按失败关闭策略阻止安装。",
        MAX_REASON_LENGTH,
    )
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "decision": "block",
        "reason": safe_reason,
        "findings": [
            {
                "ruleId": safe_rule_id,
                "message": safe_reason,
                "severity": "critical",
            }
        ],
    }


def parse_request(payload: Any) -> InstallPolicyRequest:
    if not isinstance(payload, dict):
        raise ValueError("请求 JSON 顶层必须是对象")
    if payload.get("protocolVersion") != PROTOCOL_VERSION:
        raise ValueError("仅支持 OpenClaw install policy protocolVersion=1")
    try:
        request = InstallPolicyRequest.model_validate(payload)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        location = ".".join(str(item) for item in first.get("loc", [])) or "request"
        raise ValueError(f"请求字段无效：{location}") from exc
    if request.target_type not in {"skill", "plugin"}:
        raise ValueError(f"不支持的 targetType：{request.target_type}")
    if request.source_path_kind != "directory":
        raise ValueError("M6 v1 仅支持 sourcePathKind=directory")
    return request


def _relative_finding_path(value: Any, source_root: Path) -> str | None:
    raw = _bounded_text(value, "", 1_000)
    if not raw:
        return None
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            raw = candidate.resolve(strict=False).relative_to(source_root).as_posix()
        except (OSError, ValueError):
            return None
    else:
        raw = raw.replace("\\", "/")
        parts = PurePosixPath(raw).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            return None
        raw = PurePosixPath(*parts).as_posix()
    return _bounded_text(raw, "", MAX_FINDING_FILE_LENGTH) or None


def _openclaw_severity(value: Any) -> str:
    try:
        severity = Severity(str(value).upper())
    except ValueError:
        severity = Severity.UNKNOWN
    if severity in {Severity.CRITICAL, Severity.HIGH, Severity.UNKNOWN}:
        return "critical"
    if severity in {Severity.MEDIUM, Severity.LOW}:
        return "warn"
    return "info"


def normalize_findings_for_openclaw(
    findings: list[dict[str, Any]],
    source_root: Path,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    severity_priority = {"critical": 0, "warn": 1, "info": 2}
    prioritized = sorted(
        enumerate(findings),
        key=lambda item: (
            severity_priority[_openclaw_severity(item[1].get("severity"))],
            item[0],
        ),
    )
    for index, (_, finding) in enumerate(prioritized[:MAX_FINDINGS], start=1):
        rule_id = _bounded_text(
            finding.get("rule_id") or finding.get("id"),
            f"AEGIS_FINDING_{index}",
            MAX_FINDING_RULE_LENGTH,
        )
        message = _bounded_text(
            finding.get("title") or finding.get("description"),
            "Aegis Chain 静态扫描发现安全信号。",
            MAX_FINDING_MESSAGE_LENGTH,
        )
        item: dict[str, Any] = {
            "ruleId": rule_id,
            "message": message,
            "severity": _openclaw_severity(finding.get("severity")),
        }
        location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
        relative_file = _relative_finding_path(location.get("file"), source_root)
        if relative_file:
            item["file"] = relative_file
        line = location.get("line")
        if isinstance(line, (int, float)) and not isinstance(line, bool) and line >= 1:
            item["line"] = int(line)
        evidence = _bounded_text(
            finding.get("evidence"), "", MAX_FINDING_EVIDENCE_LENGTH
        )
        if evidence:
            item["evidence"] = evidence
        normalized.append(item)
    return normalized


def _response_from_evaluation(
    decision: Decision,
    reason: str,
    findings: list[dict[str, Any]],
    source_root: Path,
) -> dict[str, Any]:
    mapping = {
        Decision.ALLOW: "allow",
        Decision.REVIEW: "warn",
        Decision.BLOCK: "block",
        Decision.UNKNOWN: "block",
    }
    openclaw_decision = mapping[decision]
    if decision == Decision.REVIEW:
        review_mode = os.getenv(REVIEW_MODE_ENV, "warn").strip().lower()
        if review_mode == "block":
            openclaw_decision = "block"
            reason = f"当前 OpenClaw 兼容模式不支持可确认警告；{reason}"
        elif review_mode != "warn":
            openclaw_decision = "block"
            reason = f"{REVIEW_MODE_ENV} 配置无效，已按失败关闭策略阻止安装。"
    safe_reason = _bounded_text(
        reason,
        "Aegis Chain 已完成安装前静态扫描。",
        MAX_REASON_LENGTH,
    )
    response: dict[str, Any] = {
        "protocolVersion": PROTOCOL_VERSION,
        "decision": openclaw_decision,
        "reason": safe_reason,
    }
    normalized = normalize_findings_for_openclaw(findings, source_root)
    if normalized:
        response["findings"] = normalized
    return response


def evaluate_install_request(
    payload: Any,
    *,
    skill_scan: SkillScan = default_skill_scan,
    plugin_scan: PluginScan = default_plugin_scan,
    dynamic_skill_scan: DynamicSkillScan = default_dynamic_skill_scan,
    tree_hasher: TreeHasher = hash_source_tree,
    audit_recorder: AuditRecorder | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()

    def finalize(
        response: dict[str, Any], source_tree_sha256: str | None = None
    ) -> dict[str, Any]:
        if audit_recorder is None:
            return response
        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        try:
            audit_recorder(payload, response, source_tree_sha256, duration_ms)
        except Exception:
            return block_response(
                "AEGIS_POLICY_AUDIT_FAILED",
                "安装前准入审计记录未能可靠持久化，已按失败关闭策略阻止安装。",
            )
        return response

    try:
        request = parse_request(payload)
    except ValueError as exc:
        rule_id = (
            "AEGIS_POLICY_PROTOCOL_MISMATCH"
            if isinstance(payload, dict) and payload.get("protocolVersion") != PROTOCOL_VERSION
            else "AEGIS_POLICY_INVALID_REQUEST"
        )
        return finalize(block_response(rule_id, str(exc)))

    try:
        source_root = validate_source_path(request.source_path)
        before_hash = tree_hasher(source_root)
    except SourceTreeRejected as exc:
        return finalize(block_response("AEGIS_POLICY_INVALID_SOURCE", str(exc)))

    try:
        scan_result = (
            skill_scan(source_root)
            if request.target_type == "skill"
            else plugin_scan(source_root)
        )
        findings = scan_result.get("findings")
        if not isinstance(findings, list):
            raise RuntimeError("静态扫描流水线未返回 Finding 列表")
        evaluation = evaluate_findings(findings)
    except subprocess.TimeoutExpired:
        return finalize(
            block_response(
                "AEGIS_POLICY_SCAN_TIMEOUT",
                "安装前静态扫描超过执行时间上限，已按失败关闭策略阻止安装。",
            ),
            before_hash,
        )
    except PolicyConfigurationError as exc:
        return finalize(
            block_response("AEGIS_POLICY_SCAN_FAILED", str(exc)), before_hash
        )
    except Exception as exc:
        return finalize(
            block_response(
                "AEGIS_POLICY_SCAN_FAILED",
                f"安装前静态扫描未能可靠完成：{type(exc).__name__}",
            ),
            before_hash,
        )

    final_decision = evaluation.decision
    final_reason = evaluation.trace.reason
    final_findings = findings
    if request.target_type == "skill":
        try:
            dynamic_mode = _dynamic_skill_mode()
        except ValueError as exc:
            return finalize(
                block_response("AEGIS_DYNAMIC_POLICY_CONFIG_INVALID", str(exc)),
                before_hash,
            )
        if dynamic_mode == "required":
            final_decision, final_reason, final_findings = _apply_required_dynamic_scan(
                source_root,
                evaluation.decision,
                evaluation.trace.reason,
                findings,
                dynamic_skill_scan,
            )

    try:
        after_hash = tree_hasher(source_root)
    except SourceTreeRejected as exc:
        return finalize(
            block_response("AEGIS_POLICY_SOURCE_CHANGED", str(exc)), before_hash
        )
    if before_hash != after_hash:
        return finalize(
            block_response(
                "AEGIS_POLICY_SOURCE_CHANGED",
                "暂存源码在扫描过程中发生变化，已阻止本次安装。",
            ),
            before_hash,
        )

    return finalize(
        _response_from_evaluation(
            final_decision,
            final_reason,
            final_findings,
            source_root,
        ),
        before_hash,
    )
