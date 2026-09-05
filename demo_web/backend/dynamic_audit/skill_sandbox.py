from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from ..models import Decision


DYNAMIC_ANALYZER = "aegis-skill-sandbox-v1"
MAX_ENTRYPOINTS = 3
MAX_SKILL_FILES = 500
MAX_SKILL_BYTES = 50 * 1024 * 1024
MAX_EVENT_COUNT = 5_000
MAX_EVENT_TEXT = 500
_SCRIPT_REFERENCE = re.compile(
    r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+(?:[/\\][A-Za-z0-9_.-]+)*\.(?:py|js|mjs|cjs|sh))(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_RUNTIME_BY_SUFFIX = {".py": "python", ".js": "node", ".mjs": "node", ".cjs": "node", ".sh": "shell"}
_SHELL_NAMES = {
    "bash",
    "sh",
    "dash",
    "zsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
}
_TRANSFER_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat"}
_SENSITIVE_PATH_PARTS = {
    ".aws",
    ".azure",
    ".config/gcloud",
    ".docker/config.json",
    ".kube/config",
    ".ssh",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
}
_SEVERITY_ORDER = {
    "SAFE": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
    "UNKNOWN": 6,
}


class SkillSandboxRejected(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class EntrypointPlan:
    entrypoints: tuple[str, ...]
    discovery: str
    files_seen: int
    total_bytes: int
    runtimes: tuple[str, ...] = ()


@dataclass(frozen=True)
class DynamicEvaluation:
    decision: Decision
    status: str
    findings: tuple[dict[str, Any], ...]
    highest_severity: str
    reason: str


def _is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _bounded_text(value: Any, limit: int = MAX_EVENT_TEXT) -> str:
    text = "".join(character for character in str(value or "") if ord(character) >= 32)
    return " ".join(text.split())[:limit]


def _relative_script_path(raw: str) -> str | None:
    normalized = raw.replace("\\", "/")
    if not normalized or normalized.startswith("/") or ":" in normalized:
        return None
    parts = PurePosixPath(normalized).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    if PurePosixPath(*parts).suffix.lower() not in _RUNTIME_BY_SUFFIX:
        return None
    return PurePosixPath(*parts).as_posix()


def _inventory_skill(root: Path) -> tuple[dict[str, Path], int, int]:
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise SkillSandboxRejected("SKILL_PATH_INVALID", "Skill 目录不存在") from exc
    if not root.is_dir() or _is_link_or_reparse(root):
        raise SkillSandboxRejected("SKILL_PATH_INVALID", "Skill 根必须是普通目录")

    files: dict[str, Path] = {}
    total_bytes = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise SkillSandboxRejected("SKILL_ENUMERATION_FAILED", "无法枚举 Skill 目录") from exc
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if entry.is_symlink() or _is_link_or_reparse(path):
                raise SkillSandboxRejected("SKILL_LINK_DENIED", relative)
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise SkillSandboxRejected("SKILL_FILE_TYPE_DENIED", relative)
            size = entry.stat(follow_symlinks=False).st_size
            total_bytes += size
            files[relative] = path
            if len(files) > MAX_SKILL_FILES:
                raise SkillSandboxRejected("SKILL_FILE_LIMIT_EXCEEDED", str(MAX_SKILL_FILES))
            if total_bytes > MAX_SKILL_BYTES:
                raise SkillSandboxRejected("SKILL_SIZE_LIMIT_EXCEEDED", str(MAX_SKILL_BYTES))
    return files, len(files), total_bytes


def discover_skill_entrypoints(
    root: Path,
    *,
    max_entrypoints: int = MAX_ENTRYPOINTS,
) -> EntrypointPlan:
    if max_entrypoints < 1 or max_entrypoints > MAX_ENTRYPOINTS:
        raise SkillSandboxRejected("ENTRYPOINT_LIMIT_INVALID", str(max_entrypoints))
    files, files_seen, total_bytes = _inventory_skill(root)
    skill_document = files.get("SKILL.md")
    if skill_document is None:
        raise SkillSandboxRejected("SKILL_MANIFEST_MISSING", "SKILL.md")
    try:
        manifest_text = skill_document.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SkillSandboxRejected("SKILL_MANIFEST_INVALID", "SKILL.md 必须是 UTF-8") from exc

    referenced: list[str] = []
    for match in _SCRIPT_REFERENCE.finditer(manifest_text):
        relative = _relative_script_path(match.group(1))
        if relative is None or relative not in files:
            continue
        if relative not in referenced:
            referenced.append(relative)
    if referenced:
        if len(referenced) > max_entrypoints:
            raise SkillSandboxRejected(
                "ENTRYPOINT_AMBIGUOUS",
                f"SKILL.md 引用了 {len(referenced)} 个脚本入口",
            )
        return EntrypointPlan(
            tuple(referenced), "skill_manifest", files_seen, total_bytes,
            tuple(_RUNTIME_BY_SUFFIX[PurePosixPath(item).suffix.lower()] for item in referenced),
        )

    fallback = sorted(
        relative
        for relative in files
        if relative.startswith("scripts/") and PurePosixPath(relative).suffix.lower() in _RUNTIME_BY_SUFFIX
    )
    if fallback:
        if len(fallback) > max_entrypoints:
            raise SkillSandboxRejected(
                "ENTRYPOINT_AMBIGUOUS",
                f"scripts/ 下存在 {len(fallback)} 个候选入口",
            )
        return EntrypointPlan(
            tuple(fallback), "scripts_fallback", files_seen, total_bytes,
            tuple(_RUNTIME_BY_SUFFIX[PurePosixPath(item).suffix.lower()] for item in fallback),
        )

    root_fallback = sorted(
        relative
        for relative in files
        if "/" not in relative and PurePosixPath(relative).suffix.lower() in _RUNTIME_BY_SUFFIX
    )
    if len(root_fallback) > 1:
        raise SkillSandboxRejected(
            "ENTRYPOINT_AMBIGUOUS",
            f"Skill 根目录存在 {len(root_fallback)} 个脚本候选入口",
        )
    if root_fallback:
        return EntrypointPlan(
            tuple(root_fallback), "root_single_script_fallback", files_seen, total_bytes,
            tuple(_RUNTIME_BY_SUFFIX[PurePosixPath(item).suffix.lower()] for item in root_fallback),
        )
    return EntrypointPlan((), "pure_instruction", files_seen, total_bytes, ())


def discover_python_entrypoints(
    root: Path,
    *,
    max_entrypoints: int = MAX_ENTRYPOINTS,
) -> EntrypointPlan:
    """Backward-compatible Python-only discovery used by the v1 runner."""
    plan = discover_skill_entrypoints(root, max_entrypoints=max_entrypoints)
    if not plan.entrypoints:
        raise SkillSandboxRejected(
            "PYTHON_ENTRYPOINT_NOT_FOUND",
            "SKILL.md 未引用 Python 脚本，scripts/ 和 Skill 根目录下也没有候选",
        )
    if any(runtime != "python" for runtime in plan.runtimes):
        raise SkillSandboxRejected("PYTHON_ENTRYPOINT_NOT_FOUND", "Skill 入口不是 Python")
    discovery = (
        "root_single_python_fallback"
        if plan.discovery == "root_single_script_fallback"
        else plan.discovery
    )
    return EntrypointPlan(
        plan.entrypoints,
        discovery,
        plan.files_seen,
        plan.total_bytes,
        plan.runtimes,
    )


def _finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    severity: str,
    evidence: str,
    event_index: int,
) -> dict[str, Any]:
    return {
        "id": f"dynamic-{rule_id.lower()}-{event_index}",
        "rule_id": rule_id,
        "title": title,
        "category": category,
        "severity": severity,
        "analyzer": DYNAMIC_ANALYZER,
        "location": {"object": f"event:{event_index}", "type": "runtime_event"},
        "evidence": _bounded_text(evidence, 240),
        "description": "安装前隔离试运行观察到可复核的运行时安全信号。",
        "remediation": "人工核对 Skill 行为；高危行为应保持阻断。",
    }


def _host_is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return host.casefold() == "localhost"


def _command_name(event: dict[str, Any]) -> str:
    executable = _bounded_text(event.get("executable") or event.get("command"), 300)
    if not executable:
        argv = event.get("argv")
        if isinstance(argv, list) and argv:
            executable = _bounded_text(argv[0], 300)
    return PurePosixPath(executable.replace("\\", "/")).name.casefold()


def classify_dynamic_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, event in enumerate(events, start=1):
        if index > MAX_EVENT_COUNT:
            findings.append(
                _finding(
                    rule_id="AEGIS_DYNAMIC_EVENT_LIMIT_EXCEEDED",
                    title="运行时事件量超过审计上限",
                    category="resource_abuse",
                    severity="HIGH",
                    evidence=f"event_count>{MAX_EVENT_COUNT}",
                    event_index=index,
                )
            )
            break
        if not isinstance(event, dict):
            continue
        event_type = _bounded_text(event.get("type"), 80).casefold()
        candidate: tuple[str, str, str, str, str] | None = None

        if event_type in {"network.connect", "socket.connect", "dns.resolve"}:
            host = _bounded_text(event.get("host") or event.get("address"), 255)
            if host and not _host_is_loopback(host):
                candidate = (
                    "AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT",
                    "Skill 在隔离运行期间尝试访问外部网络",
                    "network_exfiltration",
                    "HIGH",
                    f"type={event_type}; host={host}",
                )
        elif event_type == "os.system":
            candidate = (
                "AEGIS_DYNAMIC_SHELL_SPAWN",
                "Skill 在隔离运行期间通过系统 Shell 执行命令",
                "command_execution",
                "CRITICAL",
                "api=os.system",
            )
        elif event_type in {"process.spawn", "subprocess.popen"}:
            name = _command_name(event)
            if name in _SHELL_NAMES:
                candidate = (
                    "AEGIS_DYNAMIC_SHELL_SPAWN",
                    "Skill 在隔离运行期间启动 Shell",
                    "command_execution",
                    "CRITICAL",
                    f"executable={name}",
                )
            elif name in _TRANSFER_TOOLS:
                candidate = (
                    "AEGIS_DYNAMIC_TRANSFER_TOOL_SPAWN",
                    "Skill 在隔离运行期间启动网络传输工具",
                    "network_exfiltration",
                    "HIGH",
                    f"executable={name}",
                )
            elif name:
                candidate = (
                    "AEGIS_DYNAMIC_CHILD_PROCESS",
                    "Skill 在隔离运行期间启动子进程",
                    "command_execution",
                    "MEDIUM",
                    f"executable={name}",
                )
        elif event_type in {"decoy.read", "marker.read"}:
            marker_id = _bounded_text(event.get("marker_id"), 120) or "unknown"
            candidate = (
                "AEGIS_DYNAMIC_DECOY_ACCESS",
                "Skill 读取了政企敏感数据诱饵",
                "sensitive_data_access",
                "CRITICAL",
                f"marker_id={marker_id}",
            )
        elif event_type == "marker.sink":
            marker_ids = event.get("marker_ids")
            marker_text = ",".join(
                _bounded_text(item, 80)
                for item in marker_ids
                if isinstance(item, str)
            ) if isinstance(marker_ids, list) else "unknown"
            candidate = (
                "AEGIS_DYNAMIC_DECOY_EXFILTRATION",
                "政企敏感数据诱饵到达了受控网络汇点",
                "sensitive_data_exfiltration",
                "CRITICAL",
                f"marker_ids={marker_text or 'unknown'}",
            )
        elif event_type in {"file.open", "open"}:
            path = _bounded_text(event.get("path"), 400).replace("\\", "/").casefold()
            if any(part in path for part in _SENSITIVE_PATH_PARTS):
                candidate = (
                    "AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS",
                    "Skill 尝试访问敏感系统或凭据路径",
                    "sensitive_data_access",
                    "HIGH",
                    f"path={path}",
                )
        elif event_type in {"native.load", "ctypes.dlopen", "dynamic.import"}:
            target = _bounded_text(event.get("target") or event.get("path"), 300)
            candidate = (
                "AEGIS_DYNAMIC_NATIVE_OR_DYNAMIC_LOAD",
                "Skill 在运行时加载原生库或动态代码",
                "dynamic_code_loading",
                "MEDIUM",
                f"target={target or 'unknown'}",
            )
        elif event_type in {"telemetry.tamper", "audit.disable"}:
            candidate = (
                "AEGIS_DYNAMIC_TELEMETRY_TAMPER",
                "Skill 尝试干扰动态审计遥测",
                "defense_evasion",
                "HIGH",
                f"type={event_type}",
            )
        elif event_type in {"runtime.timeout", "resource.oom", "resource.pid_limit"}:
            severity = "HIGH" if event_type != "runtime.timeout" else "MEDIUM"
            candidate = (
                "AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT",
                "Skill 运行触发超时或资源安全门",
                "resource_abuse",
                severity,
                f"type={event_type}",
            )

        if candidate is None:
            continue
        rule_id, title, category, severity, evidence = candidate
        identity = (rule_id, evidence)
        if identity in seen:
            continue
        seen.add(identity)
        findings.append(
            _finding(
                rule_id=rule_id,
                title=title,
                category=category,
                severity=severity,
                evidence=evidence,
                event_index=index,
            )
        )
    return findings


def evaluate_dynamic_result(
    events: Iterable[dict[str, Any]],
    *,
    execution_status: str,
    telemetry_complete: bool,
) -> DynamicEvaluation:
    findings = classify_dynamic_events(events)
    normalized_status = execution_status.strip().casefold()
    if not telemetry_complete:
        findings.append(
            _finding(
                rule_id="AEGIS_DYNAMIC_TELEMETRY_INCOMPLETE",
                title="动态审计证据不完整",
                category="audit_integrity",
                severity="MEDIUM",
                evidence="telemetry_complete=false",
                event_index=len(findings) + 1,
            )
        )
    if normalized_status not in {"completed", "clean"}:
        findings.append(
            _finding(
                rule_id="AEGIS_DYNAMIC_EXECUTION_INCONCLUSIVE",
                title="Skill 隔离试运行未可靠完成",
                category="execution_failure",
                severity="MEDIUM",
                evidence=f"execution_status={_bounded_text(normalized_status, 80)}",
                event_index=len(findings) + 1,
            )
        )

    highest = max(
        (str(item.get("severity") or "UNKNOWN").upper() for item in findings),
        key=lambda value: _SEVERITY_ORDER.get(value, _SEVERITY_ORDER["UNKNOWN"]),
        default="SAFE",
    )
    if highest in {"CRITICAL", "HIGH", "UNKNOWN"}:
        decision = Decision.BLOCK
        status = "malicious"
        reason = "隔离试运行观察到高危行为，已升级为阻断。"
    elif findings:
        decision = Decision.REVIEW
        status = "inconclusive" if normalized_status not in {"completed", "clean"} else "suspicious"
        reason = "隔离试运行存在中风险或证据不完整，需要人工复核。"
    else:
        decision = Decision.ALLOW
        status = "clean"
        reason = "隔离试运行完成，未观察到影响准入的动态风险。"
    return DynamicEvaluation(decision, status, tuple(findings), highest, reason)


def fuse_static_dynamic_decision(
    static_decision: Decision | str,
    dynamic: DynamicEvaluation | None,
) -> Decision:
    try:
        static = static_decision if isinstance(static_decision, Decision) else Decision(str(static_decision).upper())
    except ValueError:
        return Decision.BLOCK
    if static in {Decision.BLOCK, Decision.UNKNOWN}:
        return Decision.BLOCK
    if dynamic is None:
        return Decision.REVIEW
    static_rank = {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.BLOCK: 2}
    dynamic_rank = {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.BLOCK: 2}
    return static if static_rank[static] >= dynamic_rank[dynamic.decision] else dynamic.decision


def serialize_dynamic_evaluation(evaluation: DynamicEvaluation) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "analyzer": DYNAMIC_ANALYZER,
        "decision": evaluation.decision.value,
        "status": evaluation.status,
        "highest_severity": evaluation.highest_severity,
        "reason": evaluation.reason,
        "findings": [json.loads(json.dumps(item, ensure_ascii=False)) for item in evaluation.findings],
    }
