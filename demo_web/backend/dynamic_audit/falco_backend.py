from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable


MAX_FALCO_LINES = 10_000
MAX_FALCO_LINE_BYTES = 256 * 1024
_PRIORITY_TO_SEVERITY = {
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "NOTICE": "LOW",
    "INFORMATIONAL": "INFO",
    "DEBUG": "INFO",
}


class FalcoEvidenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class FalcoTarget:
    container_id: str
    container_name: str


def _bounded(value: Any, limit: int) -> str:
    text = "".join(character for character in str(value or "") if ord(character) >= 32)
    return " ".join(text.split())[:limit]


def _field(fields: dict[str, Any], *names: str) -> str:
    for name in names:
        value = fields.get(name)
        if value not in {None, ""}:
            return _bounded(value, 500)
    return ""


def _matches_target(fields: dict[str, Any], target: FalcoTarget) -> bool:
    event_id = _field(fields, "container.id", "container.id.full")
    event_name = _field(fields, "container.name")
    id_matches = bool(event_id) and (
        target.container_id.startswith(event_id) or event_id.startswith(target.container_id)
    )
    name_matches = bool(event_name) and event_name == target.container_name
    return id_matches or name_matches


def parse_falco_json_lines(
    lines: Iterable[str],
    *,
    target: FalcoTarget,
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        if index > MAX_FALCO_LINES:
            raise FalcoEvidenceError("Falco 输出超过事件上限")
        if len(line.encode("utf-8", errors="replace")) > MAX_FALCO_LINE_BYTES:
            raise FalcoEvidenceError("Falco 单行输出超过大小上限")
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise FalcoEvidenceError(f"Falco JSON 第 {index} 行无法解析") from exc
        if not isinstance(payload, dict):
            raise FalcoEvidenceError(f"Falco JSON 第 {index} 行不是对象")
        fields = payload.get("output_fields")
        if not isinstance(fields, dict) or not _matches_target(fields, target):
            continue
        priority = _bounded(payload.get("priority"), 40).upper() or "WARNING"
        severity = _PRIORITY_TO_SEVERITY.get(priority, "UNKNOWN")
        rule = _bounded(payload.get("rule"), 160) or "Falco runtime alert"
        alerts.append(
            {
                "type": "falco.alert",
                "rule": rule,
                "severity": severity,
                "priority": priority,
                "process": _field(fields, "proc.name", "proc.exepath"),
                "file": _field(fields, "fd.name", "fs.path.name"),
                "container_id": target.container_id[:12],
                "container_name": target.container_name,
                "event_time": _bounded(payload.get("time"), 80),
            }
        )
    return alerts


def falco_alerts_to_findings(alerts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, alert in enumerate(alerts, start=1):
        severity = _bounded(alert.get("severity"), 20).upper() or "UNKNOWN"
        rule = _bounded(alert.get("rule"), 160) or "Falco runtime alert"
        process = _bounded(alert.get("process"), 160)
        file_name = _bounded(alert.get("file"), 240)
        identity = (rule, process, file_name)
        if identity in seen:
            continue
        seen.add(identity)
        evidence_parts = [f"falco_rule={rule}"]
        if process:
            evidence_parts.append(f"process={process}")
        if file_name:
            evidence_parts.append(f"object={file_name}")
        findings.append(
            {
                "id": f"dynamic-falco-{index}",
                "rule_id": "AEGIS_DYNAMIC_FALCO_ALERT",
                "title": f"Falco 观察到运行时规则：{rule}"[:200],
                "category": "runtime_kernel_signal",
                "severity": severity,
                "analyzer": "falco-adapter-v1",
                "location": {"object": f"falco:{index}", "type": "runtime_event"},
                "evidence": "; ".join(evidence_parts)[:300],
                "description": "可信 Falco 观测器针对目标 Skill 容器生成的内核事件告警。",
                "remediation": "与 Aegis 语言级事件交叉核对；中高危告警不得自动放行。",
            }
        )
    return findings
