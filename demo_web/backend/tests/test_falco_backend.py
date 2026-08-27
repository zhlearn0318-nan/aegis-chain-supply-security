from __future__ import annotations

import json

import pytest

from backend.dynamic_audit.falco_backend import (
    FalcoEvidenceError,
    FalcoTarget,
    falco_alerts_to_findings,
    parse_falco_json_lines,
)


def falco_line(container_id: str, *, name: str = "aegis-target") -> str:
    return json.dumps(
        {
            "time": "2026-08-27T00:00:00Z",
            "rule": "Aegis shell spawned in Skill sandbox",
            "priority": "Critical",
            "output": "redacted",
            "output_fields": {
                "container.id": container_id[:12],
                "container.name": name,
                "proc.name": "bash",
                "fd.name": "/workspace/output.txt",
            },
        }
    )


def test_parses_only_target_container_and_normalizes_findings() -> None:
    target_id = "a" * 64
    alerts = parse_falco_json_lines(
        [falco_line("b" * 64, name="other"), falco_line(target_id)],
        target=FalcoTarget(target_id, "aegis-target"),
    )
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    findings = falco_alerts_to_findings(alerts)
    assert len(findings) == 1
    assert findings[0]["analyzer"] == "falco-adapter-v1"
    assert findings[0]["severity"] == "CRITICAL"
    assert target_id not in findings[0]["evidence"]


def test_rejects_malformed_falco_output() -> None:
    with pytest.raises(FalcoEvidenceError, match="无法解析"):
        parse_falco_json_lines(
            ["not-json"], target=FalcoTarget("a" * 64, "aegis-target")
        )


def test_ignores_diagnostic_json_without_target_fields() -> None:
    alerts = parse_falco_json_lines(
        [json.dumps({"level": "info", "message": "started"})],
        target=FalcoTarget("a" * 64, "aegis-target"),
    )
    assert alerts == []
