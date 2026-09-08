from __future__ import annotations

from tools.evaluation.run_m15_e02_context_variants import protected_severity_map


def test_protected_severity_map_tracks_complete_rules_only() -> None:
    findings = [
        {"id": "a", "rule_id": "AEGIS_REMOTE_FETCH_PIPE_SHELL", "severity": "CRITICAL"},
        {"id": "b", "rule_id": "AEGIS_PARTIAL_REMOTE_EXEC_CHAIN", "severity": "MEDIUM"},
    ]
    assert protected_severity_map(findings) == {"a": "CRITICAL"}
