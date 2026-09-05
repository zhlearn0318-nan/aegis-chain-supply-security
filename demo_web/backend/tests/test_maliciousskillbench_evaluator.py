from __future__ import annotations

from tools.evaluation.run_maliciousskillbench_source_disjoint import (
    _binary_metrics,
    sanitized_findings,
)


def _row(label: str, decision: str) -> dict:
    return {"label": label, "systems": {"system": {"decision": decision}}}


def test_binary_metrics_keep_review_distinct_from_block() -> None:
    metrics = _binary_metrics(
        [_row("1", "BLOCK"), _row("1", "REVIEW"), _row("0", "ALLOW"), _row("0", "BLOCK")],
        "system",
    )
    assert metrics["malicious_non_allow_recall"] == 1.0
    assert metrics["malicious_block_rate"] == 0.5
    assert metrics["benign_allow_rate"] == 0.5
    assert metrics["benign_block_rate"] == 0.5


def test_sanitized_findings_drop_raw_evidence_and_descriptions() -> None:
    result = sanitized_findings([{
        "id": "one",
        "rule_id": "RULE",
        "category": "test",
        "severity": "HIGH",
        "analyzer": "static",
        "evidence_source": "CISCO",
        "evidence": "sensitive raw text",
        "description": "also sensitive",
        "location": {"file": "SKILL.md", "line": 2},
    }])
    assert result[0]["rule_id"] == "RULE"
    assert "evidence" not in result[0]
    assert "description" not in result[0]
