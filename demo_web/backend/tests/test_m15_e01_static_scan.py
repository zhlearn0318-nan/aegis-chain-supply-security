from __future__ import annotations

from tools.evaluation.run_m15_e01_static_scan import (
    CAPABILITY_ANALYZER,
    ML_ANALYZER,
    SEMANTIC_ANALYZER,
    binary_decision_metrics,
    paired_comparison,
    partition_findings,
)


def _finding(analyzer: str, source: str = "AEGIS_STATIC") -> dict:
    return {"analyzer": analyzer, "evidence_source": source, "rule_id": analyzer}


def test_s0_to_s6_change_only_declared_components() -> None:
    deterministic = [
        _finding("static", "CISCO"),
        _finding("aegis-static-v1"),
        _finding(CAPABILITY_ANALYZER),
        _finding(SEMANTIC_ANALYZER),
    ]
    qwen = [_finding(SEMANTIC_ANALYZER), _finding(SEMANTIC_ANALYZER)]
    prediction = {
        "status": "predicted",
        "adds_medium_review_finding": True,
        "probability_malicious": 0.995,
        "threshold": 0.99,
        "case_id": "case",
    }
    systems = partition_findings(deterministic, qwen, prediction)
    assert [item["evidence_source"] for item in systems["S0"]] == ["CISCO"]
    assert {item["analyzer"] for item in systems["S1"]} == {"static", "aegis-static-v1"}
    assert CAPABILITY_ANALYZER in {item["analyzer"] for item in systems["S2"]}
    assert SEMANTIC_ANALYZER in {item["analyzer"] for item in systems["S3"]}
    assert sum(item["analyzer"] == SEMANTIC_ANALYZER for item in systems["S4"]) == 2
    assert systems["S5"][-1]["analyzer"] == ML_ANALYZER
    assert systems["S6"][-1]["analyzer"] == ML_ANALYZER


def _decision_row(label: str, left: str, right: str) -> dict:
    return {
        "label": label,
        "systems": {"L": {"decision": left}, "R": {"decision": right}},
    }


def test_validation_metrics_treat_review_and_unknown_as_non_allow() -> None:
    rows = [
        _decision_row("1", "ALLOW", "REVIEW"),
        _decision_row("1", "ALLOW", "UNKNOWN"),
        _decision_row("0", "ALLOW", "ALLOW"),
        _decision_row("0", "ALLOW", "BLOCK"),
    ]
    metrics = binary_decision_metrics(rows, "R")
    assert metrics["malicious_non_allow_recall"] == 1.0
    assert metrics["malicious_block_rate"] == 0.0
    assert metrics["benign_allow_rate"] == 0.5
    assert metrics["benign_block_rate"] == 0.5
    comparison = paired_comparison(rows, "L", "R")
    assert comparison["malicious_non_allow_recall_delta"]["estimate"] == 1.0
    assert comparison["benign_allow_rate_delta"]["estimate"] == -0.5
