from __future__ import annotations

from pathlib import Path

import pytest

from tools.evaluation import run_static_audit_regression as evaluator


def test_exact_mcnemar_counts_paired_correctness() -> None:
    rows = [
        {"ground_truth": "malicious", "baseline_predicted_label": "normal", "enhanced_predicted_label": "malicious"},
        {"ground_truth": "normal", "baseline_predicted_label": "normal", "enhanced_predicted_label": "normal"},
        {"ground_truth": "suspicious", "baseline_predicted_label": "suspicious", "enhanced_predicted_label": "normal"},
        {"ground_truth": "malicious", "baseline_predicted_label": "normal", "enhanced_predicted_label": "normal"},
    ]

    result = evaluator.exact_mcnemar(rows)

    assert result["both_correct"] == 1
    assert result["baseline_only_correct"] == 1
    assert result["enhanced_only_correct"] == 1
    assert result["both_wrong"] == 1
    assert result["p_value"] == pytest.approx(1.0)


def test_compact_findings_drops_raw_evidence() -> None:
    compact = evaluator.compact_findings([{
        "id": "x",
        "rule_id": "RULE_X",
        "category": "test",
        "severity": "HIGH",
        "analyzer": "test-analyzer",
        "location": "skill.py:4",
        "evidence": "verified_flow=secret raw payload;literal=do-not-retain",
        "message": "raw message",
    }])

    assert compact == [{
        "id": "x",
        "rule_id": "RULE_X",
        "category": "test",
        "severity": "HIGH",
        "analyzer": "test-analyzer",
        "location": "skill.py:4",
        "evidence_type": "verified_flow",
    }]
    assert "raw payload" not in str(compact)


def test_verdict_precedence_and_gates() -> None:
    comparable = {"comparable": True}
    bootstrap = {"ci_lower": 0.001}
    strong, _ = evaluator.classify_verdict(
        comparable,
        {"strict_macro_f1": 0.02, "malicious_recall": 0.0, "normal_fpr": 0.02},
        bootstrap,
    )
    refuted, _ = evaluator.classify_verdict(
        comparable,
        {"strict_macro_f1": 0.02, "malicious_recall": 0.0, "normal_fpr": 0.051},
        bootstrap,
    )
    not_comparable, _ = evaluator.classify_verdict(
        {"comparable": False},
        {"strict_macro_f1": 1.0, "malicious_recall": 1.0, "normal_fpr": -1.0},
        bootstrap,
    )

    assert strong == "strongly_supported"
    assert refuted == "refuted"
    assert not_comparable == "not_comparable"


def test_preflight_never_parses_regression_jsonl(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def forbidden_loader(path: Path):
        raise AssertionError(f"preflight must not parse JSONL: {path}")

    monkeypatch.setattr(evaluator, "load_jsonl", forbidden_loader)

    result = evaluator.preflight(tmp_path)

    assert result["status"] == "passed"
    assert result["regression_content_opened"] is False
    assert result["synthetic_self_test"]["status"] == "passed"
