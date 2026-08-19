from __future__ import annotations

import pytest

from tools.evaluation.run_skilltrustbench import (
    EvaluationError,
    SMOKE_IDS,
    compute_metrics,
    error_slices,
    sanitize_findings,
    select_records,
    validate_resume_prefix,
    verify_case,
)


def test_smoke_selection_is_frozen_and_keeps_declared_order() -> None:
    records = [{"id": case_id} for case_id in reversed(SMOKE_IDS)]

    selected = select_records(records, "smoke")

    assert [record["id"] for record in selected] == list(SMOKE_IDS)


def test_strict_metrics_count_abstention_as_error() -> None:
    records = [
        {"ground_truth": "normal", "predicted_label": "normal", "duration_ms": 10, "risk_labels": []},
        {"ground_truth": "suspicious", "predicted_label": "abstain", "duration_ms": 20, "risk_labels": ["T04"]},
        {"ground_truth": "malicious", "predicted_label": "malicious", "duration_ms": 30, "risk_labels": ["T04"]},
    ]

    metrics = compute_metrics(records, "smoke")

    assert metrics["coverage"] == 2 / 3
    assert metrics["failure_rate"] == 1 / 3
    assert metrics["strict_macro_f1"] == 2 / 3
    assert metrics["malicious_recall"] == 1.0
    assert metrics["non_normal_recall"] == 0.5
    assert metrics["per_risk_label_recall"]["T04"] == {
        "support": 2,
        "detected": 1,
        "recall": 0.5,
    }
    assert metrics["aegis_policy_loose_non_normal"] == {
        "mapping": "truth malicious/suspicious=positive; prediction BLOCK/REVIEW=positive",
        "not_equivalent_to_official_cisco_actual_safe": True,
        "tp": 1,
        "fp": 0,
        "fn": 1,
        "tn": 1,
        "abstention_count": 1,
        "precision": 1.0,
        "recall": 0.5,
        "loose_f1": 2 / 3,
        "fpr": 0.0,
    }


def test_loose_non_normal_metrics_use_policy_labels_and_strict_abstention() -> None:
    records = [
        {"ground_truth": "normal", "predicted_label": "suspicious", "duration_ms": 1, "risk_labels": []},
        {"ground_truth": "normal", "predicted_label": "normal", "duration_ms": 1, "risk_labels": []},
        {"ground_truth": "suspicious", "predicted_label": "malicious", "duration_ms": 1, "risk_labels": []},
        {"ground_truth": "malicious", "predicted_label": "abstain", "duration_ms": 1, "risk_labels": []},
    ]

    binary = compute_metrics(records, "official10")["aegis_policy_loose_non_normal"]

    assert (binary["tp"], binary["fp"], binary["fn"], binary["tn"]) == (1, 1, 1, 1)
    assert binary["precision"] == 0.5
    assert binary["recall"] == 0.5
    assert binary["loose_f1"] == 0.5
    assert binary["fpr"] == 0.5


def test_resume_requires_an_exact_frozen_prefix() -> None:
    selected = [{"id": "case_1"}, {"id": "case_2"}, {"id": "case_3"}]
    valid = [
        {"run_id": "run-1", "case_id": "case_1"},
        {"run_id": "run-1", "case_id": "case_2"},
    ]
    validate_resume_prefix(valid, selected, "run-1")

    with pytest.raises(EvaluationError, match="exact prefix"):
        validate_resume_prefix(list(reversed(valid)), selected, "run-1")
    with pytest.raises(EvaluationError, match="different run ID"):
        validate_resume_prefix([{**valid[0], "run_id": "other"}], selected, "run-1")


def test_endpoint_blocked_case_can_be_quarantined_after_audited_intake(tmp_path) -> None:
    cases_root = tmp_path / "cases"
    case_root = cases_root / "case_blocked"
    case_root.mkdir(parents=True)
    record = {
        "id": "case_blocked",
        "scanner_eligible": False,
        "case_tree_sha256": "a" * 64,
    }

    assert verify_case(case_root, record, cases_root) == "a" * 64


def test_sanitized_findings_never_copy_untrusted_text() -> None:
    findings = [{
        "id": "finding-1",
        "rule_id": "RULE-1",
        "category": "test",
        "severity": "HIGH",
        "analyzer": "static_analyzer",
        "location": {"file": "script.py", "line": 4},
        "title": "untrusted title",
        "evidence": "untrusted code",
        "description": "untrusted description",
        "remediation": "untrusted remediation",
    }]

    result = sanitize_findings(findings)

    assert result == [{
        "id": "finding-1",
        "rule_id": "RULE-1",
        "category": "test",
        "severity": "HIGH",
        "analyzer": "static_analyzer",
        "location": {"file": "script.py", "line": 4},
    }]
    assert "evidence" not in result[0]


def test_error_slices_follow_frozen_false_positive_and_negative_definitions() -> None:
    records = [
        {"case_id": "n1", "ground_truth": "normal", "predicted_label": "suspicious"},
        {"case_id": "n2", "ground_truth": "normal", "predicted_label": "abstain"},
        {"case_id": "s1", "ground_truth": "suspicious", "predicted_label": "malicious"},
        {"case_id": "m1", "ground_truth": "malicious", "predicted_label": "suspicious"},
        {"case_id": "m2", "ground_truth": "malicious", "predicted_label": "malicious"},
    ]

    slices = error_slices(records)

    assert [row["case_id"] for row in slices["false_positives"]] == ["n1"]
    assert [row["case_id"] for row in slices["false_negatives"]] == ["m1"]
    assert [row["case_id"] for row in slices["classification_errors"]] == ["n1", "n2", "s1", "m1"]
