from __future__ import annotations

from tools.evaluation.run_m15_e02_malicious_train_semantic_regression import decision_metrics


def test_semantic_regression_metric_uses_nonallow() -> None:
    rows = [
        {"label": "1", "decision": "REVIEW"},
        {"label": "1", "decision": "ALLOW"},
        {"label": "0", "decision": "BLOCK"},
    ]
    result = decision_metrics(rows, "decision")
    assert result["malicious_non_allow_recall"] == 0.5
    assert result["benign_non_allow_rate"] == 1.0


def test_semantic_regression_metric_handles_single_class_source() -> None:
    malicious_only = decision_metrics(
        [{"label": "1", "decision": "BLOCK"}],
        "decision",
    )
    benign_only = decision_metrics(
        [{"label": "0", "decision": "ALLOW"}],
        "decision",
    )
    assert malicious_only["malicious_non_allow_recall"] == 1.0
    assert malicious_only["benign_non_allow_rate"] is None
    assert benign_only["malicious_non_allow_recall"] is None
    assert benign_only["benign_non_allow_rate"] == 0.0
