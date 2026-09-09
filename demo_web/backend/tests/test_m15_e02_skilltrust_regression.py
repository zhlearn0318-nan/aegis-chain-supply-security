from __future__ import annotations

from tools.evaluation.run_m15_e02_skilltrust_regression import metrics


def test_metrics_count_review_or_block_as_malicious_non_allow() -> None:
    rows = [
        {"ground_truth": "malicious", "decision": "REVIEW"},
        {"ground_truth": "malicious", "decision": "ALLOW"},
        {"ground_truth": "normal", "decision": "BLOCK"},
    ]
    result = metrics(rows, "decision")
    assert result["malicious_non_allow_recall"] == 0.5
    assert result["normal_non_allow_rate"] == 1.0
