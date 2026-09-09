from __future__ import annotations

from tools.evaluation.run_m15_e01_static_ablation import binary_metrics, select_threshold


def _config() -> dict:
    return {
        "lightweight_model": {
            "threshold_grid": {"minimum": 0.1, "maximum": 0.9, "step": 0.1}
        }
    }


def test_threshold_candidates_include_conservative_tail() -> None:
    from tools.evaluation.run_m15_e01_static_ablation import threshold_candidates

    config = _config()
    config["lightweight_model"]["threshold_grid"]["additional_values"] = [0.95, 1.0]
    values = threshold_candidates(config)
    assert values[-2:] == [0.95, 1.0]


def test_binary_metrics_preserves_undefined_class_metrics() -> None:
    metrics = binary_metrics([1, 1], [1, 0])
    assert metrics["malicious_recall"] == 0.5
    assert metrics["benign_false_positive_rate"] is None
    assert metrics["macro_f1"] is None


def test_threshold_selection_enforces_benign_fpr_gate() -> None:
    labels = [0, 0, 0, 0, 1, 1]
    probabilities = [0.05, 0.08, 0.12, 0.19, 0.18, 0.85]
    selected, rows = select_threshold(labels, probabilities, _config())
    assert selected["threshold"] == 0.8
    assert selected["benign_false_positive_rate"] == 0.0
    assert selected["malicious_recall"] == 0.5
    assert len(rows) == 9
