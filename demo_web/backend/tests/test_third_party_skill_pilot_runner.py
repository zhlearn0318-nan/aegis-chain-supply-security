from __future__ import annotations

from tools.evaluation.run_third_party_skill_pilot import compute_metrics, dynamic_eligibility


def result(case_id: str, truth: str, predicted: str, *, metric: bool = True) -> dict:
    decision = {"normal": "ALLOW", "suspicious": "REVIEW", "malicious": "BLOCK", "abstain": "UNKNOWN"}[predicted]
    return {
        "case_id": case_id,
        "ground_truth": truth,
        "predicted_label": predicted,
        "decision": decision,
        "status": "completed" if predicted != "abstain" else "failed",
        "metric_eligible": metric,
        "risk_labels": ["T01"] if truth != "normal" else [],
        "duration_ms": 10,
    }


def test_metrics_separate_strong_labels_from_weak_negatives() -> None:
    results = [
        result("n", "normal", "normal"),
        result("s", "suspicious", "suspicious"),
        result("m", "malicious", "malicious"),
        result("w", "weak_safe", "malicious", metric=False),
    ]

    metrics = compute_metrics(results)

    assert metrics["strong_label_metrics"]["strict_macro_f1"] == 1.0
    assert metrics["weak_negative_diagnostics"]["weak_negative_block_rate"] == 1.0
    assert metrics["strong_label_metrics"]["normal_fpr"] == 0.0


def test_dynamic_gate_never_executes_known_non_normal_case() -> None:
    sources = [
        {
            "case_id": "bad",
            "dynamic_label_eligible": False,
            "dynamic_candidate_pre_static": True,
            "python_entrypoints": ["scripts/run.py"],
        },
        {
            "case_id": "good",
            "dynamic_label_eligible": True,
            "dynamic_candidate_pre_static": True,
            "python_entrypoints": ["scripts/run.py"],
        },
    ]
    results = [
        result("bad", "malicious", "normal"),
        result("good", "normal", "normal"),
    ]

    eligibility = dynamic_eligibility(sources, results)

    assert eligibility[0]["eligible"] is False
    assert "ground_truth_safety_gate" in eligibility[0]["reasons"]
    assert eligibility[1]["eligible"] is True
