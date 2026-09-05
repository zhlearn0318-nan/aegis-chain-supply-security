from __future__ import annotations

from tools.evaluation.analyze_third_party_dynamic_pairs_posthoc import analyze, fused


def test_fusion_is_monotonic_and_unknown_fails_closed() -> None:
    assert fused("ALLOW", "BLOCK") == "BLOCK"
    assert fused("REVIEW", "ALLOW") == "REVIEW"
    assert fused("BLOCK", "ALLOW") == "BLOCK"
    assert fused("UNKNOWN", "ALLOW") == "BLOCK"


def test_posthoc_counts_new_and_stricter_dynamic_cases() -> None:
    manifest = [
        {"case_id": "base", "variant": "original", "risk_type": "none"},
        {"case_id": "miss", "variant": "controlled_risk_twin", "risk_type": "decoy_access"},
        {"case_id": "upgrade", "variant": "controlled_risk_twin", "risk_type": "shell_spawn"},
    ]
    static = [
        {"case_id": "base", "decision": "REVIEW"},
        {"case_id": "miss", "decision": "ALLOW"},
        {"case_id": "upgrade", "decision": "REVIEW"},
    ]
    dynamic = [
        {"case_id": "base", "decision": "ALLOW"},
        {"case_id": "miss", "decision": "BLOCK"},
        {"case_id": "upgrade", "decision": "BLOCK"},
    ]
    result = analyze(manifest, static, dynamic)
    assert result["originals"]["fused_decisions"] == {"REVIEW": 1}
    assert result["controlled_risks"]["dynamic_new_non_allow_cases"] == 1
    assert result["controlled_risks"]["dynamic_stricter_cases"] == 2
