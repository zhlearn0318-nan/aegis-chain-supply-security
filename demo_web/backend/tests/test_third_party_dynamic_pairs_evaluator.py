from __future__ import annotations

import json
from pathlib import Path

from tools.evaluation import run_third_party_skill_dynamic_pairs as evaluator


def test_frozen_contract_has_balanced_pair_design() -> None:
    contract = json.loads(evaluator.CONTRACT_PATH.read_text(encoding="utf-8"))
    assert contract["contract_status"] == "frozen_before_main_run"
    assert contract["case_counts"] == {"total": 36, "original": 6, "controlled_risk_twin": 30}
    assert len(contract["risk_types"]) == 5
    assert contract["execution"]["known_malicious_third_party_execution"] is False


def test_acceptance_applies_frozen_thresholds_without_rounding() -> None:
    contract = json.loads(evaluator.CONTRACT_PATH.read_text(encoding="utf-8"))
    metrics = {
        "expected_dynamic_rule_recall": 0.9,
        "controlled_risk_non_allow_recall": 0.9,
        "original_allow_rate": 0.8,
        "three_round_attestation_rate": 1.0,
        "container_security_gate_rate": 1.0,
        "cleanup_verification_rate": 1.0,
        "case_tree_immutability_rate": 1.0,
    }
    assert evaluator.acceptance(metrics, contract)["passed"] is True
    metrics["expected_dynamic_rule_recall"] = 0.899999
    assert evaluator.acceptance(metrics, contract)["passed"] is False
