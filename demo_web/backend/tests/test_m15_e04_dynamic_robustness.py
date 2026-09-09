from __future__ import annotations

from tools.evaluation.run_m15_e04_dynamic_robustness import metrics
from backend.dynamic_audit.docker_backend import DockerBackendError
from backend.dynamic_audit.skill_sandbox_multiruntime import run_multiruntime_entrypoint
from tools.dynamic.docker.skill_sandbox.runner_shell import _events


def test_metrics_requires_detection_and_clean_controls() -> None:
    records = [{"pair_id": "p1"}, {"pair_id": "p1"}]
    base = {
        "pair_id": "p1", "runtime": "python", "factor": "encoded_command",
        "three_rounds": True, "image_gates_all": True, "inspect_gates_all": True,
        "cleanup_verified": True, "input_unchanged": True, "internet_used_attestation": False,
        "infrastructure_failure_non_allow": None, "duration_ms": 10,
    }
    results = [
        {**base, "case_id": "c", "variant": "safe_control", "decision": "ALLOW", "expected_rule_detected": None},
        {**base, "case_id": "r", "variant": "transformed_risk", "decision": "REVIEW", "expected_rule_detected": True},
    ]
    contract = {"acceptance": {"transformed_non_allow": 1, "minimum_expected_rule_recall": .9, "safe_control_non_allow": 0}}
    output = metrics(records, results, contract)
    assert output["passed"] is True
    assert output["expected_rule_recall"] == 1.0


def test_metrics_exposes_allowed_transformation() -> None:
    records = [{"pair_id": "p1"}, {"pair_id": "p1"}]
    base = {
        "pair_id": "p1", "runtime": "shell", "factor": "split_sensitive_path",
        "three_rounds": True, "image_gates_all": True, "inspect_gates_all": True,
        "cleanup_verified": True, "input_unchanged": True, "internet_used_attestation": False,
        "infrastructure_failure_non_allow": None, "duration_ms": 10,
    }
    results = [
        {**base, "case_id": "c", "variant": "safe_control", "decision": "ALLOW", "expected_rule_detected": None},
        {**base, "case_id": "r", "variant": "transformed_risk", "decision": "ALLOW", "expected_rule_detected": False},
    ]
    contract = {"acceptance": {"transformed_non_allow": 1, "minimum_expected_rule_recall": .9, "safe_control_non_allow": 0}}
    output = metrics(records, results, contract)
    assert output["passed"] is False
    assert output["missed_transformed_cases"] == ["r"]


def test_multiruntime_discovery_failure_is_fail_closed(monkeypatch, tmp_path) -> None:
    class Config:
        pass

    def missing_cli():
        raise DockerBackendError("DOCKER_CLI_NOT_FOUND", "docker_discovery")

    monkeypatch.setattr("backend.dynamic_audit.skill_sandbox_multiruntime.discover_docker_cli", missing_cli)
    result = run_multiruntime_entrypoint(Config(), tmp_path, "main.py", "python", 9)
    assert result["success"] is False
    assert result["error"] == {"code": "DOCKER_CLI_NOT_FOUND", "operation": "docker_discovery"}
    assert result["evaluation"]["decision"] in {"REVIEW", "BLOCK"}


def test_shell_xtrace_records_expanded_decoy_path() -> None:
    events = _events(b"+ cat /workspace/decoys/database_credential.txt\n", "adversarial")
    assert {item["type"] for item in events} >= {"telemetry.ready", "decoy.read"}
    assert next(item for item in events if item["type"] == "decoy.read")["marker_id"] == "database_credential"
