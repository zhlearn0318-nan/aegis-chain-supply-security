from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.adapters.process import AdapterResult
from backend.dynamic_audit.docker_backend import (
    EXPECTED_SECURITY,
    IMAGE_REFERENCE,
    DockerBackendError,
)
from backend.dynamic_audit.skill_closure import (
    DEMO_ROOT,
    EXPECTED_MATERIALIZED_PATHS,
    SKILL_CLOSURE_FIXTURE_SHA256,
    evaluate_skill_closure_payload,
    load_skill_closure_config,
)
from backend.skill_static_pipeline import run_skill_static_pipeline
from tools.dynamic.docker.fixtures import skill_runtime_closure as fixture


CONFIG_PATH = DEMO_ROOT / "config" / "docker_skill_closure_backend.json"


class EmptyVendorAdapter:
    def scan(self, _skill_path: Path) -> AdapterResult:
        return AdapterResult(
            report={
                "results": [{
                    "skill_name": "controlled-runtime-closure",
                    "analyzers_used": ["static_analyzer"],
                    "findings": [],
                }]
            },
            logs=["controlled vendor stub completed"],
        )


def _static_scan(skill_path: Path) -> dict:
    return run_skill_static_pipeline(skill_path, EmptyVendorAdapter())


def _payload(tmp_path: Path) -> dict:
    payload = fixture.build_payload(
        tmp_path / "fixture-skill", include_security_probe=False
    )
    payload.update({
        "probe_id": "aegis-docker-security-probe-v1",
        "uid": 65532,
        "gid": 65532,
        "cap_eff": "0000000000000000",
        "no_new_privs": "1",
        "seccomp": "2",
        "rootfs_write": {"succeeded": False},
        "input_write": {"succeeded": False},
        "workspace_write": {"succeeded": True, "content_matched": True},
        "temp_write": {"succeeded": True, "content_matched": True},
        "network_interfaces": ["lo"],
        "cwd": "/workspace",
    })
    return payload


def _mutated_config(tmp_path: Path, mutate) -> Path:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    mutate(payload)
    path = tmp_path / "skill-closure-config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_config_locks_fixture_image_closure_and_security() -> None:
    config = load_skill_closure_config(CONFIG_PATH)

    assert config.docker.image_reference == IMAGE_REFERENCE
    assert config.docker.fixture_sha256 == SKILL_CLOSURE_FIXTURE_SHA256
    assert config.materialized_paths == EXPECTED_MATERIALIZED_PATHS
    assert config.docker.security == EXPECTED_SECURITY


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update({"pull_policy": "always"}),
        lambda payload: payload["image"].update({"reference": "python:latest"}),
        lambda payload: payload["fixture"].update({"sha256": "0" * 64}),
        lambda payload: payload["closure"].update({"max_files": 500}),
        lambda payload: payload["security"].update({"network_mode": "bridge"}),
    ],
)
def test_config_rejects_identity_or_safety_relaxation(
    tmp_path: Path, mutate
) -> None:
    with pytest.raises(DockerBackendError):
        load_skill_closure_config(_mutated_config(tmp_path, mutate))


def test_fixture_materializes_exact_inert_instruction_script_and_config(
    tmp_path: Path,
) -> None:
    payload = _payload(tmp_path)
    pre_paths = {row["path"] for row in payload["pre_manifest"]}
    post_paths = {row["path"] for row in payload["post_manifest"]}

    assert pre_paths == set(fixture.INITIAL_FILES)
    assert post_paths - pre_paths == set(fixture.MATERIALIZED_FILES)
    assert payload["generated_content_executed"] is False
    assert {row["category"] for row in payload["post_manifest"]} >= {
        "instruction", "script", "config"
    }


def test_evaluator_recovers_runtime_only_risk_via_existing_static_pipeline(
    tmp_path: Path,
) -> None:
    config = load_skill_closure_config(CONFIG_PATH)
    result = evaluate_skill_closure_payload(
        _payload(tmp_path), config, tmp_path / "workspaces", static_scan=_static_scan
    )

    assert result["closure_coverage_rate"] == 1.0
    assert all(result["runtime_gates"].values())
    assert all(result["closure_gates"].values())
    assert result["static_lift"]["vendor_scans"] == 2
    assert result["static_lift"]["pre_policy_recommendation"] == "ALLOW"
    assert result["static_lift"]["post_policy_recommendation"] == "BLOCK"
    runtime_findings = result["static_lift"]["runtime_risk_findings"]
    assert runtime_findings
    assert any(
        finding["location"].get("file") == "runtime/generated_action.py"
        for finding in runtime_findings
    )


@pytest.mark.parametrize("bad_path", ["../escape.py", "/absolute.py", "runtime\\bad.py"])
def test_evaluator_rejects_unsafe_materialized_paths(
    tmp_path: Path, bad_path: str
) -> None:
    config = load_skill_closure_config(CONFIG_PATH)
    payload = _payload(tmp_path)
    payload["materialized_bundle"][0]["path"] = bad_path

    with pytest.raises(DockerBackendError, match="PATH_DENIED"):
        evaluate_skill_closure_payload(
            payload, config, tmp_path / "workspaces", static_scan=_static_scan
        )


def test_evaluator_rejects_hash_mismatch(tmp_path: Path) -> None:
    config = load_skill_closure_config(CONFIG_PATH)
    payload = _payload(tmp_path)
    payload["materialized_bundle"][0]["sha256"] = "0" * 64

    with pytest.raises(DockerBackendError, match="INTEGRITY_FAILED"):
        evaluate_skill_closure_payload(
            payload, config, tmp_path / "workspaces", static_scan=_static_scan
        )


def test_public_evidence_keeps_hashes_but_not_generated_content(tmp_path: Path) -> None:
    config = load_skill_closure_config(CONFIG_PATH)
    result = evaluate_skill_closure_payload(
        _payload(tmp_path), config, tmp_path / "workspaces", static_scan=_static_scan
    )
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)

    assert "content_b64" not in serialized
    assert result["privacy"] == {
        "raw_content_retained": False,
        "raw_content_leaks": 0,
        "content_bundles_retained": False,
    }
    for raw_content in fixture.MATERIALIZED_FILES.values():
        assert raw_content not in serialized
