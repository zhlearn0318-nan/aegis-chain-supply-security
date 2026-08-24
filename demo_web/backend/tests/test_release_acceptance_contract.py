from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import app as gateway
from backend.dynamic_audit.docker_backend import DockerBackendError
from tools.release import run_release_http_acceptance as release_http
from tools.release import verify_vm_attestation as vm_attestation

DEMO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = DEMO_ROOT.parent
REPOSITORY_URL = "https://github.com/zhlearn0318-nan/aegis-chain-supply-security.git"
EXPECTED_COMMIT = "a" * 40
EXPECTED_REF = "refs/heads/dynamic-audit-v1"


def test_release_http_client_refuses_non_loopback_or_implicit_port() -> None:
    assert (
        release_http.validate_local_base_url("http://127.0.0.1:8765/")
        == "http://127.0.0.1:8765"
    )
    for value in (
        "https://127.0.0.1:8765",
        "http://example.com:8765",
        "http://127.0.0.1",
        "http://user:secret@127.0.0.1:8765",
        "http://127.0.0.1:8765/api",
    ):
        with pytest.raises(release_http.AcceptanceError):
            release_http.validate_local_base_url(value)


def test_release_oracles_are_deterministic_and_complete() -> None:
    skill_root = PROJECT_ROOT / "fixtures/skills/malicious_exfiltration"
    first = release_http.build_skill_zip(skill_root)
    second = release_http.build_skill_zip(skill_root)
    assert first == second
    assert len(first) > 100
    mcp = json.loads(release_http.build_mcp_bundle())
    assert len(mcp["tools"]) == 2
    assert len(mcp["prompts"]) == 2
    assert len(mcp["resources"]) == 2
    invalid_export = release_http.requests.Response()
    invalid_export.status_code = 200
    invalid_export.headers["content-disposition"] = 'attachment; filename="bad.json"'
    invalid_export._content = b"{}"

    class FakeSession:
        @staticmethod
        def get(*_args, **_kwargs):
            return invalid_export

    with pytest.raises(release_http.AcceptanceError, match="requested terminal job"):
        release_http.export_scan(
            FakeSession(),
            "http://127.0.0.1:8765",
            "expected-job",
            "json",
            Path("unused.json"),
        )


def test_static_release_oracle_rejects_missing_risk_evidence() -> None:
    job = {
        "status": "completed",
        "target_kind": "skill",
        "artifact_sha256": "b" * 64,
        "findings": [],
        "decision": "ALLOW",
        "policy_trace": {"fail_closed": True, "rule_id": "ALLOW_NO_FINDINGS"},
        "analyzers": ["test"],
        "duration_ms": 1,
    }
    with pytest.raises(release_http.AcceptanceError):
        release_http.verify_static_job(
            job, target_kind="skill", artifact_sha256="b" * 64
        )


def test_dynamic_release_oracle_requires_locked_fixture_metrics() -> None:
    boundary = {
        "execution_trust": "self_built_hash_locked_only",
        "accepts_user_code": False,
        "accepts_user_paths": False,
        "accepts_custom_commands": False,
        "raw_values_retained": False,
        "policy_effect": "none",
        "decision_changes": 0,
    }
    job = {
        "status": "completed",
        "audit_type": "mechanism_fixture",
        "fixture_set_id": "aegis-safe-dynamic-fixtures-v1",
        "safety_boundary": boundary,
        "metrics": {
            "fixtures_completed": 3,
            "expected_checks_passed": 7,
            "policy_violations": 0,
            "timeouts": 0,
            "raw_token_leaks": 0,
            "decision_changes": 0,
        },
    }
    release_http.verify_dynamic_job(job)
    job["metrics"]["decision_changes"] = 1
    with pytest.raises(release_http.AcceptanceError):
        release_http.verify_dynamic_job(job)


def test_skill_closure_readiness_reports_docker_failure_and_caches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "closure.json"
    scanner = tmp_path / "skill-scanner.exe"
    config.touch()
    scanner.touch()
    monkeypatch.setattr(gateway, "DYNAMIC_SKILL_CLOSURE_CONFIG", config)
    monkeypatch.setattr(gateway, "SKILL_SCANNER", scanner)
    monkeypatch.setattr(gateway, "load_skill_closure_config", lambda path: object())
    calls = 0

    def unavailable() -> Path:
        nonlocal calls
        calls += 1
        raise DockerBackendError("DOCKER_CLI_NOT_FOUND", "docker_discovery")

    monkeypatch.setattr(gateway, "discover_docker_cli", unavailable)
    gateway._SKILL_CLOSURE_READINESS_CACHE.update(checked_at=0.0, value=None)
    first = gateway.skill_closure_readiness()
    second = gateway.skill_closure_readiness()
    assert first["ready"] is False
    assert first["reason_code"] == "DOCKER_CLI_NOT_FOUND"
    assert second == first
    assert calls == 1


def test_health_and_admin_api_expose_closure_degradation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readiness = {
        "ready": False,
        "reason_code": "DOCKER_ENGINE_NOT_READY",
        "operation": "engine_version",
        "message": "Docker Skill closure is unavailable at engine_version.",
    }
    monkeypatch.setenv(gateway.ADMIN_TOKEN_ENV, "release-admin-token-for-tests")
    monkeypatch.setattr(gateway, "skill_closure_readiness", lambda: readiness)
    monkeypatch.setattr(gateway, "skill_closure_is_ready", lambda: False)
    with TestClient(gateway.app) as client:
        health = client.get("/api/v1/health")
        response = client.post(
            "/api/v1/admin/dynamic-audits/skill-closure",
            headers={"X-Aegis-Admin-Token": "release-admin-token-for-tests"},
        )
    assert health.status_code == 200
    engine = next(
        item
        for item in health.json()["data"]["engines"]
        if item["id"] == "dynamic-skill-closure"
    )
    assert engine["ready"] is False
    assert engine["reason_code"] == "DOCKER_ENGINE_NOT_READY"
    assert response.status_code == 503
    assert (
        response.json()["error"]["details"]["reason_code"] == "DOCKER_ENGINE_NOT_READY"
    )


def _valid_attestation(tmp_path: Path) -> tuple[Path, Path]:
    project_root = tmp_path / "fresh-clone"
    release_root = project_root / "demo_web/release_vm"
    release_root.mkdir(parents=True)
    source_manifest = DEMO_ROOT / "release_vm/toolchain.windows-x64.json"
    source_controller = DEMO_ROOT / "release_vm/Initialize-AegisAcceptanceGuest.ps1"
    manifest_path = release_root / source_manifest.name
    controller_path = release_root / source_controller.name
    manifest_path.write_bytes(source_manifest.read_bytes())
    controller_path.write_bytes(source_controller.read_bytes())
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    downloads = []
    for item in manifest["artifacts"]:
        download_path = tmp_path / item["file"]
        download_path.write_bytes(b"test-artifact")
        downloads.append({**item, "path": str(download_path), "verified": True})
    package_manager = manifest["package_managers"][0]
    package_path = tmp_path / package_manager["file"]
    package_path.write_bytes(b"test-package")
    downloads.append(
        {
            **package_manager,
            "path": str(package_path),
            "url": package_manager["tarball"],
            "verified": True,
        }
    )
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "schema_version": "1.0",
        "status": "completed",
        "virtual_machine": {
            "proof_accepted": True,
            "provider": "virtualbox",
            "manufacturer": "Oracle Corporation",
            "model": "VirtualBox",
            "machine_guid_sha256": "c" * 64,
        },
        "toolchain_manifest_sha256": vm_attestation.normalized_text_sha256(
            manifest_path
        ),
        "controller_sha256": vm_attestation.normalized_text_sha256(controller_path),
        "toolchain": {
            "downloads": downloads,
            "git": {"version": "git version 2.53.0.windows.3", "path": sys.executable},
            "node": {"version": "24.15.0", "path": "node.exe"},
            "conda": {"version": "conda 25.11.0", "path": "conda.exe"},
            "pnpm": {
                "version": manifest["package_managers"][0]["version"],
                "path": "pnpm.cmd",
                "integrity": manifest["package_managers"][0]["integrity"],
            },
        },
        "repository": {
            "fresh_clone": True,
            "target_preexisted": False,
            "url": REPOSITORY_URL,
            "ref": EXPECTED_REF,
            "remote_commit": EXPECTED_COMMIT,
            "checkout_commit": EXPECTED_COMMIT,
            "initial_status": "",
            "preexisting_generated_paths": [],
            "clone_started_at": now,
            "clone_completed_at": now,
            "path": str(project_root),
        },
        "negative_control": {
            "prebootstrap_preflight_exit": 1,
            "prebootstrap_required_failures": 8,
            "prebootstrap_ready": False,
            "output": {
                "checks": [
                    {"id": "skill_python", "status": "FAIL"},
                    {"id": "mcp_python", "status": "FAIL"},
                ]
            },
        },
    }
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path, project_root


def test_vm_attestation_requires_real_vm_fresh_clone_and_locked_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, project_root = _valid_attestation(tmp_path)

    def fake_git(_git: Path, _repository: Path, *arguments: str) -> str:
        if arguments == ("rev-parse", "HEAD"):
            return EXPECTED_COMMIT
        if arguments == ("remote", "get-url", "origin"):
            return REPOSITORY_URL
        if arguments[0] == "status":
            return ""
        raise AssertionError(arguments)

    monkeypatch.setattr(vm_attestation, "run_git", fake_git)
    monkeypatch.setattr(vm_attestation, "current_machine_guid_sha256", lambda: "c" * 64)
    expected_sha = {
        item["file"]: item["sha256"]
        for item in json.loads(
            (DEMO_ROOT / "release_vm/toolchain.windows-x64.json").read_text("utf-8")
        )["artifacts"]
    }
    monkeypatch.setattr(
        vm_attestation,
        "sha256_file",
        lambda path: expected_sha.get(path.name, "d" * 64),
    )
    monkeypatch.setattr(
        vm_attestation,
        "integrity_file",
        lambda _path: json.loads(
            (DEMO_ROOT / "release_vm/toolchain.windows-x64.json").read_text("utf-8")
        )["package_managers"][0]["integrity"],
    )
    result = vm_attestation.validate_attestation(
        attestation_path=path,
        project_root=project_root,
        expected_commit=EXPECTED_COMMIT,
        expected_ref=EXPECTED_REF,
        repository_url=REPOSITORY_URL,
    )
    assert result["status"] == "completed"
    assert result["provider"] == "virtualbox"
    assert result["tool_downloads_verified"] == 4


def test_vm_attestation_rejects_directory_simulation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, project_root = _valid_attestation(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["virtual_machine"]["provider"] = "unproved"
    payload["virtual_machine"]["proof_accepted"] = False
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(vm_attestation, "run_git", lambda *_args: "")
    with pytest.raises(vm_attestation.AttestationError, match="real VM"):
        vm_attestation.validate_attestation(
            attestation_path=path,
            project_root=project_root,
            expected_commit=EXPECTED_COMMIT,
            expected_ref=EXPECTED_REF,
            repository_url=REPOSITORY_URL,
        )


def test_guest_controller_and_gate_encode_non_simulation_contract() -> None:
    controller = (
        DEMO_ROOT / "release_vm/Initialize-AegisAcceptanceGuest.ps1"
    ).read_text(encoding="utf-8")
    gate = (DEMO_ROOT / "release_vm/Invoke-AegisReleaseAcceptance.ps1").read_text(
        encoding="utf-8"
    )
    manifest = json.loads(
        (DEMO_ROOT / "release_vm/toolchain.windows-x64.json").read_text("utf-8")
    )
    assert "Get-CimInstance Win32_ComputerSystem" in controller
    assert "Physical-host or directory simulation is rejected" in controller
    assert "git ls-remote" in controller
    assert "Fresh remote clone" in controller
    assert "prebootstrap_preflight_exit" in controller
    assert "SHA512" in controller
    assert "SRI mismatch" in controller
    assert 'corepack @("prepare"' not in controller
    assert '[string]$ProxyUrl = ""' in controller
    assert "proxy.UserInfo" in controller
    assert "$env:HTTPS_PROXY = $DownloadProxyUrl" in controller
    assert '[string]$GitSshPrivateKeyPath = ""' in controller
    assert '[string]$GitSshKnownHostsPath = ""' in controller
    assert "must be provided together" in controller
    assert "cannot be enabled together" in controller
    assert "restricted to the official GitHub SSH endpoints" in controller
    assert "aegis-readonly-deploy-key" in controller
    assert "$expectedKeyHeader" in controller
    assert "@('-----BEGIN', 'OPENSSH PRIVATE', 'KEY-----')" in controller
    assert "expectedKnownHost" in controller
    assert "StrictHostKeyChecking=yes" in controller
    assert "BatchMode=yes" in controller
    assert "read_only_deploy_key" in controller
    assert "git_ssh_private_key_retained" in controller
    assert "Remove-Item -LiteralPath $sshPrivateKey -Force" in controller
    assert "dependency-offline" in gate
    assert "--porcelain=v1" in gate
    assert '$priorErrorActionPreference = $ErrorActionPreference' in gate
    assert '$ErrorActionPreference = "Continue"' in gate
    assert '$ErrorActionPreference = $priorErrorActionPreference' in gate
    assert '($Id + ".step.json")' in gate
    assert all("latest" not in item["url"] for item in manifest["artifacts"])
    assert all(len(item["sha256"]) == 64 for item in manifest["artifacts"])
