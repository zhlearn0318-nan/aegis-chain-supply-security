from __future__ import annotations

import json
import sqlite3

from fastapi.testclient import TestClient

from backend import app as gateway


ADMIN_TOKEN = "test-admin-token-2026-memory-only"
ADMIN_HEADER = {"X-Aegis-Admin-Token": ADMIN_TOKEN}


def configure_isolated_runtime(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(gateway, "DB_PATH", tmp_path / "scan_history.db")
    monkeypatch.setattr(gateway, "DYNAMIC_JOB_ROOT", tmp_path / "dynamic-audit-jobs")


def test_dynamic_admin_api_fails_closed_when_server_token_is_not_configured(
    monkeypatch, tmp_path
) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    monkeypatch.delenv(gateway.ADMIN_TOKEN_ENV, raising=False)

    with TestClient(gateway.app) as client:
        response = client.post("/api/v1/admin/dynamic-audits")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ADMIN_TOKEN_NOT_CONFIGURED"


def test_dynamic_admin_api_rejects_missing_and_incorrect_tokens_without_reflection(
    monkeypatch, tmp_path
) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    monkeypatch.setenv(gateway.ADMIN_TOKEN_ENV, ADMIN_TOKEN)
    wrong = "wrong-admin-token-that-must-not-leak"

    with TestClient(gateway.app) as client:
        missing = client.get("/api/v1/admin/dynamic-audits")
        incorrect = client.get(
            "/api/v1/admin/dynamic-audits",
            headers={"X-Aegis-Admin-Token": wrong},
        )

    assert missing.status_code == 401
    assert incorrect.status_code == 401
    assert missing.json()["error"]["code"] == "ADMIN_TOKEN_INVALID"
    assert incorrect.json()["error"]["code"] == "ADMIN_TOKEN_INVALID"
    assert ADMIN_TOKEN not in missing.text + incorrect.text
    assert wrong not in missing.text + incorrect.text


def test_dynamic_create_rejects_any_request_body(monkeypatch, tmp_path) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    monkeypatch.setenv(gateway.ADMIN_TOKEN_ENV, ADMIN_TOKEN)

    with TestClient(gateway.app) as client:
        response = client.post(
            "/api/v1/admin/dynamic-audits",
            headers=ADMIN_HEADER,
            json={"script": "arbitrary.py", "command": "whoami"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "DYNAMIC_AUDIT_BODY_NOT_ALLOWED"
    assert "arbitrary.py" not in response.text
    assert "whoami" not in response.text


def test_skill_closure_create_rejects_any_request_body(monkeypatch, tmp_path) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    monkeypatch.setenv(gateway.ADMIN_TOKEN_ENV, ADMIN_TOKEN)

    with TestClient(gateway.app) as client:
        response = client.post(
            "/api/v1/admin/dynamic-audits/skill-closure",
            headers=ADMIN_HEADER,
            json={"skill_path": "untrusted", "command": "python arbitrary.py"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "DYNAMIC_AUDIT_BODY_NOT_ALLOWED"
    assert "untrusted" not in response.text
    assert "arbitrary.py" not in response.text


def test_dynamic_create_list_and_detail_persist_no_token(
    monkeypatch, tmp_path
) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    monkeypatch.setenv(gateway.ADMIN_TOKEN_ENV, ADMIN_TOKEN)
    monkeypatch.setattr(gateway, "guarded_dynamic_audit_worker", lambda _job_id: None)

    with TestClient(gateway.app) as client:
        created = client.post("/api/v1/admin/dynamic-audits", headers=ADMIN_HEADER)
        job_id = created.json()["data"]["id"]
        listed = client.get(
            "/api/v1/admin/dynamic-audits?limit=5", headers=ADMIN_HEADER
        )
        detail = client.get(
            f"/api/v1/admin/dynamic-audits/{job_id}", headers=ADMIN_HEADER
        )

    assert created.status_code == 202
    assert created.json()["data"]["status"] == "queued"
    assert created.json()["data"]["safety_boundary"]["accepts_user_code"] is False
    assert listed.json()["data"][0]["id"] == job_id
    assert detail.json()["data"]["fixture_set_id"] == "aegis-safe-dynamic-fixtures-v1"
    combined_responses = created.text + listed.text + detail.text
    assert ADMIN_TOKEN not in combined_responses

    with sqlite3.connect(gateway.DB_PATH) as db:
        stored = db.execute(
            "SELECT payload_json FROM dynamic_audits WHERE id = ?", (job_id,)
        ).fetchone()[0]
    assert ADMIN_TOKEN not in stored
    assert json.loads(stored)["safety_boundary"]["decision_changes"] == 0


def test_skill_closure_job_uses_fixed_identity_and_persists_only_redacted_result(
    monkeypatch, tmp_path
) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    monkeypatch.setenv(gateway.ADMIN_TOKEN_ENV, ADMIN_TOKEN)
    monkeypatch.setattr(gateway, "skill_closure_is_ready", lambda: True)
    raw_sentinel = "runtime-generated-secret-must-not-persist"

    def controlled_probe(_config, _workspace):
        return {
            "success": True,
            "error": None,
            "metrics": {
                "all_gates_passed": 59,
                "all_gates_total": 59,
                "materialized_files_expected": 3,
                "materialized_files_observed": 3,
                "materialized_files_lifted": 3,
                "materialized_hashes_verified": 3,
                "closure_coverage_rate": 1.0,
                "runtime_risk_findings": 2,
                "vendor_scans": 2,
                "raw_content_leaks": 0,
                "third_party_samples_executed": 0,
                "decision_changes": 0,
                "container_residuals": 0,
                "duration_ms": 1200,
            },
            "closure": {
                "materialized_bundle": [{"content_b64": raw_sentinel}],
                "pre_manifest": [{
                    "path": "SKILL.md", "bytes": 100, "sha256": "a" * 64,
                    "category": "initial",
                }],
                "post_manifest": [
                    {"path": "SKILL.md", "bytes": 100, "sha256": "a" * 64, "category": "initial"},
                    {"path": "runtime/generated_action.py", "bytes": 180, "sha256": "b" * 64, "category": "script"},
                ],
                "delta": {
                    "added": ["runtime/generated_action.py"],
                    "modified": [],
                    "deleted": [],
                },
                "static_lift": {
                    "pre_findings_total": 2,
                    "post_findings_total": 9,
                    "new_findings_total": 7,
                    "vendor_scans": 2,
                    "policy_effect": "none",
                    "runtime_risk_findings": [{
                        "id": "risk-1",
                        "rule_id": "AEGIS_REMOTE_FETCH_PIPE_SHELL",
                        "analyzer": "aegis-static-v1",
                        "severity": "CRITICAL",
                        "category": "remote_payload_execution",
                        "location": {"file": "runtime/generated_action.py", "line": 5},
                        "evidence_sha256": "c" * 64,
                        "raw_content_retained": False,
                        "description": raw_sentinel,
                    }],
                },
                "privacy": {
                    "raw_content_retained": False,
                    "raw_content_leaks": 0,
                    "content_bundles_retained": False,
                },
            },
        }

    monkeypatch.setattr(gateway, "run_skill_closure_probe", controlled_probe)

    with TestClient(gateway.app) as client:
        created = client.post(
            "/api/v1/admin/dynamic-audits/skill-closure", headers=ADMIN_HEADER
        )
        job_id = created.json()["data"]["id"]
        detail = client.get(
            f"/api/v1/admin/dynamic-audits/{job_id}", headers=ADMIN_HEADER
        )

    job = detail.json()["data"]
    assert created.status_code == 202
    assert job["status"] == "completed"
    assert job["audit_type"] == "skill_runtime_closure"
    assert job["fixture_set_id"] == "aegis-skill-runtime-closure-v1"
    assert job["safety_boundary"]["network_allowance"] == "none"
    assert job["safety_boundary"]["policy_effect"] == "none"
    assert job["metrics"]["decision_changes"] == 0
    assert job["closure"]["delta"]["added"] == ["runtime/generated_action.py"]
    assert job["closure"]["static_lift"]["runtime_risk_findings"][0]["severity"] == "CRITICAL"
    assert ADMIN_TOKEN not in created.text + detail.text
    assert raw_sentinel not in created.text + detail.text
    assert not (gateway.DYNAMIC_JOB_ROOT / job_id).exists()

    with sqlite3.connect(gateway.DB_PATH) as db:
        stored = db.execute(
            "SELECT payload_json FROM dynamic_audits WHERE id = ?", (job_id,)
        ).fetchone()[0]
    assert ADMIN_TOKEN not in stored
    assert raw_sentinel not in stored
    stored_job = json.loads(stored)
    assert stored_job["closure"]["static_lift"]["policy_effect"] == "none"


def test_dynamic_real_fixture_execution_is_redacted_and_info_only(
    monkeypatch, tmp_path
) -> None:
    configure_isolated_runtime(monkeypatch, tmp_path)
    monkeypatch.setenv(gateway.ADMIN_TOKEN_ENV, ADMIN_TOKEN)

    with TestClient(gateway.app) as client:
        created = client.post("/api/v1/admin/dynamic-audits", headers=ADMIN_HEADER)
        job_id = created.json()["data"]["id"]
        detail = client.get(
            f"/api/v1/admin/dynamic-audits/{job_id}", headers=ADMIN_HEADER
        )

    assert created.status_code == 202
    job = detail.json()["data"]
    assert job["status"] == "completed"
    assert job["metrics"]["fixtures_completed"] == 3
    assert job["metrics"]["expected_checks_passed"] == 7
    assert job["metrics"]["policy_violations"] == 0
    assert job["metrics"]["timeouts"] == 0
    assert job["metrics"]["raw_token_leaks"] == 0
    assert job["metrics"]["decision_changes"] == 0
    assert len(job["fixture_results"]) == 3
    assert job["events"]
    assert all(event["severity"] == "INFO" for event in job["events"])
    assert all(event["policy_effect"] == "none" for event in job["events"])
    assert "fixture_paths" not in job
    assert ADMIN_TOKEN not in detail.text
    assert not (gateway.DYNAMIC_JOB_ROOT / job_id).exists()


def test_dynamic_admin_openapi_declares_header_and_error_contract() -> None:
    schema = gateway.app.openapi()
    operation = schema["paths"]["/api/v1/admin/dynamic-audits"]["post"]

    assert "202" in operation["responses"]
    assert "400" in operation["responses"]
    assert "401" in operation["responses"]
    assert "503" in operation["responses"]
    header = next(
        item for item in operation["parameters"] if item["name"] == "X-Aegis-Admin-Token"
    )
    assert header["in"] == "header"

    closure_operation = schema["paths"][
        "/api/v1/admin/dynamic-audits/skill-closure"
    ]["post"]
    assert "202" in closure_operation["responses"]
    assert "400" in closure_operation["responses"]
    assert "401" in closure_operation["responses"]
    closure_header = next(
        item for item in closure_operation["parameters"]
        if item["name"] == "X-Aegis-Admin-Token"
    )
    assert closure_header["in"] == "header"
