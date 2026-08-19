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
