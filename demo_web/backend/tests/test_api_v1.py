from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from backend import app as gateway
from backend.models import ScanJob


def sample_job() -> dict[str, Any]:
    return ScanJob(
        id="contract-job",
        created_at="2026-08-10T00:00:00+00:00",
        updated_at="2026-08-10T00:00:00+00:00",
        status="queued",
        target_kind="skill",
        source_kind="preset",
        display_name="contract fixture",
    ).model_dump(mode="json")


def sample_health() -> dict[str, Any]:
    return {
        "status": "ready",
        "mode": "LOCAL_STATIC_ONLY",
        "policy": {
            "ready": True,
            "id": "aegis-chain-local-default",
            "version": "1.0.0",
            "fail_closed": True,
        },
        "engines": [
            {
                "id": "skill",
                "name": "Skill Scanner",
                "ready": True,
                "version": "test",
                "analyzers": ["static"],
            }
        ],
        "privacy": "temporary files are deleted",
    }


def test_v1_health_is_enveloped_and_old_health_remains_unwrapped(monkeypatch) -> None:
    monkeypatch.setattr(gateway, "health", sample_health)
    with TestClient(gateway.app) as client:
        v1_response = client.get("/api/v1/health")
        old_response = client.get("/api/health")

    assert v1_response.status_code == 200
    assert v1_response.json() == {"api_version": "v1", "data": sample_health()}
    assert old_response.status_code == 200
    assert old_response.json()["status"] in {"ready", "degraded"}
    assert "engines" in old_response.json()
    assert "api_version" not in old_response.json()


def test_v1_scan_creation_returns_202_envelope(monkeypatch) -> None:
    monkeypatch.setattr(gateway, "start_preset", lambda _preset_id, _background: sample_job())

    with TestClient(gateway.app) as client:
        response = client.post("/api/v1/scans/preset/skill-risky")

    assert response.status_code == 202
    assert response.json()["api_version"] == "v1"
    assert response.json()["data"]["id"] == "contract-job"
    assert response.json()["data"]["schema_version"] == "1.2"


def test_v1_known_error_has_code_and_old_error_keeps_detail_shape() -> None:
    with TestClient(gateway.app) as client:
        v1_response = client.post("/api/v1/scans/preset/not-found")
        old_response = client.post("/api/scans/preset/not-found")

    assert v1_response.status_code == 404
    assert v1_response.json() == {
        "api_version": "v1",
        "error": {
            "code": "PRESET_NOT_FOUND",
            "message": "未找到预置样本",
            "details": None,
        },
    }
    assert old_response.status_code == 404
    assert old_response.json() == {"detail": "未找到预置样本"}


def test_v1_upload_error_exposes_machine_readable_context() -> None:
    with TestClient(gateway.app) as client:
        response = client.post(
            "/api/v1/scans/skill",
            files={"file": ("not-a-skill.txt", b"not a zip", "text/plain")},
        )

    assert response.status_code == 400
    payload = response.json()
    assert payload["error"]["code"] == "SKILL_FILE_TYPE_INVALID"
    assert payload["error"]["details"] == {
        "field": "file",
        "accepted_extension": ".zip",
    }


def test_v1_request_validation_error_uses_error_envelope() -> None:
    with TestClient(gateway.app) as client:
        response = client.post("/api/v1/scans/skill")

    assert response.status_code == 422
    payload = response.json()
    assert payload["api_version"] == "v1"
    assert payload["error"]["code"] == "REQUEST_VALIDATION_ERROR"
    assert payload["error"]["details"][0]["location"][-1] == "file"


def test_v1_get_scan_is_enveloped_and_old_get_scan_is_not(monkeypatch) -> None:
    monkeypatch.setattr(gateway, "load_job", lambda _job_id: sample_job())
    with TestClient(gateway.app) as client:
        v1_response = client.get("/api/v1/scans/contract-job")
        old_response = client.get("/api/scans/contract-job")

    assert v1_response.status_code == 200
    assert v1_response.json()["data"]["id"] == "contract-job"
    assert old_response.status_code == 200
    assert old_response.json()["id"] == "contract-job"
    assert "data" not in old_response.json()


def test_v1_internal_error_is_generic_and_machine_readable(monkeypatch) -> None:
    def fail_health() -> dict[str, Any]:
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr(gateway, "health", fail_health)
    with TestClient(gateway.app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_SERVER_ERROR"
    assert "sensitive internal detail" not in response.text


def test_v1_export_remains_a_file_response(monkeypatch) -> None:
    job = sample_job()
    monkeypatch.setattr(gateway, "load_job", lambda _job_id: job)
    with TestClient(gateway.app) as client:
        response = client.get("/api/v1/scans/contract-job/export?format=md")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "PENDING_SCAN" in response.text
    assert "api_version" not in response.text


def test_openapi_declares_both_route_families_and_v1_error_models() -> None:
    schema = gateway.app.openapi()

    assert "/api/health" in schema["paths"]
    assert "/api/v1/health" in schema["paths"]
    assert "/api/scans/skill" in schema["paths"]
    assert "/api/v1/scans/skill" in schema["paths"]
    v1_post = schema["paths"]["/api/v1/scans/skill"]["post"]
    assert "202" in v1_post["responses"]
    assert "400" in v1_post["responses"]
    assert "413" in v1_post["responses"]
    assert "422" in v1_post["responses"]
    assert "500" in v1_post["responses"]


def test_v1_unsupported_export_format_has_stable_code(monkeypatch) -> None:
    monkeypatch.setattr(gateway, "load_job", lambda _job_id: sample_job())
    with TestClient(gateway.app) as client:
        response = client.get("/api/v1/scans/contract-job/export?format=xml")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "EXPORT_FORMAT_UNSUPPORTED"
    assert response.json()["error"]["details"]["accepted_formats"] == ["json", "md", "sbom"]


def test_unknown_api_path_never_falls_through_to_spa_html() -> None:
    with TestClient(gateway.app) as client:
        v1_response = client.get("/api/v1/not-a-route")
        old_response = client.get("/api/not-a-route")

    assert v1_response.status_code == 404
    assert v1_response.json()["error"]["code"] == "API_ROUTE_NOT_FOUND"
    assert v1_response.headers["content-type"].startswith("application/json")
    assert old_response.status_code == 404
    assert old_response.json() == {"detail": "API 路径不存在。"}


def test_v1_method_not_allowed_uses_error_envelope() -> None:
    with TestClient(gateway.app) as client:
        response = client.delete("/api/v1/health")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "METHOD_NOT_ALLOWED"


def test_v1_list_limit_is_strictly_validated() -> None:
    with TestClient(gateway.app) as client:
        response = client.get("/api/v1/scans?limit=0")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "REQUEST_VALIDATION_ERROR"
    assert response.json()["error"]["details"][0]["location"] == ["query", "limit"]
