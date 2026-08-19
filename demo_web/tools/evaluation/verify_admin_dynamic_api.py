from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
import tempfile
import time
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend import app as gateway


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the administrator-only fixed dynamic fixture API"
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    output = args.output.resolve(strict=False)
    if output.exists():
        raise SystemExit(f"Refusing to overwrite existing output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    token = secrets.token_urlsafe(32)
    original_token = os.environ.get(gateway.ADMIN_TOKEN_ENV)
    original_db = gateway.DB_PATH
    original_job_root = gateway.DYNAMIC_JOB_ROOT
    started_at = utc_now()
    started = time.perf_counter()

    try:
        with tempfile.TemporaryDirectory(
            prefix="admin-dynamic-api-", dir=output.parent
        ) as temporary:
            temporary_root = Path(temporary)
            gateway.DB_PATH = temporary_root / "history.db"
            gateway.DYNAMIC_JOB_ROOT = temporary_root / "dynamic-jobs"
            os.environ[gateway.ADMIN_TOKEN_ENV] = token

            with TestClient(gateway.app) as client:
                rejected_body = client.post(
                    "/api/v1/admin/dynamic-audits",
                    headers={"X-Aegis-Admin-Token": token},
                    json={"script": "denied.py", "command": "denied"},
                )
                created = client.post(
                    "/api/v1/admin/dynamic-audits",
                    headers={"X-Aegis-Admin-Token": token},
                )
                job_id = created.json()["data"]["id"]
                detail = client.get(
                    f"/api/v1/admin/dynamic-audits/{job_id}",
                    headers={"X-Aegis-Admin-Token": token},
                )
                history = client.get(
                    "/api/v1/admin/dynamic-audits?limit=10",
                    headers={"X-Aegis-Admin-Token": token},
                )

            job = detail.json()["data"]
            database = sqlite3.connect(gateway.DB_PATH)
            try:
                stored_payload = database.execute(
                    "SELECT payload_json FROM dynamic_audits WHERE id = ?", (job_id,)
                ).fetchone()[0]
            finally:
                database.close()

            response_text = created.text + detail.text + history.text + rejected_body.text
            frontend_sources = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((gateway.DEMO_ROOT / "frontend" / "src").glob("*"))
                if path.is_file() and path.suffix in {".js", ".jsx"}
            )
            persistent_storage_call_markers = (
                "localStorage.",
                "sessionStorage.",
                "window.localStorage",
                "window.sessionStorage",
                "globalThis.localStorage",
                "globalThis.sessionStorage",
            )
            metrics = job["metrics"]
            checks: dict[str, bool] = {
                "create_http_202": created.status_code == 202,
                "custom_body_http_400": rejected_body.status_code == 400,
                "custom_body_stable_error": rejected_body.json()["error"]["code"]
                == "DYNAMIC_AUDIT_BODY_NOT_ALLOWED",
                "detail_http_200": detail.status_code == 200,
                "history_http_200": history.status_code == 200,
                "job_completed": job["status"] == "completed",
                "fixtures_3_of_3": metrics["fixtures_completed"] == metrics["fixtures_total"] == 3,
                "mechanisms_7_of_7": metrics["expected_checks_passed"]
                == metrics["expected_checks_total"]
                == 7,
                "negative_metrics_zero": all(
                    metrics[key] == 0
                    for key in (
                        "policy_violations",
                        "timeouts",
                        "event_parse_errors",
                        "non_info_evidence",
                        "raw_token_leaks",
                        "protected_samples_read",
                        "protected_samples_executed",
                        "internet_connections_allowed",
                        "decision_changes",
                    )
                ),
                "events_info_only": bool(job["events"])
                and all(event.get("severity") == "INFO" for event in job["events"]),
                "events_policy_effect_none": bool(job["events"])
                and all(event.get("policy_effect") == "none" for event in job["events"]),
                "token_not_in_responses": token not in response_text,
                "token_not_in_sqlite_payload": token not in stored_payload,
                "fixture_paths_not_exposed": "fixture_paths" not in job,
                "job_workspace_removed": not (gateway.DYNAMIC_JOB_ROOT / job_id).exists(),
                "no_browser_persistent_storage_api": not any(
                    marker in frontend_sources
                    for marker in persistent_storage_call_markers
                ),
            }
            result: dict[str, Any] = {
                "schema_version": "1.0",
                "run_id": "2026-08-18-admin-dynamic-api-ui-dev-v1",
                "status": "completed" if all(checks.values()) else "failed",
                "started_at": started_at,
                "completed_at": utc_now(),
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
                "fixture_set_id": job["fixture_set_id"],
                "fixture_set_sha256": job["fixture_set_sha256"],
                "api": {
                    "create_status": created.status_code,
                    "detail_status": detail.status_code,
                    "history_status": history.status_code,
                    "custom_body_status": rejected_body.status_code,
                },
                "checks": checks,
                "metrics": metrics,
                "fixture_results": [
                    {
                        "fixture_id": row["fixture_id"],
                        "status": row["status"],
                        "duration_ms": row["duration_ms"],
                        "policy_violations": row["policy_violations"],
                        "timed_out": row["timed_out"],
                    }
                    for row in job["fixture_results"]
                ],
                "event_type_counts": metrics["event_type_counts"],
                "safety_boundary": job["safety_boundary"],
                "token_value_retained": False,
                "protected_samples_read": 0,
                "protected_samples_executed": 0,
            }
            output.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            return 0 if result["status"] == "completed" else 1
    finally:
        gateway.DB_PATH = original_db
        gateway.DYNAMIC_JOB_ROOT = original_job_root
        if original_token is None:
            os.environ.pop(gateway.ADMIN_TOKEN_ENV, None)
        else:
            os.environ[gateway.ADMIN_TOKEN_ENV] = original_token


if __name__ == "__main__":
    raise SystemExit(main())
