from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend import app as gateway  # noqa: E402
from tools.dynamic.docker.fixtures import skill_runtime_closure as fixture  # noqa: E402


RUN_ID = "2026-08-23-skill-closure-platform-dev-v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
SOURCE_PATHS = (
    "backend/models.py",
    "backend/app.py",
    "backend/api_v1.py",
    "frontend/src/api.js",
    "frontend/src/main.jsx",
    "frontend/src/styles.css",
    "tools/dynamic/run_skill_closure_platform_acceptance.py",
)


def _sha256_file(path: Path) -> dict[str, str | int]:
    payload = path.read_bytes()
    return {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_text(path: Path, payload: str) -> None:
    path.write_text(payload.rstrip() + "\n", encoding="utf-8", newline="\n")


def _run_frontend(command: list[str]) -> dict[str, Any]:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=DEMO_ROOT / "frontend",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        shell=False,
        check=False,
    )
    return {
        "command": command,
        "return_code": completed.returncode,
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def _api_acceptance(runtime_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    admin_token = f"acceptance-{secrets.token_urlsafe(24)}"
    wrong_token = f"wrong-{secrets.token_urlsafe(18)}"
    previous_token = os.environ.get(gateway.ADMIN_TOKEN_ENV)
    original_db = gateway.DB_PATH
    original_job_root = gateway.DYNAMIC_JOB_ROOT
    gateway.DB_PATH = runtime_root / "scan_history.db"
    gateway.DYNAMIC_JOB_ROOT = runtime_root / "jobs"
    os.environ[gateway.ADMIN_TOKEN_ENV] = admin_token
    headers = {"X-Aegis-Admin-Token": admin_token}
    try:
        with TestClient(gateway.app) as client:
            missing = client.post("/api/v1/admin/dynamic-audits/skill-closure")
            incorrect = client.post(
                "/api/v1/admin/dynamic-audits/skill-closure",
                headers={"X-Aegis-Admin-Token": wrong_token},
            )
            body_rejected = client.post(
                "/api/v1/admin/dynamic-audits/skill-closure",
                headers=headers,
                json={"path": "user-supplied", "command": "arbitrary"},
            )
            health = client.get("/api/v1/health")
            created = client.post(
                "/api/v1/admin/dynamic-audits/skill-closure",
                headers=headers,
            )
            created_payload = created.json()
            job_id = created_payload["data"]["id"]
            detail = client.get(
                f"/api/v1/admin/dynamic-audits/{job_id}", headers=headers
            )
            listed = client.get(
                "/api/v1/admin/dynamic-audits?limit=5", headers=headers
            )

        detail_payload = detail.json()["data"]
        health_payload = health.json()["data"]
        with closing(sqlite3.connect(gateway.DB_PATH)) as database:
            stored_json = database.execute(
                "SELECT payload_json FROM dynamic_audits WHERE id = ?", (job_id,)
            ).fetchone()[0]
        response_text = "".join([
            missing.text, incorrect.text, body_rejected.text, health.text,
            created.text, detail.text, listed.text,
        ])
        raw_needles = [*fixture.INITIAL_FILES.values(), *fixture.MATERIALIZED_FILES.values()]
        raw_response_leaks = sum(needle in response_text for needle in raw_needles)
        raw_database_leaks = sum(needle in stored_json for needle in raw_needles)
        token_leaks = sum(
            token in response_text or token in stored_json
            for token in (admin_token, wrong_token)
        )
        closure_engine = next(
            engine for engine in health_payload["engines"]
            if engine["id"] == "dynamic-skill-closure"
        )
        metrics = detail_payload.get("metrics") or {}
        closure = detail_payload.get("closure") or {}
        static_lift = closure.get("static_lift") or {}
        api_metrics = {
            "missing_token_status": missing.status_code,
            "incorrect_token_status": incorrect.status_code,
            "request_body_status": body_rejected.status_code,
            "create_status": created.status_code,
            "detail_status": detail.status_code,
            "list_status": listed.status_code,
            "health_status": health.status_code,
            "closure_engine_ready": int(closure_engine.get("ready") is True),
            "job_completed": int(detail_payload.get("status") == "completed"),
            "audit_type_correct": int(
                detail_payload.get("audit_type") == "skill_runtime_closure"
            ),
            "fixture_identity_correct": int(
                detail_payload.get("fixture_set_id")
                == "aegis-skill-runtime-closure-v1"
            ),
            "closure_field_present": int(bool(closure)),
            "runtime_risk_rows_exposed": len(
                static_lift.get("runtime_risk_findings") or []
            ),
            "raw_response_leaks": raw_response_leaks,
            "raw_database_leaks": raw_database_leaks,
            "admin_token_leaks": token_leaks,
            "job_workspace_residuals": int(
                (gateway.DYNAMIC_JOB_ROOT / job_id).exists()
            ),
        }
        evidence = {
            "endpoint": "/api/v1/admin/dynamic-audits/skill-closure",
            "authentication": {
                "missing_token_status": missing.status_code,
                "incorrect_token_status": incorrect.status_code,
                "admin_header_only": True,
                "token_retained": False,
            },
            "request_contract": {
                "request_body_status": body_rejected.status_code,
                "accepts_user_code": False,
                "accepts_user_paths": False,
                "accepts_custom_commands": False,
            },
            "job": {
                "id_sha256": hashlib.sha256(job_id.encode("utf-8")).hexdigest(),
                "status": detail_payload.get("status"),
                "audit_type": detail_payload.get("audit_type"),
                "fixture_set_id": detail_payload.get("fixture_set_id"),
                "safety_boundary": detail_payload.get("safety_boundary"),
                "metrics": metrics,
                "closure": closure,
            },
            "persistence": {
                "sqlite_record_present": True,
                "stored_payload_sha256": hashlib.sha256(
                    stored_json.encode("utf-8")
                ).hexdigest(),
                "raw_content_retained": False,
                "admin_token_retained": False,
                "job_workspace_removed": not (
                    gateway.DYNAMIC_JOB_ROOT / job_id
                ).exists(),
            },
            "health": {
                "status": health_payload.get("status"),
                "closure_engine": closure_engine,
            },
        }
        return evidence, api_metrics
    finally:
        gateway.DB_PATH = original_db
        gateway.DYNAMIC_JOB_ROOT = original_job_root
        if previous_token is None:
            os.environ.pop(gateway.ADMIN_TOKEN_ENV, None)
        else:
            os.environ[gateway.ADMIN_TOKEN_ENV] = previous_token


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Accept the Skill closure through the real administrator API"
    )
    parser.add_argument("--run-id", default=RUN_ID)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.run_id != RUN_ID:
        raise ValueError(f"run-id must be {RUN_ID}")
    output = args.output.resolve(strict=False)
    output.mkdir(parents=True, exist_ok=True)
    protected = (
        "api_acceptance_evidence.json", "metrics.json", "evaluation_summary.json",
        "run_manifest.json", "artifact_manifest.json", "run.log", "bash.log",
        "frontend_test.log", "frontend_build.log", "summary.md",
    )
    existing = [name for name in protected if (output / name).exists()]
    if existing:
        raise ValueError(f"refusing to overwrite existing outputs: {existing}")

    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="platform-acceptance-", dir=output) as temp:
        api_evidence, api_metrics = _api_acceptance(Path(temp))
    frontend_test = _run_frontend(["npm.cmd", "test"])
    frontend_build = _run_frontend(["npm.cmd", "run", "build"])
    elapsed_seconds = round(time.perf_counter() - started, 3)
    completed_at = datetime.now(timezone.utc)
    d3c = api_evidence["job"]["metrics"]
    metrics = {
        "run_id": args.run_id,
        "schema_version": "1.0",
        **api_metrics,
        "d3c_all_gates_total": int(d3c.get("all_gates_total") or 0),
        "d3c_all_gates_passed": int(d3c.get("all_gates_passed") or 0),
        "materialized_files_observed": int(d3c.get("materialized_files_observed") or 0),
        "materialized_files_lifted": int(d3c.get("materialized_files_lifted") or 0),
        "materialized_hashes_verified": int(d3c.get("materialized_hashes_verified") or 0),
        "runtime_risk_findings": int(d3c.get("runtime_risk_findings") or 0),
        "vendor_scans": int(d3c.get("vendor_scans") or 0),
        "decision_changes": int(d3c.get("decision_changes") or 0),
        "container_residuals": int(d3c.get("container_residuals") or 0),
        "third_party_samples_executed": int(d3c.get("third_party_samples_executed") or 0),
        "internet_used": int(d3c.get("internet_used") or 0),
        "image_pull_used": int(d3c.get("image_pull_used") or 0),
        "frontend_tests_passed": int(frontend_test["return_code"] == 0),
        "frontend_build_passed": int(frontend_build["return_code"] == 0),
        "run_elapsed_seconds": elapsed_seconds,
    }
    positive = {
        "missing_token_status": 401,
        "incorrect_token_status": 401,
        "request_body_status": 400,
        "create_status": 202,
        "detail_status": 200,
        "list_status": 200,
        "health_status": 200,
        "closure_engine_ready": 1,
        "job_completed": 1,
        "audit_type_correct": 1,
        "fixture_identity_correct": 1,
        "closure_field_present": 1,
        "runtime_risk_rows_exposed": 2,
        "d3c_all_gates_total": 59,
        "d3c_all_gates_passed": 59,
        "materialized_files_observed": 3,
        "materialized_files_lifted": 3,
        "materialized_hashes_verified": 3,
        "runtime_risk_findings": 2,
        "vendor_scans": 2,
        "frontend_tests_passed": 1,
        "frontend_build_passed": 1,
    }
    negative = (
        "raw_response_leaks", "raw_database_leaks", "admin_token_leaks",
        "job_workspace_residuals", "decision_changes", "container_residuals",
        "third_party_samples_executed", "internet_used", "image_pull_used",
    )
    mismatches = {
        key: {"expected": expected, "observed": metrics.get(key)}
        for key, expected in positive.items() if metrics.get(key) != expected
    }
    negative_nonzero = {
        key: metrics.get(key) for key in negative if metrics.get(key) != 0
    }
    success = not mismatches and not negative_nonzero
    metrics["status"] = "completed" if success else "failed"
    api_evidence["acceptance"] = {
        "success": success,
        "positive_mismatches": mismatches,
        "negative_nonzero": negative_nonzero,
    }
    _write_json(output / "api_acceptance_evidence.json", api_evidence)
    _write_json(output / "metrics.json", metrics)
    _write_text(
        output / "frontend_test.log",
        json.dumps(frontend_test, ensure_ascii=False, indent=2),
    )
    _write_text(
        output / "frontend_build.log",
        json.dumps(frontend_build, ensure_ascii=False, indent=2),
    )
    evaluation_summary = {
        "takeaway": (
            "Skill 运行时闭包已通过真实管理员 API 接入统一平台，完成脱敏持久化和前端构建。"
            if success else "Skill 闭包平台接入至少一项 API、安全、D3-C 或前端门未通过。"
        ),
        "claim_update": "strengthens" if success else "neutral",
        "baseline_relation": "extends_d3c_without_metric_regression",
        "comparability": "high",
        "failure_mode": "none" if success else "implementation",
        "next_action": "add_dynamic_job_resource_queue" if success else "repair_platform_gate",
    }
    _write_json(output / "evaluation_summary.json", evaluation_summary)
    command = [sys.executable, *sys.argv]
    run_manifest = {
        "schema_version": "1.0",
        "run_id": args.run_id,
        "status": metrics["status"],
        "experiment_tier": "auxiliary/dev",
        "branch": "dynamic-audit-v1",
        "baseline": {
            "run_id": "2026-08-23-skill-runtime-closure-dev-v1",
            "commit": "4b4e843",
            "relation": "platform_delivery_extension_same_d3c_core",
        },
        "research_question": "D3-C 能否通过统一平台安全触发、脱敏持久化并展示？",
        "research_type": "deterministic_platform_integration_acceptance",
        "research_objective": "验证管理员 API、后台任务、Docker、静态提升、SQLite 与前端交付的完整链路。",
        "experimental_setup": {
            "endpoint": api_evidence["endpoint"],
            "request_body_allowed": False,
            "administrator_header_required": True,
            "docker_fixture": "self_built_hash_locked_only",
            "frontend_commands": [frontend_test["command"], frontend_build["command"]],
        },
        "experimental_results": metrics,
        "experimental_analysis": evaluation_summary["takeaway"],
        "experimental_conclusions": "supported" if success else "inconclusive",
        "null_hypothesis": "平台接入使鉴权、脱敏、D3-C 指标、清理或页面交付任一退化。",
        "alternative_hypothesis": "真实管理员 API 保持 D3-C 指标并完成无泄漏持久化与前端交付。",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "seed": None,
        "dataset": {
            "external_dataset": None,
            "controlled_fixtures": 1,
            "third_party_samples_executed": 0,
        },
        "environment": {
            "host_python": sys.version,
            "host_platform": platform.platform(),
            "gpu_used": False,
            "cloud_used": False,
            "internet_used": False,
            "image_pull_used": False,
        },
        "sources": {path: _sha256_file(DEMO_ROOT / path) for path in SOURCE_PATHS},
        "metric_contract": {
            "positive": positive,
            "negative_zero": list(negative),
        },
        "safety_contract": {
            "execution_trust": "self_built_hash_locked_only",
            "accepts_user_code": False,
            "accepts_user_paths": False,
            "accepts_custom_commands": False,
            "administrator_only": True,
            "raw_content_retained": False,
            "administrator_token_retained": False,
            "policy_effect": "none",
            "decision_changes": 0,
        },
        "evaluation_summary": evaluation_summary,
    }
    _write_json(output / "run_manifest.json", run_manifest)
    _write_text(
        output / "run.log",
        "\n".join([
            f"run_id={args.run_id}",
            f"status={metrics['status']}",
            f"api_statuses={metrics['create_status']}/{metrics['detail_status']}/{metrics['list_status']}",
            f"d3c_gates={metrics['d3c_all_gates_passed']}/{metrics['d3c_all_gates_total']}",
            f"materialized={metrics['materialized_files_observed']}/{metrics['materialized_files_lifted']}/{metrics['materialized_hashes_verified']}",
            f"runtime_risks={metrics['runtime_risk_findings']}",
            f"frontend={metrics['frontend_tests_passed']}/{metrics['frontend_build_passed']}",
            f"raw_response_leaks={metrics['raw_response_leaks']}",
            f"raw_database_leaks={metrics['raw_database_leaks']}",
            f"admin_token_leaks={metrics['admin_token_leaks']}",
            f"job_workspace_residuals={metrics['job_workspace_residuals']}",
            f"elapsed_seconds={elapsed_seconds}",
        ]),
    )
    _write_text(
        output / "bash.log",
        "\n".join([
            "execution_interface=exec_command",
            "required_bash_exec_artifact_memory_interfaces=unavailable",
            f"command={json.dumps(command, ensure_ascii=False)}",
            f"frontend_test_command={json.dumps(frontend_test['command'])}",
            f"frontend_build_command={json.dumps(frontend_build['command'])}",
            f"status={metrics['status']}",
        ]),
    )
    _write_text(
        output / "summary.md",
        "\n".join([
            "# D3-D Skill 运行时闭包平台接入结果",
            "",
            f"- 状态：`{metrics['status']}`",
            f"- API 创建/详情/列表：{metrics['create_status']}/{metrics['detail_status']}/{metrics['list_status']}",
            f"- 缺失令牌/错误令牌/请求体拒绝：{metrics['missing_token_status']}/{metrics['incorrect_token_status']}/{metrics['request_body_status']}",
            f"- D3-C 接受门：{metrics['d3c_all_gates_passed']}/{metrics['d3c_all_gates_total']}",
            f"- 新增/提升/哈希验证：{metrics['materialized_files_observed']}/{metrics['materialized_files_lifted']}/{metrics['materialized_hashes_verified']}",
            f"- 运行时风险：{metrics['runtime_risk_findings']}",
            f"- 前端测试/构建：{metrics['frontend_tests_passed']}/{metrics['frontend_build_passed']}",
            f"- 响应原文/数据库原文/令牌泄漏：{metrics['raw_response_leaks']}/{metrics['raw_database_leaks']}/{metrics['admin_token_leaks']}",
            f"- 任务工作区/容器残留：{metrics['job_workspace_residuals']}/{metrics['container_residuals']}",
            f"- 最终决策变化：{metrics['decision_changes']}",
            "- 边界：平台仍只运行固定自建 fixture，不开放第三方 Skill 或用户命令。",
        ]),
    )
    output_names = [
        "api_acceptance_evidence.json", "metrics.json", "evaluation_summary.json",
        "run_manifest.json", "run.log", "bash.log", "frontend_test.log",
        "frontend_build.log", "summary.md", "PLAN.md", "CHECKLIST.md",
    ]
    artifact_manifest = {
        "schema_version": "1.0",
        "run_id": args.run_id,
        "evidence_files": {
            name: _sha256_file(output / name)
            for name in output_names if (output / name).is_file()
        },
    }
    _write_json(output / "artifact_manifest.json", artifact_manifest)
    return {"run_id": args.run_id, "status": metrics["status"], "metrics": metrics}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"Skill closure platform acceptance failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
