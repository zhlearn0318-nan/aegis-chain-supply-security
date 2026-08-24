from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
TERMINAL_STATUSES = {"completed", "failed"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
EXPECTED_ENGINES = {"skill", "mcp", "dependency", "dynamic-fixture"}
REQUIRED_ANALYZERS = {
    "skill": {"static_analyzer", "aegis-static-v1"},
    "mcp": {"yara_analyzer", "aegis-mcp-policy-v1"},
    "dependency": {"pip-audit", "aegis-dependency-integrity-v1"},
}


class AcceptanceError(RuntimeError):
    """Raised when an externally observable release invariant is not met."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def validate_local_base_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS:
        raise AcceptanceError(
            "Release acceptance only sends the administrator token to a local HTTP endpoint."
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AcceptanceError(
            "Base URL must not contain credentials, a query, or a fragment."
        )
    if parsed.path not in {"", "/"}:
        raise AcceptanceError("Base URL must not contain a path.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise AcceptanceError("Base URL contains an invalid port.") from exc
    if port is None:
        raise AcceptanceError(
            "Base URL must include the explicitly selected local port."
        )
    return value.rstrip("/")


def require_response(response: requests.Response, expected: int, label: str) -> None:
    if response.status_code != expected:
        excerpt = response.text[:1000].replace("\r", " ").replace("\n", " ")
        raise AcceptanceError(
            f"{label} returned HTTP {response.status_code}; expected {expected}: {excerpt}"
        )


def api_data(response: requests.Response, expected: int, label: str) -> Any:
    require_response(response, expected, label)
    try:
        payload = response.json()
    except ValueError as exc:
        raise AcceptanceError(f"{label} did not return JSON.") from exc
    if not isinstance(payload, dict) or payload.get("api_version") != "v1":
        raise AcceptanceError(f"{label} returned an invalid API v1 envelope.")
    if "data" not in payload:
        raise AcceptanceError(f"{label} API v1 envelope has no data field.")
    return payload["data"]


def api_error_code(response: requests.Response, expected: int, label: str) -> str:
    require_response(response, expected, label)
    try:
        payload = response.json()
    except ValueError as exc:
        raise AcceptanceError(f"{label} did not return JSON.") from exc
    error = payload.get("error") if isinstance(payload, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    if payload.get("api_version") != "v1" or not isinstance(code, str):
        raise AcceptanceError(f"{label} returned an invalid API v1 error envelope.")
    return code


def build_skill_zip(skill_root: Path) -> bytes:
    if not (skill_root / "SKILL.md").is_file():
        raise AcceptanceError(f"Skill fixture is missing SKILL.md: {skill_root}")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(skill_root.rglob("*")):
            if path.is_file():
                relative = path.relative_to(skill_root).as_posix()
                info = zipfile.ZipInfo(relative, date_time=(2020, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, path.read_bytes())
    return buffer.getvalue()


def build_mcp_bundle() -> bytes:
    tools = json.loads((REPOSITORY_ROOT / "fixtures/mcp/tools.json").read_text("utf-8"))
    prompts = json.loads(
        (REPOSITORY_ROOT / "fixtures/mcp/prompts.json").read_text("utf-8")
    )
    resources = json.loads(
        (REPOSITORY_ROOT / "fixtures/mcp/resources.json").read_text("utf-8")
    )
    payload = {
        "tools": tools["tools"],
        "prompts": prompts["prompts"],
        "resources": resources["contents"],
    }
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode()


def wait_for_scan(
    session: requests.Session,
    base_url: str,
    job_id: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        job = api_data(
            session.get(f"{base_url}/api/v1/scans/{job_id}", timeout=10),
            200,
            f"scan detail {job_id}",
        )
        if job.get("status") in TERMINAL_STATUSES:
            return job
        time.sleep(0.25)
    raise AcceptanceError(f"Scan {job_id} did not reach a terminal state.")


def wait_for_dynamic(
    session: requests.Session,
    base_url: str,
    job_id: str,
    headers: dict[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        job = api_data(
            session.get(
                f"{base_url}/api/v1/admin/dynamic-audits/{job_id}",
                headers=headers,
                timeout=10,
            ),
            200,
            f"dynamic detail {job_id}",
        )
        if job.get("status") in TERMINAL_STATUSES:
            return job
        time.sleep(0.25)
    raise AcceptanceError(f"Dynamic audit {job_id} did not reach a terminal state.")


def verify_static_job(
    job: dict[str, Any],
    *,
    target_kind: str,
    artifact_sha256: str,
    minimum_findings: int = 1,
) -> None:
    if job.get("status") != "completed":
        raise AcceptanceError(
            f"{target_kind} scan failed closed instead of completing: {job.get('error')}"
        )
    if job.get("target_kind") != target_kind:
        raise AcceptanceError(f"Expected {target_kind}, got {job.get('target_kind')}.")
    if job.get("artifact_sha256") != artifact_sha256:
        raise AcceptanceError(f"{target_kind} artifact SHA-256 changed across upload.")
    findings = job.get("findings")
    if not isinstance(findings, list) or len(findings) < minimum_findings:
        raise AcceptanceError(
            f"{target_kind} did not expose the expected risk evidence."
        )
    if job.get("decision") not in {"BLOCK", "REVIEW"}:
        raise AcceptanceError(
            f"{target_kind} unsafe oracle did not produce BLOCK/REVIEW: {job.get('decision')}"
        )
    trace = job.get("policy_trace") or {}
    if trace.get("fail_closed") is not True or not trace.get("rule_id"):
        raise AcceptanceError(f"{target_kind} policy trace is incomplete.")
    analyzers = job.get("analyzers")
    if not isinstance(analyzers, list) or not REQUIRED_ANALYZERS[target_kind].issubset(
        set(analyzers)
    ):
        raise AcceptanceError(
            f"{target_kind} did not run the required vendor and Aegis analyzers."
        )
    if not isinstance(job.get("duration_ms"), int):
        raise AcceptanceError(f"{target_kind} analyzer or timing evidence is missing.")


def verify_dynamic_job(job: dict[str, Any]) -> None:
    if job.get("status") != "completed":
        raise AcceptanceError(f"Dynamic fixture failed: {job.get('error')}")
    if job.get("audit_type") != "mechanism_fixture":
        raise AcceptanceError("Dynamic audit did not run the mechanism fixture set.")
    if job.get("fixture_set_id") != "aegis-safe-dynamic-fixtures-v1":
        raise AcceptanceError("Dynamic fixture identity changed.")
    boundary = job.get("safety_boundary") or {}
    expected_boundary = {
        "execution_trust": "self_built_hash_locked_only",
        "accepts_user_code": False,
        "accepts_user_paths": False,
        "accepts_custom_commands": False,
        "raw_values_retained": False,
        "policy_effect": "none",
        "decision_changes": 0,
    }
    mismatches = {
        key: {"expected": expected, "observed": boundary.get(key)}
        for key, expected in expected_boundary.items()
        if boundary.get(key) != expected
    }
    if mismatches:
        raise AcceptanceError(f"Dynamic safety boundary changed: {mismatches}")
    metrics = job.get("metrics") or {}
    expected_metrics = {
        "fixtures_completed": 3,
        "expected_checks_passed": 7,
        "policy_violations": 0,
        "timeouts": 0,
        "raw_token_leaks": 0,
        "decision_changes": 0,
    }
    mismatches = {
        key: {"expected": expected, "observed": metrics.get(key)}
        for key, expected in expected_metrics.items()
        if metrics.get(key) != expected
    }
    if mismatches:
        raise AcceptanceError(f"Dynamic mechanism metrics changed: {mismatches}")


def export_scan(
    session: requests.Session,
    base_url: str,
    job_id: str,
    export_format: str,
    output: Path,
) -> dict[str, Any]:
    response = session.get(
        f"{base_url}/api/v1/scans/{job_id}/export",
        params={"format": export_format},
        timeout=30,
    )
    require_response(response, 200, f"{export_format} export {job_id}")
    disposition = response.headers.get("content-disposition", "")
    if "attachment" not in disposition.lower():
        raise AcceptanceError(f"{export_format} export has no attachment disposition.")
    if not response.content:
        raise AcceptanceError(f"{export_format} export is empty.")
    if export_format in {"json", "sbom"}:
        try:
            payload = response.json()
        except ValueError as exc:
            raise AcceptanceError(f"{export_format} export is not valid JSON.") from exc
        if export_format == "json" and (
            not isinstance(payload, dict)
            or payload.get("id") != job_id
            or payload.get("status") not in TERMINAL_STATUSES
        ):
            raise AcceptanceError(
                "JSON export does not represent the requested terminal job."
            )
        if export_format == "sbom" and (
            not isinstance(payload, dict)
            or payload.get("bomFormat") != "CycloneDX"
            or not isinstance(payload.get("components"), list)
            or not payload["components"]
        ):
            raise AcceptanceError("SBOM export is not a non-empty CycloneDX document.")
    elif export_format == "md":
        try:
            markdown = response.content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AcceptanceError("Markdown export is not UTF-8.") from exc
        if job_id not in markdown or len(markdown) < 100:
            raise AcceptanceError(
                "Markdown export does not represent the requested job."
            )
    output.write_bytes(response.content)
    return {
        "format": export_format,
        "bytes": len(response.content),
        "sha256": sha256_bytes(response.content),
        "content_type": response.headers.get("content-type", ""),
        "file": output.name,
    }


def write_artifact_manifest(output: Path) -> None:
    artifact_rows = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "artifact_manifest.json":
            artifact_rows.append(
                {
                    "path": path.relative_to(output).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    (output / "artifact_manifest.json").write_text(
        json.dumps(
            {"schema_version": "1.0", "artifacts": artifact_rows},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def run_offline_dependency_probe(args: argparse.Namespace) -> dict[str, Any]:
    base_url = validate_local_base_url(args.base_url)
    output = args.output.resolve(strict=False)
    if output.exists() and any(output.iterdir()):
        raise AcceptanceError(f"Refusing to overwrite non-empty output: {output}")
    output.mkdir(parents=True, exist_ok=True)
    exports = output / "exports"
    exports.mkdir(parents=False, exist_ok=False)
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "Aegis-Release-Offline-Probe/1.0"})
    started_at = utc_now()
    started = time.perf_counter()
    health = api_data(
        session.get(f"{base_url}/api/v1/health", timeout=15),
        200,
        "offline-probe health",
    )
    dependency_engine = next(
        (
            item
            for item in health.get("engines", [])
            if isinstance(item, dict) and item.get("id") == "dependency"
        ),
        None,
    )
    if not dependency_engine or dependency_engine.get("ready") is not True:
        raise AcceptanceError(
            "Dependency scanner must exist before the offline provider probe."
        )
    dependency_bytes = (
        REPOSITORY_ROOT / "fixtures/vulnerable_dependencies/requirements_urllib3.txt"
    ).read_bytes()
    submitted = api_data(
        session.post(
            f"{base_url}/api/v1/scans/dependency",
            files={
                "requirements": (
                    "requirements_urllib3.txt",
                    dependency_bytes,
                    "text/plain",
                )
            },
            timeout=args.request_timeout,
        ),
        202,
        "offline dependency submission",
    )
    job = wait_for_scan(
        session, base_url, submitted["id"], timeout_seconds=args.scan_timeout
    )
    trace = job.get("policy_trace") or {}
    if (
        job.get("status") != "failed"
        or job.get("decision") != "UNKNOWN"
        or trace.get("fail_closed") is not True
        or trace.get("rule_id") != "SCAN_EXECUTION_FAILED"
        or not job.get("error")
    ):
        raise AcceptanceError(
            "Unavailable vulnerability provider was not represented as an explicit fail-closed job."
        )
    export = export_scan(
        session,
        base_url,
        job["id"],
        "json",
        exports / f"offline-dependency-{job['id']}.json",
    )
    result = {
        "schema_version": "1.0",
        "status": "completed",
        "started_at": started_at,
        "completed_at": utc_now(),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "base_url": base_url,
        "network_fault": (
            "HTTP_PROXY/HTTPS_PROXY/ALL_PROXY routed to closed loopback port "
            "by the release controller"
        ),
        "dependency_engine_ready_before_fault": True,
        "job": job,
        "export": export,
        "fail_closed_verified": True,
    }
    (output / "offline_dependency_probe.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    write_artifact_manifest(output)
    return {
        "status": "completed",
        "mode": "dependency-offline",
        "fail_closed_verified": True,
        "output": str(output),
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    base_url = validate_local_base_url(args.base_url)
    output = args.output.resolve(strict=False)
    if output.exists() and any(output.iterdir()):
        raise AcceptanceError(f"Refusing to overwrite non-empty output: {output}")
    output.mkdir(parents=True, exist_ok=True)
    exports = output / "exports"
    exports.mkdir(parents=False, exist_ok=False)

    admin_token = os.environ.get(args.admin_token_env, "")
    if len(admin_token) < 16:
        raise AcceptanceError(
            f"{args.admin_token_env} must contain at least 16 characters."
        )
    headers = {"X-Aegis-Admin-Token": admin_token}
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "Aegis-Release-Acceptance/1.0"})

    started_at = utc_now()
    started = time.perf_counter()

    page = session.get(f"{base_url}/", timeout=15)
    require_response(page, 200, "frontend page")
    if "text/html" not in page.headers.get("content-type", "").lower():
        raise AcceptanceError("Root route did not serve the built frontend.")
    page_text = page.text
    if "Aegis Chain" not in page_text or 'id="root"' not in page_text:
        raise AcceptanceError("Built frontend markers are missing from the root page.")

    health = api_data(
        session.get(f"{base_url}/api/v1/health", timeout=15),
        200,
        "health",
    )
    engines = {
        engine.get("id"): engine
        for engine in health.get("engines", [])
        if isinstance(engine, dict)
    }
    missing_engines = EXPECTED_ENGINES.difference(engines)
    if missing_engines:
        raise AcceptanceError(f"Health response is missing engines: {missing_engines}")
    not_ready = [
        name for name in EXPECTED_ENGINES if engines[name].get("ready") is not True
    ]
    if not_ready:
        raise AcceptanceError(f"Required four-chain engines are not ready: {not_ready}")

    missing_auth = session.post(f"{base_url}/api/v1/admin/dynamic-audits", timeout=15)
    missing_auth_code = api_error_code(
        missing_auth, 401, "dynamic audit without administrator token"
    )
    if missing_auth_code != "ADMIN_TOKEN_INVALID":
        raise AcceptanceError(
            f"Missing administrator token returned unexpected code: {missing_auth_code}"
        )

    skill_bytes = build_skill_zip(
        REPOSITORY_ROOT / "fixtures/skills/malicious_exfiltration"
    )
    mcp_bytes = build_mcp_bundle()
    dependency_bytes = (
        REPOSITORY_ROOT / "fixtures/vulnerable_dependencies/requirements_urllib3.txt"
    ).read_bytes()
    uploads: dict[str, dict[str, Any]] = {}
    submissions = {
        "skill": session.post(
            f"{base_url}/api/v1/scans/skill",
            files={
                "file": ("malicious_exfiltration.zip", skill_bytes, "application/zip")
            },
            timeout=args.request_timeout,
        ),
        "mcp": session.post(
            f"{base_url}/api/v1/scans/mcp",
            files={"mcp_json": ("mcp-risk-oracle.json", mcp_bytes, "application/json")},
            timeout=args.request_timeout,
        ),
        "dependency": session.post(
            f"{base_url}/api/v1/scans/dependency",
            files={
                "requirements": (
                    "requirements_urllib3.txt",
                    dependency_bytes,
                    "text/plain",
                )
            },
            timeout=args.request_timeout,
        ),
    }
    upload_bytes = {
        "skill": skill_bytes,
        "mcp": mcp_bytes,
        "dependency": dependency_bytes,
    }
    for kind, response in submissions.items():
        submitted = api_data(response, 202, f"{kind} submission")
        job_id = submitted.get("id")
        if not isinstance(job_id, str) or not job_id:
            raise AcceptanceError(f"{kind} submission did not return a job ID.")
        job = wait_for_scan(
            session, base_url, job_id, timeout_seconds=args.scan_timeout
        )
        digest = sha256_bytes(upload_bytes[kind])
        verify_static_job(job, target_kind=kind, artifact_sha256=digest)
        uploads[kind] = {
            "job": job,
            "upload_sha256": digest,
            "exports": [
                export_scan(
                    session,
                    base_url,
                    job_id,
                    "json",
                    exports / f"{kind}-{job_id}.json",
                ),
                export_scan(
                    session,
                    base_url,
                    job_id,
                    "md",
                    exports / f"{kind}-{job_id}.md",
                ),
            ],
        }
    dependency_job = uploads["dependency"]["job"]
    if not isinstance(dependency_job.get("sbom"), dict):
        raise AcceptanceError("Dependency scan did not return a CycloneDX SBOM.")
    uploads["dependency"]["exports"].append(
        export_scan(
            session,
            base_url,
            dependency_job["id"],
            "sbom",
            exports / f"dependency-{dependency_job['id']}.cdx.json",
        )
    )

    listed = api_data(
        session.get(f"{base_url}/api/v1/scans", params={"limit": 20}, timeout=15),
        200,
        "scan list",
    )
    listed_ids = {item.get("id") for item in listed if isinstance(item, dict)}
    expected_ids = {item["job"]["id"] for item in uploads.values()}
    if not expected_ids.issubset(listed_ids):
        raise AcceptanceError("Scan list did not expose every accepted upload job.")

    dynamic_submission = api_data(
        session.post(
            f"{base_url}/api/v1/admin/dynamic-audits",
            headers=headers,
            timeout=15,
        ),
        202,
        "dynamic fixture submission",
    )
    dynamic_job = wait_for_dynamic(
        session,
        base_url,
        dynamic_submission["id"],
        headers,
        timeout_seconds=args.dynamic_timeout,
    )
    verify_dynamic_job(dynamic_job)
    dynamic_list = api_data(
        session.get(
            f"{base_url}/api/v1/admin/dynamic-audits",
            params={"limit": 20},
            headers=headers,
            timeout=15,
        ),
        200,
        "dynamic audit list",
    )
    if dynamic_job["id"] not in {
        item.get("id") for item in dynamic_list if isinstance(item, dict)
    }:
        raise AcceptanceError("Dynamic audit list did not expose the completed job.")

    closure_engine = engines.get("dynamic-skill-closure") or {}
    closure_probe: dict[str, Any]
    if closure_engine.get("ready") is True:
        closure_submission = api_data(
            session.post(
                f"{base_url}/api/v1/admin/dynamic-audits/skill-closure",
                headers=headers,
                timeout=15,
            ),
            202,
            "Docker Skill closure submission",
        )
        closure_job = wait_for_dynamic(
            session,
            base_url,
            closure_submission["id"],
            headers,
            timeout_seconds=args.dynamic_timeout,
        )
        if closure_job.get("status") != "completed":
            raise AcceptanceError(
                f"Docker Skill closure failed: {closure_job.get('error')}"
            )
        closure_boundary = closure_job.get("safety_boundary") or {}
        closure_metrics = closure_job.get("metrics") or {}
        if (
            closure_job.get("audit_type") != "skill_runtime_closure"
            or closure_job.get("fixture_set_id") != "aegis-skill-runtime-closure-v1"
            or closure_boundary.get("network_allowance") != "none"
            or closure_boundary.get("policy_effect") != "none"
            or closure_metrics.get("decision_changes") != 0
        ):
            raise AcceptanceError("Docker Skill closure safety evidence changed.")
        closure_probe = {
            "mode": "executed",
            "status": closure_job.get("status"),
            "job_id": closure_job.get("id"),
        }
    else:
        closure_response = session.post(
            f"{base_url}/api/v1/admin/dynamic-audits/skill-closure",
            headers=headers,
            timeout=15,
        )
        closure_probe = {
            "mode": "degraded",
            "http_status": closure_response.status_code,
            "error_code": api_error_code(
                closure_response, 503, "unavailable Docker Skill closure"
            ),
        }

    elapsed_seconds = round(time.perf_counter() - started, 3)
    result = {
        "schema_version": "1.0",
        "status": "completed",
        "started_at": started_at,
        "completed_at": utc_now(),
        "elapsed_seconds": elapsed_seconds,
        "base_url": base_url,
        "administrator_token_retained": False,
        "frontend": {
            "http_status": page.status_code,
            "bytes": len(page.content),
            "sha256": sha256_bytes(page.content),
            "markers_verified": ["Aegis Chain", 'id="root"'],
        },
        "health": health,
        "authentication": {
            "missing_token_status": missing_auth.status_code,
            "missing_token_error_code": missing_auth_code,
        },
        "static_chains": uploads,
        "scan_list_contains_all_jobs": True,
        "dynamic_chain": dynamic_job,
        "dynamic_list_contains_job": True,
        "docker_skill_closure": closure_probe,
        "safety": {
            "third_party_samples_executed": 0,
            "dynamic_fixture_trust": "self_built_hash_locked_only",
            "admin_token_sent_to": "loopback_only",
        },
    }
    result_path = output / "http_acceptance.json"
    result_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    write_artifact_manifest(output)
    return {
        "status": "completed",
        "static_chains": len(uploads),
        "dynamic_chains": 1,
        "exports": sum(len(item["exports"]) for item in uploads.values()),
        "elapsed_seconds": elapsed_seconds,
        "output": str(output),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the real HTTP release acceptance against a local Aegis server."
    )
    parser.add_argument(
        "--mode", choices=("full", "dependency-offline"), default="full"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--admin-token-env", default="AEGIS_ADMIN_TOKEN")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--request-timeout", type=float, default=180.0)
    parser.add_argument("--scan-timeout", type=float, default=240.0)
    parser.add_argument("--dynamic-timeout", type=float, default=180.0)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        summary = (
            run_offline_dependency_probe(args)
            if args.mode == "dependency-offline"
            else run(args)
        )
    except (AcceptanceError, OSError, requests.RequestException, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
