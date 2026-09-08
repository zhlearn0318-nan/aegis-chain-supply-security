from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import shutil
import statistics
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

import requests


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
CONTRACT_PATH = DEMO_ROOT / "config" / "m15_e05_openclaw_e2e_v2.json"
E04_ROOT = REPRODUCTION_ROOT / "datasets" / "m15_e04_robustness_pairs_v2"
INSTRUCTION_ROOT = REPRODUCTION_ROOT / "fixtures" / "skills" / "benign_doc_summary"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / "2026-09-08-m15-e05-openclaw-e2e-v2-attempt2"
TOKEN = re.compile(r'(?:token|TOKEN)="([0-9a-f]{64})"')
NON_ALLOW = {"REVIEW", "WARN", "BLOCK", "UNKNOWN"}
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.openclaw_install_policy import hash_source_tree  # noqa: E402


class E05Error(RuntimeError):
    pass


SCENARIOS = (
    {"id": "s01", "runtime": "instruction", "source": "instruction", "source_kind": "zip", "expected": "ALLOW", "install": True},
    {"id": "s02", "runtime": "instruction", "source": "instruction", "source_kind": "folder", "expected": "ALLOW", "install": True},
    {"id": "s03", "runtime": "python", "source": "python-01-encoded_command-safe_control", "source_kind": "zip", "expected": "ALLOW", "install": True},
    {"id": "s04", "runtime": "node", "source": "node-01-encoded_command-safe_control", "source_kind": "folder", "expected": "ALLOW", "install": True},
    {"id": "s05", "runtime": "shell", "source": "shell-01-encoded_command-safe_control", "source_kind": "zip", "expected": "ALLOW", "install": True},
    {"id": "s06", "runtime": "python", "source": "python-08-timeout_fail_closed-transformed_risk", "source_kind": "zip", "expected": "WARN", "install": False},
    {"id": "s07", "runtime": "node", "source": "node-08-timeout_fail_closed-transformed_risk", "source_kind": "folder", "expected": "WARN", "install": False},
    {"id": "s08", "runtime": "shell", "source": "shell-08-timeout_fail_closed-transformed_risk", "source_kind": "zip", "expected": "WARN", "install": False},
    {"id": "s09", "runtime": "python", "source": "python-02-split_sensitive_path-transformed_risk", "source_kind": "folder", "expected": "BLOCK", "install": False},
    {"id": "s10", "runtime": "node", "source": "node-07-staged_read_network-transformed_risk", "source_kind": "zip", "expected": "BLOCK", "install": False},
    {"id": "s11", "runtime": "shell", "source": "shell-01-encoded_command-transformed_risk", "source_kind": "folder", "expected": "BLOCK", "install": False},
    {"id": "s12", "runtime": "python", "source": "python-01-encoded_command-safe_control", "update_source": "python-01-encoded_command-safe_control", "derived_update_marker": "E05 confirmed-update revision 2", "source_kind": "zip", "expected": "ALLOW", "install": True, "update": True},
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_hash(root: Path) -> str:
    return hash_source_tree(root)


def source_root(name: str) -> Path:
    if name == "instruction":
        return INSTRUCTION_ROOT.resolve(strict=True)
    return (E04_ROOT / "cases" / name).resolve(strict=True)


def deterministic_zip(root: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            info = zipfile.ZipInfo(path.relative_to(root).as_posix(), (2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    return buffer.getvalue()


def require_json(response: requests.Response, status: int) -> dict[str, Any]:
    if response.status_code != status:
        raise E05Error(f"HTTP {response.status_code}, expected {status}: {response.text[:500]}")
    payload = response.json()
    if not isinstance(payload, dict):
        raise E05Error("Response is not a JSON object")
    return payload


class PluginClient:
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")
        self.http = requests.Session()
        self.http.trust_env = False
        self.token = self._page_token("/plugins/aegis-admission/panel?embed=1")
        self.admin_token = self._page_token("/plugins/aegis-security-center/panel?tab=reports")

    def refresh_tokens(self) -> None:
        """Start an independent UI-equivalent operation with fresh short-lived tokens."""
        self.token = self._page_token("/plugins/aegis-admission/panel?embed=1")
        self.admin_token = self._page_token("/plugins/aegis-security-center/panel?tab=reports")

    def _page_token(self, path: str) -> str:
        response = self.http.get(self.base + path, timeout=15)
        if response.status_code != 200:
            raise E05Error(f"Plugin page unavailable: {response.status_code}")
        match = TOKEN.search(response.text)
        if not match:
            raise E05Error("Plugin page token missing")
        return match.group(1)

    def action_json(self, action: str, body: dict[str, Any], expected_status: int = 200) -> dict[str, Any]:
        response = self.http.post(
            self.base + "/plugins/aegis-admission/api/run",
            headers={"X-Aegis-Action": action, "X-Aegis-Token": self.token, "Content-Type": "application/json"},
            data=json.dumps(body), timeout=35,
        )
        return require_json(response, expected_status)

    def create(self, source_kind: str, target_name: str) -> str:
        payload = self.action_json("create", {"source_kind": source_kind, "target_name": target_name, "display_name": target_name}, 201)
        return str(payload["data"]["session_id"])

    def upload(self, session_id: str, root: Path, source_kind: str) -> tuple[int, int]:
        started = time.perf_counter()
        uploaded = 0
        if source_kind == "zip":
            items = [(None, deterministic_zip(root))]
        else:
            items = [(path.relative_to(root).as_posix(), path.read_bytes()) for path in sorted(root.rglob("*")) if path.is_file()]
        for relative, content in items:
            headers = {"X-Aegis-Action": "upload", "X-Aegis-Token": self.token, "X-Aegis-Session": session_id, "Content-Type": "application/octet-stream"}
            if relative is not None:
                headers["X-Aegis-Relative-Path"] = base64.urlsafe_b64encode(relative.encode()).decode().rstrip("=")
            response = self.http.post(self.base + "/plugins/aegis-admission/api/run", headers=headers, data=content, timeout=60)
            require_json(response, 200)
            uploaded += len(content)
        return uploaded, round((time.perf_counter() - started) * 1000)

    def stream(self, action: str, session_id: str, **body: Any) -> tuple[dict[str, Any], list[str], int]:
        started = time.perf_counter()
        response = self.http.post(
            self.base + "/plugins/aegis-admission/api/run",
            headers={"X-Aegis-Action": action, "X-Aegis-Token": self.token, "Content-Type": "application/json"},
            data=json.dumps({"session_id": session_id, **body}), stream=True, timeout=(15, 180),
        )
        if "application/json" in response.headers.get("content-type", ""):
            payload = require_json(response, response.status_code)
            return payload.get("data") or payload, [], round((time.perf_counter() - started) * 1000)
        if response.status_code != 200:
            raise E05Error(f"{action} HTTP {response.status_code}: {response.text[:500]}")
        result: dict[str, Any] | None = None
        logs: list[str] = []
        for raw in response.iter_lines(decode_unicode=True):
            if not raw:
                continue
            event = json.loads(raw)
            if event.get("type") in {"log", "heartbeat"}:
                logs.append(str(event.get("line") or "")[:1000])
            elif event.get("type") == "error":
                raise E05Error(str((event.get("error") or {}).get("message") or "stream error"))
            elif event.get("type") == "result":
                result = event.get("result")
        if not isinstance(result, dict):
            raise E05Error(f"{action} stream has no result")
        return result, logs, round((time.perf_counter() - started) * 1000)

    def rejected_install(self, session_id: str) -> str:
        response = self.http.post(
            self.base + "/plugins/aegis-admission/api/run",
            headers={"X-Aegis-Action": "install", "X-Aegis-Token": self.token, "Content-Type": "application/json"},
            data=json.dumps({"session_id": session_id}), timeout=30,
        )
        payload = require_json(response, 409)
        return str((payload.get("error") or {}).get("code") or "")

    def admin(self, operation: str, **payload: Any) -> dict[str, Any]:
        response = self.http.post(
            self.base + "/plugins/aegis-admin/api",
            headers={"X-Aegis-Demo-Token": self.admin_token, "Content-Type": "application/json"},
            data=json.dumps({"operation": operation, **payload}), timeout=40,
        )
        body = require_json(response, 200)
        if body.get("ok") is not True:
            raise E05Error(f"Admin operation failed: {body}")
        return body.get("data") or {}

    def pdf(self, sequence: int) -> tuple[bytes, int]:
        started = time.perf_counter()
        response = self.http.post(
            self.base + "/plugins/aegis-admin/report.pdf",
            headers={"X-Aegis-Demo-Token": self.admin_token, "Content-Type": "application/json"},
            data=json.dumps({"sequence": sequence}), timeout=60,
        )
        if response.status_code != 200 or not response.content.startswith(b"%PDF"):
            raise E05Error(f"PDF export failed: {response.status_code}")
        return response.content, round((time.perf_counter() - started) * 1000)

    def cancel(self, session_id: str) -> None:
        self.action_json("cancel", {"session_id": session_id})


def verify_sources(contract: dict[str, Any]) -> None:
    if sha256_file(E04_ROOT / "manifest.jsonl") != contract["source_locks"]["e04_manifest_sha256"]:
        raise E05Error("E04 source manifest drift")
    if tree_hash(INSTRUCTION_ROOT) != contract["source_locks"]["instruction_fixture_tree_sha256"]:
        raise E05Error("Instruction fixture drift")


def expected_matches(observed: str, expected: str) -> bool:
    return observed == expected


def safe_remove_install(path_text: str, target_name: str) -> bool:
    path = Path(path_text).resolve(strict=True)
    if path.name != target_name or not target_name.startswith("aegis-e05-") or path.parent.name.casefold() != "skills":
        raise E05Error(f"Refusing to clean unexpected install path: {path}")
    if path.is_symlink():
        path.unlink()
    else:
        shutil.rmtree(path)
    return not path.exists()


def prepare_derived_update_source(base: Path, output: Path, label: str, marker: str) -> Path:
    """Create an evidence-retained, content-distinct benign update package."""
    destination = output / "input_snapshots" / label
    if destination.exists():
        raise E05Error(f"Refusing to replace derived update input: {destination}")
    shutil.copytree(base, destination)
    (destination / "AEGIS_E05_UPDATE.txt").write_text(marker + "\n", encoding="utf-8", newline="\n")
    return destination


def audit_pdf_check(client: PluginClient, scan: dict[str, Any], output: Path, label: str) -> dict[str, Any]:
    audit = scan.get("audit") or {}
    sequence = audit.get("sequence")
    if not isinstance(sequence, int):
        raise E05Error("Scan result has no audit sequence")
    detail = client.admin("get_audit", sequence=sequence)
    current = detail.get("audit") or {}
    integrity = detail.get("integrity") or {}
    if str(current.get("decision") or "").upper() != str(scan.get("decision") or "").upper() or integrity.get("valid") is not True:
        raise E05Error("Scan/API audit decision mismatch")
    pdf, duration = client.pdf(sequence)
    pdf_path = output / "pdf" / f"{label}-{sequence}.pdf"
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    pdf_path.write_bytes(pdf)
    return {"sequence": sequence, "decision": str(current.get("decision") or "").upper(), "integrity_valid": True, "pdf_bytes": len(pdf), "pdf_sha256": hashlib.sha256(pdf).hexdigest(), "pdf_duration_ms": duration}


def execute_one(client: PluginClient, scenario: dict[str, Any], repetition: int, output: Path) -> dict[str, Any]:
    client.refresh_tokens()
    target = f"aegis-e05-r{repetition}-{scenario['id']}"
    started = time.perf_counter()
    sessions: list[str] = []
    installed_paths: list[str] = []
    try:
        root = source_root(scenario["source"])
        session = client.create(scenario["source_kind"], target)
        sessions.append(session)
        uploaded, upload_ms = client.upload(session, root, scenario["source_kind"])
        scan, logs, scan_ms = client.stream("scan", session)
        observed = str(scan.get("decision") or "UNKNOWN").upper()
        install_verified = False
        installation_performed = False
        update_verified = None
        install_ms = 0
        if scenario.get("install"):
            installed, install_logs, install_ms = client.stream("install", session)
            logs.extend(install_logs)
            if installed.get("requires_confirmation"):
                raise E05Error("Unexpected pre-existing E05 install target")
            if installed.get("installed") is not True:
                raise E05Error("ALLOW scenario was not installed")
            installed_paths.append(str(installed["install_path"]))
            install_verified = True
            installation_performed = True
        else:
            install_verified = client.rejected_install(session) == "INSTALL_NOT_ELIGIBLE"

        if scenario.get("update"):
            update_root = prepare_derived_update_source(
                source_root(scenario["update_source"]), output,
                f"r{repetition}-{scenario['id']}", str(scenario["derived_update_marker"]),
            )
            second = client.create(scenario["source_kind"], target)
            sessions.append(second)
            client.upload(second, update_root, scenario["source_kind"])
            update_scan, update_logs, update_scan_ms = client.stream("scan", second)
            logs.extend(update_logs)
            if str(update_scan.get("decision") or "").upper() != "ALLOW" or update_scan.get("install_eligible") is not True:
                raise E05Error(
                    "Derived update did not receive ALLOW eligibility: "
                    f"decision={update_scan.get('decision')!r}, "
                    f"rules={sorted({str(item.get('rule_id') or '') for item in update_scan.get('findings') or []})!r}"
                )
            if update_scan.get("source_tree_sha256") == scan.get("source_tree_sha256"):
                raise E05Error("Derived update package did not change the source tree hash")
            confirmation, _, confirmation_ms = client.stream("install", second)
            if confirmation.get("requires_confirmation") is not True or confirmation.get("installed") is not False:
                raise E05Error(f"Update did not require explicit confirmation: {confirmation!r}")
            updated, update_install_logs, update_install_ms = client.stream("install", second, overwrite_confirmed=True)
            logs.extend(update_install_logs)
            if updated.get("installed") is not True or updated.get("updated") is not True:
                raise E05Error("Confirmed update did not complete transactionally")
            scan = update_scan
            observed = str(scan.get("decision") or "UNKNOWN").upper()
            scan_ms += update_scan_ms
            install_ms += confirmation_ms + update_install_ms
            update_verified = True

        audit = audit_pdf_check(client, scan, output, f"r{repetition}-{scenario['id']}")
        total_ms = round((time.perf_counter() - started) * 1000)
        passed = expected_matches(observed, scenario["expected"]) and install_verified and update_verified is not False and total_ms <= 120_000
        return {
            "repetition": repetition, "scenario_id": scenario["id"], "runtime": scenario["runtime"],
            "source_kind": scenario["source_kind"], "expected_decision": scenario["expected"], "observed_decision": observed,
            "target_name": target, "uploaded_bytes": uploaded, "upload_ms": upload_ms, "scan_ms": scan_ms,
            "install_ms": install_ms, "pdf_ms": audit["pdf_duration_ms"], "total_ms": total_ms,
            "install_gate_verified": install_verified, "installation_performed": installation_performed,
            "update_verified": update_verified,
            "audit": audit, "source_tree_sha256": scan.get("source_tree_sha256"),
            "finding_rule_ids": sorted({str(item.get("rule_id") or item.get("ruleId") or "") for item in scan.get("findings") or []} - {""}),
            "log_lines": logs[-120:], "passed": passed,
        }
    finally:
        for session_id in sessions:
            try:
                client.cancel(session_id)
            except Exception:
                pass
        for installed_path in dict.fromkeys(installed_paths):
            if Path(installed_path).exists():
                safe_remove_install(installed_path, target)


def percentile(values: list[int], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return float(ordered[min(len(ordered) - 1, max(0, int(len(ordered) * fraction + .999999) - 1))])


def atomic_json(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18789")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--scenario", action="append", choices=[item["id"] for item in SCENARIOS])
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise E05Error(f"Refusing to overwrite non-empty output: {output}")
    output.mkdir(parents=True, exist_ok=True)
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    verify_sources(contract)
    client = PluginClient(args.base_url)
    rows: list[dict[str, Any]] = []
    started = time.perf_counter()
    selected = [item for item in SCENARIOS if not args.scenario or item["id"] in set(args.scenario)]
    for repetition in range(1, args.repetitions + 1):
        for scenario in selected:
            try:
                row = execute_one(client, scenario, repetition, output)
            except Exception as exc:
                atomic_json(output / "normal_results.partial.json", rows)
                atomic_json(output / "failure_receipt.json", {
                    "schema_version": "1.0", "status": "failed", "completed_runs": len(rows),
                    "failed_repetition": repetition, "failed_scenario": scenario["id"],
                    "error_type": type(exc).__name__, "error": str(exc),
                    "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                })
                raise
            rows.append(row)
            atomic_json(output / "normal_results.partial.json", rows)
            print(f"[{len(rows):02d}/{len(selected)*args.repetitions}] r{repetition}-{scenario['id']} {row['observed_decision']} {'PASS' if row['passed'] else 'FAIL'} {row['total_ms']}ms", flush=True)
    durations = [int(row["total_ms"]) for row in rows]
    standard_durations = [
        int(row["total_ms"]) for row in rows
        if row["scenario_id"] not in {"s06", "s07", "s08", "s12"}
    ]
    metrics = {
        "schema_version": "1.0", "runs": len(rows), "passed_runs": sum(row["passed"] for row in rows),
        "decision_matches": sum(row["observed_decision"] == row["expected_decision"] for row in rows),
        "non_allow_installations": sum(row["observed_decision"] in NON_ALLOW and row["installation_performed"] for row in rows),
        "non_allow_gate_failures": sum(row["observed_decision"] in NON_ALLOW and not row["install_gate_verified"] for row in rows),
        "audit_api_pdf_consistent": sum(row["audit"]["decision"] == row["observed_decision"] and row["audit"]["integrity_valid"] for row in rows),
        "timing_ms": {"median": statistics.median(durations), "p95": percentile(durations, .95), "max": max(durations)},
        "standard_timing_ms": {"median": statistics.median(standard_durations), "p95": percentile(standard_durations, .95), "max": max(standard_durations)},
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
    }
    metrics["normal_matrix_passed"] = (
        metrics["runs"] == 36 and metrics["passed_runs"] == 36 and metrics["decision_matches"] == 36
        and metrics["non_allow_installations"] == 0 and metrics["non_allow_gate_failures"] == 0
        and metrics["audit_api_pdf_consistent"] == 36
        and metrics["standard_timing_ms"]["p95"] < 60_000 and metrics["timing_ms"]["max"] <= 120_000
    )
    atomic_json(output / "normal_results.json", rows)
    atomic_json(output / "normal_metrics.json", metrics)
    atomic_json(output / "run_manifest.json", {
        "schema_version": "1.0", "started_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "contract_sha256": sha256_file(CONTRACT_PATH), "e04_manifest_sha256": sha256_file(E04_ROOT / "manifest.jsonl"),
        "instruction_tree_sha256": tree_hash(INSTRUCTION_ROOT), "base_url": args.base_url,
        "token_retained": False, "scenario_count": len(selected), "selected_scenarios": [item["id"] for item in selected], "repetitions": args.repetitions,
    })
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0 if metrics["normal_matrix_passed"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (E05Error, OSError, requests.RequestException, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        raise SystemExit(1)
