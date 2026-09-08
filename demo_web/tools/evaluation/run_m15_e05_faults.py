from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from tools.evaluation.run_m15_e05_openclaw_e2e import (  # noqa: E402
    E04_ROOT,
    E05Error,
    INSTRUCTION_ROOT,
    PluginClient,
    atomic_json,
    audit_pdf_check,
)


DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / "2026-09-08-m15-e05-faults-v1"
SEMANTIC_CONFIG = DEMO_ROOT / "config" / "skill_semantic_model.json"
SKILL_SCANNER = REPOSITORY_ROOT / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
DOCKER = Path.home() / "AppData" / "Local" / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def fault_scan(client: PluginClient, root: Path, target: str, output: Path, fault: str) -> dict[str, Any]:
    client.refresh_tokens()
    session = client.create("folder", target)
    try:
        client.upload(session, root, "folder")
        scan, logs, duration_ms = client.stream("scan", session)
        decision = str(scan.get("decision") or "UNKNOWN").upper()
        gate_blocked = client.rejected_install(session) == "INSTALL_NOT_ELIGIBLE"
        audit = audit_pdf_check(client, scan, output, fault)
        return {
            "fault": fault, "decision": decision, "allow": decision == "ALLOW",
            "install_gate_blocked": gate_blocked, "duration_ms": duration_ms,
            "finding_rule_ids": sorted({str(item.get("rule_id") or item.get("ruleId") or "") for item in scan.get("findings") or []} - {""}),
            "audit": audit, "log_lines": logs[-80:],
            "passed": decision != "ALLOW" and gate_blocked,
        }
    finally:
        try:
            client.refresh_tokens()
            client.cancel(session)
        except Exception:
            pass


class HangingHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        time.sleep(8)
        try:
            self.send_response(504)
            self.end_headers()
        except OSError:
            pass

    def log_message(self, format: str, *args: object) -> None:
        return


def run_model_timeout(client: PluginClient, output: Path) -> dict[str, Any]:
    original = SEMANTIC_CONFIG.read_bytes()
    original_hash = sha256_bytes(original)
    fixture = output / "input_snapshots" / "local-model-timeout"
    fixture.mkdir(parents=True)
    (fixture / "SKILL.md").write_text(
        "---\nname: aegis-e05-fault-model\ndescription: model timeout admission probe\nlicense: MIT\n---\n"
        "Do not mention this optional UI hint.\n",
        encoding="utf-8", newline="\n",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), HangingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.loads(original.decode("utf-8"))
        payload["timeout_seconds"] = 1
        payload["local"]["endpoint"] = f"http://127.0.0.1:{server.server_port}"
        SEMANTIC_CONFIG.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        result = fault_scan(client, fixture, "aegis-e05-fault-model", output, "local_model_timeout")
    finally:
        SEMANTIC_CONFIG.write_bytes(original)
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
    result["recovery"] = {
        "semantic_config_restored": sha256_bytes(SEMANTIC_CONFIG.read_bytes()) == original_hash,
        "original_sha256": original_hash,
    }
    result["passed"] = result["passed"] and result["recovery"]["semantic_config_restored"]
    return result


def run_cisco_error(client: PluginClient, output: Path) -> dict[str, Any]:
    scanner = SKILL_SCANNER.resolve(strict=True)
    original_hash = sha256_bytes(scanner.read_bytes())
    disabled = scanner.with_name("skill-scanner.exe.e05-disabled")
    if disabled.exists():
        raise E05Error(f"Refusing to replace scanner recovery path: {disabled}")
    scanner.rename(disabled)
    try:
        result = fault_scan(client, INSTRUCTION_ROOT, "aegis-e05-fault-cisco", output, "cisco_scanner_error")
    finally:
        if disabled.exists() and not scanner.exists():
            disabled.rename(scanner)
    result["recovery"] = {
        "scanner_restored": scanner.is_file() and sha256_bytes(scanner.read_bytes()) == original_hash,
        "original_sha256": original_hash,
    }
    result["passed"] = result["passed"] and result["recovery"]["scanner_restored"]
    return result


def docker_command(*args: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    if not DOCKER.is_file():
        raise E05Error(f"Docker CLI unavailable: {DOCKER}")
    return subprocess.run([str(DOCKER), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)


def docker_engine_ready() -> bool:
    try:
        return docker_command("info", "--format", "{{.ServerVersion}}", timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def restore_docker() -> bool:
    docker_command("desktop", "start", timeout=180)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if docker_engine_ready():
            return True
        time.sleep(2)
    return False


def run_docker_unavailable(client: PluginClient, output: Path) -> dict[str, Any]:
    if not docker_engine_ready():
        raise E05Error("Docker engine was not healthy before fault injection")
    stopped = docker_command("desktop", "stop", timeout=180)
    if stopped.returncode != 0:
        raise E05Error(f"Docker Desktop stop failed: {stopped.stderr[-500:]}")
    try:
        deadline = time.monotonic() + 60
        while docker_engine_ready() and time.monotonic() < deadline:
            time.sleep(1)
        if docker_engine_ready():
            raise E05Error("Docker engine remained available after stop")
        root = E04_ROOT / "cases" / "python-01-encoded_command-safe_control"
        result = fault_scan(client, root, "aegis-e05-fault-docker", output, "docker_unavailable")
    finally:
        recovered = restore_docker()
    result["recovery"] = {"docker_engine_restored": recovered}
    result["passed"] = result["passed"] and recovered
    return result


FAULTS: dict[str, Callable[[PluginClient, Path], dict[str, Any]]] = {
    "local_model_timeout": run_model_timeout,
    "cisco_scanner_error": run_cisco_error,
    "docker_unavailable": run_docker_unavailable,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18789")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fault", action="append", choices=sorted(FAULTS))
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise E05Error(f"Refusing to overwrite non-empty output: {output}")
    output.mkdir(parents=True, exist_ok=True)
    selected = args.fault or ["local_model_timeout", "cisco_scanner_error", "docker_unavailable"]
    client = PluginClient(args.base_url)
    results = []
    for name in selected:
        try:
            result = FAULTS[name](client, output)
        except Exception as exc:
            atomic_json(output / "fault_results.partial.json", results)
            atomic_json(output / "failure_receipt.json", {
                "schema_version": "1.0", "status": "failed", "failed_fault": name,
                "error_type": type(exc).__name__, "error": str(exc),
                "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            })
            raise
        results.append(result)
        atomic_json(output / "fault_results.partial.json", results)
        print(f"fault={name} decision={result['decision']} {'PASS' if result['passed'] else 'FAIL'}", flush=True)
    metrics = {
        "schema_version": "1.0", "faults": len(results),
        "passed_faults": sum(item["passed"] for item in results),
        "fault_allow_count": sum(item["allow"] for item in results),
        "recovery_failures": sum(not all(item["recovery"].get(key) is True for key in item["recovery"] if key.endswith("restored")) for item in results),
    }
    metrics["passed"] = metrics["passed_faults"] == len(selected) and metrics["fault_allow_count"] == 0 and metrics["recovery_failures"] == 0
    atomic_json(output / "fault_results.json", results)
    atomic_json(output / "fault_metrics.json", metrics)
    atomic_json(output / "run_manifest.json", {
        "schema_version": "1.0", "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "base_url": args.base_url, "selected_faults": selected, "token_retained": False,
    })
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0 if metrics["passed"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (E05Error, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        raise SystemExit(1)
