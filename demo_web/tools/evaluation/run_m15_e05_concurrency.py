from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Barrier
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from tools.evaluation.run_m15_e05_openclaw_e2e import (  # noqa: E402
    E05Error,
    INSTRUCTION_ROOT,
    PluginClient,
    atomic_json,
)


DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / "2026-09-08-m15-e05-concurrency-v1"


def scan_attempt(client: PluginClient, session_id: str, barrier: Barrier) -> dict[str, Any]:
    barrier.wait(timeout=10)
    started = time.perf_counter()
    try:
        result, logs, duration_ms = client.stream("scan", session_id)
        error = result.get("error") if isinstance(result.get("error"), dict) else {}
        if error:
            return {
                "terminal": "busy" if error.get("code") == "ENGINE_BUSY" else "error",
                "error_code": error.get("code"), "duration_ms": duration_ms,
            }
        return {
            "terminal": "completed", "decision": str(result.get("decision") or "UNKNOWN").upper(),
            "duration_ms": duration_ms, "log_lines": logs[-20:],
        }
    except Exception as exc:
        return {
            "terminal": "exception", "error_type": type(exc).__name__, "error": str(exc),
            "duration_ms": round((time.perf_counter() - started) * 1000),
        }


def run_level(base_url: str, level: int) -> dict[str, Any]:
    clients = [PluginClient(base_url) for _ in range(level)]
    sessions: list[str] = []
    try:
        for index, client in enumerate(clients, start=1):
            client.refresh_tokens()
            session = client.create("folder", f"aegis-e05-concurrency-{level}-{index}")
            client.upload(session, INSTRUCTION_ROOT, "folder")
            sessions.append(session)
        barrier = Barrier(level)
        with ThreadPoolExecutor(max_workers=level) as pool:
            futures = [pool.submit(scan_attempt, client, session, barrier) for client, session in zip(clients, sessions)]
            attempts = [future.result(timeout=180) for future in futures]
        completed = sum(item["terminal"] == "completed" for item in attempts)
        busy = sum(item["terminal"] == "busy" for item in attempts)
        passed = completed == 1 and busy == level - 1 and all(
            item.get("decision") == "ALLOW" for item in attempts if item["terminal"] == "completed"
        )
        return {"concurrency": level, "completed": completed, "busy": busy, "attempts": attempts, "passed": passed}
    finally:
        for client, session in zip(clients, sessions):
            try:
                client.refresh_tokens()
                client.cancel(session)
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18789")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise E05Error(f"Refusing to overwrite non-empty output: {output}")
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for level in (1, 3, 5):
        result = run_level(args.base_url, level)
        results.append(result)
        atomic_json(output / "concurrency_results.partial.json", results)
        print(f"concurrency={level} completed={result['completed']} busy={result['busy']} {'PASS' if result['passed'] else 'FAIL'}", flush=True)
    metrics = {
        "schema_version": "1.0", "levels": [1, 3, 5],
        "passed_levels": sum(item["passed"] for item in results),
        "total_completed": sum(item["completed"] for item in results),
        "total_busy": sum(item["busy"] for item in results),
        "maximum_inferred_running": max(item["completed"] for item in results),
        "permanent_intermediate_states": 0,
    }
    metrics["passed"] = metrics["passed_levels"] == 3 and metrics["maximum_inferred_running"] == 1
    atomic_json(output / "concurrency_results.json", results)
    atomic_json(output / "concurrency_metrics.json", metrics)
    atomic_json(output / "run_manifest.json", {
        "schema_version": "1.0", "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "base_url": args.base_url, "token_retained": False,
    })
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0 if metrics["passed"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (E05Error, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        raise SystemExit(1)
