from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.dynamic_audit.skill_sandbox_multiruntime import (  # noqa: E402
    CONFIG_PATH as SANDBOX_CONFIG_PATH,
    load_multiruntime_config,
    run_multiruntime_entrypoint,
)
from tools.datasets.prepare_m15_e04_robustness_pairs import tree_sha256  # noqa: E402


DATA_ROOT = REPRODUCTION_ROOT / "datasets" / "m15_e04_robustness_pairs_v2"
CONTRACT_PATH = DEMO_ROOT / "config" / "m15_e04_dynamic_robustness_v2.json"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / "2026-09-08-m15-e04-dynamic-robustness-v1"
NON_ALLOW = {"REVIEW", "BLOCK", "UNKNOWN"}


class ExperimentError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ExperimentError(f"Expected object: {path}")
    return payload


def load_records(data_root: Path = DATA_ROOT, contract_path: Path = CONTRACT_PATH) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    manifest = data_root / "manifest.jsonl"
    lock = load_json(data_root / "source_lock.json")
    contract = load_json(contract_path)
    if sha256_file(manifest) != lock.get("manifest_sha256"):
        raise ExperimentError("Dataset manifest drift")
    records = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines() if line]
    design = contract["design"]
    if len(records) != design["safe_controls"] + design["transformed_risks"]:
        raise ExperimentError("Dataset count differs from contract")
    if len({row["case_id"] for row in records}) != len(records):
        raise ExperimentError("Duplicate case ID")
    for row in records:
        root = (data_root / row["local_path"]).resolve(strict=True)
        root.relative_to((data_root / "cases").resolve(strict=True))
        if tree_sha256(root) != row["case_tree_sha256"]:
            raise ExperimentError(f"Case tree drift: {row['case_id']}")
        if sha256_file(root / row["entrypoint"]) != row["entrypoint_sha256"]:
            raise ExperimentError(f"Entrypoint drift: {row['case_id']}")
    return records, lock, contract


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def atomic_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def run_case(config: Any, row: dict[str, Any], output: Path, timeout_seconds: float, data_root: Path = DATA_ROOT) -> dict[str, Any]:
    root = (data_root / row["local_path"]).resolve(strict=True)
    before = tree_sha256(root)
    result = run_multiruntime_entrypoint(config, root, row["entrypoint"], row["runtime"], timeout_seconds)
    after = tree_sha256(root)
    atomic_json(output / "raw" / f"{row['case_id']}.json", result)
    evaluation = result.get("evaluation") or {}
    runner = result.get("runner") or {}
    rule_ids = sorted({str(item.get("rule_id") or "") for item in evaluation.get("findings") or []})
    rounds = [item.get("id") for item in runner.get("rounds") or [] if isinstance(item, dict)]
    expected = row.get("expected_rule_id")
    decision = str(evaluation.get("decision") or "UNKNOWN")
    return {
        "case_id": row["case_id"], "pair_id": row["pair_id"], "runtime": row["runtime"],
        "factor": row["factor"], "variant": row["variant"], "decision": decision,
        "rule_ids": rule_ids, "expected_rule_id": expected,
        "expected_rule_detected": expected in rule_ids if expected else None,
        "three_rounds": rounds == ["typical", "edge", "adversarial"],
        "round_ids": rounds, "event_count": len(runner.get("events") or []),
        "success": result.get("success") is True, "error": result.get("error"),
        "infrastructure_failure_non_allow": decision in NON_ALLOW if result.get("error") else None,
        "image_gates_all": bool(result.get("image_gates")) and all((result.get("image_gates") or {}).values()),
        "inspect_gates_all": bool(result.get("inspect_gates")) and all((result.get("inspect_gates") or {}).values()),
        "cleanup_verified": (result.get("cleanup") or {}).get("removed") is True and (result.get("cleanup") or {}).get("residual") is False,
        "input_hash_before": before, "input_hash_after": after, "input_unchanged": before == after == row["case_tree_sha256"],
        "internet_used_attestation": runner.get("internet_used"), "duration_ms": result.get("duration_ms"),
    }


def ratio(count: int, total: int) -> float:
    return count / total if total else 0.0


def percentile95(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((0.95 * len(ordered) + 0.999999)) - 1))
    return float(ordered[index])


def metrics(rows: list[dict[str, Any]], results: list[dict[str, Any]], contract: dict[str, Any]) -> dict[str, Any]:
    controls = [row for row in results if row["variant"] == "safe_control"]
    risks = [row for row in results if row["variant"] == "transformed_risk"]
    completed_risks = [row for row in risks if not row.get("error")]
    completed_controls = [row for row in controls if not row.get("error")]
    risk_non_allow = sum(row["decision"] in NON_ALLOW for row in completed_risks)
    expected = sum(row["expected_rule_detected"] is True for row in completed_risks)
    safe_non_allow = sum(row["decision"] in NON_ALLOW for row in completed_controls)
    per_runtime: dict[str, Any] = {}
    per_factor: dict[str, Any] = {}
    for key, destination in (("runtime", per_runtime), ("factor", per_factor)):
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in results:
            groups[str(row[key])].append(row)
        for name, group in sorted(groups.items()):
            group_risks = [row for row in group if row["variant"] == "transformed_risk" and not row.get("error")]
            group_controls = [row for row in group if row["variant"] == "safe_control" and not row.get("error")]
            destination[name] = {
                "risk_support": len(group_risks),
                "risk_non_allow": sum(row["decision"] in NON_ALLOW for row in group_risks),
                "expected_rule_detected": sum(row["expected_rule_detected"] is True for row in group_risks),
                "safe_control_non_allow": sum(row["decision"] in NON_ALLOW for row in group_controls),
            }
    all_security = [row["image_gates_all"] and row["inspect_gates_all"] for row in results]
    acceptance = contract["acceptance"]
    gates = {
        "all_cases_executed": len(completed_risks) == len(risks) and len(completed_controls) == len(controls),
        "transformed_non_allow_24_of_24": risk_non_allow == acceptance["transformed_non_allow"],
        "expected_rule_recall_at_least_90pct": ratio(expected, len(completed_risks)) >= acceptance["minimum_expected_rule_recall"] if completed_risks else False,
        "safe_control_false_positive_zero": safe_non_allow == acceptance["safe_control_non_allow"],
        "three_round_rate_100pct": all(row["three_rounds"] for row in results),
        "security_gate_rate_100pct": all(all_security),
        "cleanup_rate_100pct": all(row["cleanup_verified"] for row in results),
        "input_immutability_100pct": all(row["input_unchanged"] for row in results),
        "network_success_zero": all(row["internet_used_attestation"] is False for row in results),
        "infrastructure_failure_fail_closed": all(row["infrastructure_failure_non_allow"] is not False for row in results),
    }
    durations = [int(row["duration_ms"] or 0) for row in results]
    return {
        "schema_version": "1.0", "cases": len(results), "pairs": len({row["pair_id"] for row in rows}),
        "transformed_risk_non_allow": risk_non_allow, "transformed_risk_executed": len(completed_risks), "transformed_risk_total": len(risks),
        "transformed_risk_non_allow_rate": ratio(risk_non_allow, len(completed_risks)) if completed_risks else None,
        "expected_rule_detected": expected, "expected_rule_total": len(completed_risks),
        "expected_rule_recall": ratio(expected, len(completed_risks)) if completed_risks else None,
        "safe_control_non_allow": safe_non_allow, "safe_control_executed": len(completed_controls), "safe_control_total": len(controls),
        "safe_control_false_positive_rate": ratio(safe_non_allow, len(completed_controls)) if completed_controls else None,
        "infrastructure_failures": sum(bool(row.get("error")) for row in results),
        "per_runtime": per_runtime, "per_factor": per_factor,
        "duration_ms": {"median": statistics.median(durations), "p95": percentile95(durations), "max": max(durations, default=0)},
        "acceptance_gates": gates, "passed": all(gates.values()),
        "missed_transformed_cases": [row["case_id"] for row in completed_risks if row["decision"] not in NON_ALLOW or row["expected_rule_detected"] is not True],
        "safe_control_false_positives": [row["case_id"] for row in completed_controls if row["decision"] in NON_ALLOW],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=float, default=9)
    parser.add_argument("--data-root", type=Path, default=DATA_ROOT)
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    data_root = args.data_root.resolve()
    contract_path = args.contract.resolve()
    records, lock, contract = load_records(data_root, contract_path)
    config = load_multiruntime_config(SANDBOX_CONFIG_PATH)
    started = time.perf_counter()
    completed: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 4))) as pool:
        futures = {pool.submit(run_case, config, row, output, args.timeout_seconds, data_root): row for row in records}
        for future in as_completed(futures):
            result = future.result()
            completed.append(result)
            print(f"[{len(completed):02d}/{len(records)}] {result['case_id']} -> {result['decision']}", flush=True)
    order = {row["case_id"]: index for index, row in enumerate(records)}
    completed.sort(key=lambda row: order[row["case_id"]])
    calculated = metrics(records, completed, contract)
    atomic_jsonl(output / "results.jsonl", completed)
    atomic_json(output / "metrics.json", calculated)
    atomic_json(output / "run_manifest.json", {
        "schema_version": "1.0", "run_id": output.name,
        "started_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
        "dataset_lock": lock, "contract_sha256": sha256_file(contract_path),
        "sandbox_config_sha256": sha256_file(SANDBOX_CONFIG_PATH), "workers": args.workers,
        "timeout_seconds_per_case": args.timeout_seconds,
    })
    if not calculated["passed"]:
        atomic_json(output / "FAILURE_RECEIPT.json", {
            "schema_version": "1.0", "run_id": output.name, "status": "invalid_for_positive_detection_claims",
            "failed_gates": [name for name, passed in calculated["acceptance_gates"].items() if not passed],
            "infrastructure_failures": calculated["infrastructure_failures"],
            "failure_codes": sorted({str((row.get("error") or {}).get("code")) for row in completed if row.get("error")}),
            "preservation_reason": "E04 requires real isolated executions. Fail-closed outcomes caused by missing infrastructure are not counted as detections or safe-control false positives.",
        })
    print(json.dumps(calculated, ensure_ascii=False, indent=2))
    return 0 if calculated["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
