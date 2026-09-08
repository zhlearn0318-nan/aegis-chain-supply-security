from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.adapters import ProcessRunner, SkillScannerAdapter  # noqa: E402
from backend.policy import DEFAULT_POLICY_PATH, evaluate_findings, load_policy, summarize  # noqa: E402
from backend.skill_static_pipeline import run_skill_static_pipeline  # noqa: E402
from tools.datasets.prepare_m15_e02_real_skill_corpus import (  # noqa: E402
    DEFAULT_OUTPUT as DEFAULT_DATA_ROOT,
    sha256_file,
    tree_sha256,
    verify_scan_inputs,
)


RUN_ID = "2026-09-06-m15-e02-static-false-positive-v3"
DEFAULT_RUN_ROOT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
ALLOWED_ANALYZERS = {
    "static_analyzer", "bytecode", "pipeline", "aegis-static-v1",
    "aegis-sensitive-flow-v1", "aegis-untrusted-exec-flow-v1", "aegis-enterprise-controls-v1",
    "aegis-static-coverage-v1", "aegis-network-context-v1", "aegis-filesystem-context-v1",
    "aegis-command-context-v1", "aegis-custom-rules-v1", "aegis-skill-semantic-v1",
    "aegis-skill-capability-alignment-v1",
}
EXTERNAL_TOKENS = {"llm", "behavioral", "virustotal", "aidefense"}


class ExperimentError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ExperimentError(f"Expected JSON object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def validate_analyzers(analyzers: list[str]) -> None:
    normalized = {str(value).lower() for value in analyzers}
    if not normalized or not {"static_analyzer", "aegis-static-v1"} <= normalized:
        raise ExperimentError(f"Required analyzers missing: {sorted(normalized)}")
    if not normalized <= ALLOWED_ANALYZERS:
        raise ExperimentError(f"Unexpected analyzer crossed E02 boundary: {sorted(normalized - ALLOWED_ANALYZERS)}")
    if any(token in analyzer for analyzer in normalized for token in EXTERNAL_TOKENS):
        raise ExperimentError(f"External/dynamic analyzer crossed E02 boundary: {sorted(normalized)}")


def public_finding(finding: dict[str, Any]) -> dict[str, Any]:
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    return {
        "id": finding.get("id"),
        "rule_id": finding.get("rule_id"),
        "title": finding.get("title"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "analyzer": finding.get("analyzer"),
        "location": {key: location.get(key) for key in ("file", "line", "object", "type") if location.get(key) is not None},
        "evidence": finding.get("evidence"),
        "description": finding.get("description"),
        "remediation": finding.get("remediation"),
        "evidence_confidence": finding.get("evidence_confidence"),
        "reachability": finding.get("reachability"),
        "behavior_alignment": finding.get("behavior_alignment"),
        "evidence_source": finding.get("evidence_source"),
    }


def scan_case(
    adapter: SkillScannerAdapter,
    policy: Any,
    data_root: Path,
    record: dict[str, Any],
) -> dict[str, Any]:
    case_root = (data_root / str(record["local_path"])).resolve()
    expected_hash = str(record["case_tree_sha256"])
    before_hash = tree_sha256(case_root)
    if before_hash != expected_hash:
        raise ExperimentError(f"Case hash drift before scan: {record['case_id']}")
    started = time.perf_counter()
    try:
        pipeline = run_skill_static_pipeline(case_root, adapter)
        findings = pipeline["findings"]
        analyzers = pipeline["analyzers"]
        validate_analyzers(analyzers)
        evaluation = evaluate_findings(findings, policy)
        result = {
            "status": "completed",
            "decision": evaluation.decision.value,
            "policy_trace": evaluation.trace.model_dump(mode="json"),
            "summary": summarize(findings),
            "findings": [public_finding(item) for item in findings],
            "analyzers": analyzers,
            "vendor_scans": int(pipeline.get("vendor_scans", 0)),
            "error": None,
        }
    except Exception as exc:
        result = {
            "status": "failed",
            "decision": "UNKNOWN",
            "policy_trace": {
                "policy_id": policy.policy_id,
                "policy_version": policy.version,
                "rule_id": "CASE_SCAN_FAILED",
                "reason": "Static pipeline failed; fail-closed UNKNOWN.",
                "matched_severities": [],
                "matched_finding_ids": [],
                "fail_closed": True,
            },
            "summary": {},
            "findings": [],
            "analyzers": [],
            "vendor_scans": 0,
            "error": {"type": type(exc).__name__, "raw_message_retained": False},
        }
    after_hash = tree_sha256(case_root)
    if after_hash != before_hash:
        raise ExperimentError(f"Case changed during scan: {record['case_id']}")
    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "system": "F0",
        "case_id": record["case_id"],
        "source_kind": record["source_kind"],
        "case_tree_sha256_before": before_hash,
        "case_tree_sha256_after": after_hash,
        "duration_ms": max(1, round((time.perf_counter() - started) * 1000)),
        **result,
    }


def run_scan(data_root: Path, run_root: Path, workers: int, timeout_seconds: int) -> dict[str, Any]:
    if not 1 <= workers <= 8:
        raise ExperimentError("workers must be between 1 and 8")
    if run_root.exists() and any(run_root.iterdir()):
        raise ExperimentError(f"Output directory is not empty: {run_root}")
    verification = verify_scan_inputs(data_root)
    records = load_jsonl(data_root / "scan_manifest.jsonl")
    if len(records) != 40:
        raise ExperimentError("E02 scan requires exactly 40 frozen cases")
    scanner = REPOSITORY_ROOT / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
    if not scanner.is_file():
        raise ExperimentError(f"Cisco Skill Scanner unavailable: {scanner}")
    runner = ProcessRunner(
        timeout_seconds=timeout_seconds,
        cache_root=DEMO_ROOT / "data" / "cache" / "m15_e02_real_skill_v1",
        extra_path=scanner.parent,
    )
    version_call = runner.run([str(scanner), "--version"])
    if version_call.returncode != 0:
        raise ExperimentError("Cisco Skill Scanner version probe failed")
    adapter = SkillScannerAdapter(scanner=scanner, runner=runner)
    policy = load_policy()
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "running",
        "started_at": now_iso(),
        "system": "F0",
        "dataset": {
            "id": "third-party-skill-e02-v1",
            "case_count": 40,
            "scan_manifest_sha256": sha256_file(data_root / "scan_manifest.jsonl"),
            "scan_input_tree_sha256": verification["scan_input_tree_sha256"],
        },
        "scanner": {
            "version": (version_call.stdout or version_call.stderr).strip().splitlines()[0],
            "executable_sha256": sha256_file(scanner),
            "workers": workers,
            "timeout_seconds_per_case": timeout_seconds,
        },
        "policy": {"id": policy.policy_id, "version": policy.version, "sha256": sha256_file(DEFAULT_POLICY_PATH)},
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "sample_execution": False,
            "sample_install": False,
            "ground_truth_opened": False,
            "external_model_enabled": False,
        },
    }
    run_root.mkdir(parents=True, exist_ok=True)
    write_json(run_root / "run_manifest.json", manifest)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="m15-e02-f0") as executor:
        results = list(executor.map(lambda row: scan_case(adapter, policy, data_root, row), records))
    after = verify_scan_inputs(data_root)
    if after["scan_input_tree_sha256"] != verification["scan_input_tree_sha256"]:
        raise ExperimentError("E02 scan input changed during F0 scan")
    write_jsonl(run_root / "f0_results.jsonl", results)
    rule_counts = Counter(
        finding.get("rule_id") or "<missing>"
        for row in results
        for finding in row["findings"]
        if finding.get("severity") in {"MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    )
    write_json(run_root / "f0_hotspots_label_blind.json", dict(sorted(rule_counts.items(), key=lambda item: (-item[1], item[0]))))
    manifest["status"] = "scan_complete_labels_unopened"
    manifest["completed_at"] = now_iso()
    manifest["wall_seconds"] = round(time.perf_counter() - started, 3)
    manifest["decision_counts"] = dict(sorted(Counter(row["decision"] for row in results).items()))
    manifest["failed_cases"] = sum(row["status"] != "completed" for row in results)
    manifest["scan_input_tree_sha256_after"] = after["scan_input_tree_sha256"]
    manifest["outputs"] = {
        name: {"sha256": sha256_file(run_root / name), "bytes": (run_root / name).stat().st_size}
        for name in ("f0_results.jsonl", "f0_hotspots_label_blind.json")
    }
    write_json(run_root / "run_manifest.json", manifest)
    return manifest


def nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)] if ordered else 0


def run_evaluate(data_root: Path, run_root: Path) -> dict[str, Any]:
    output_path = run_root / "f0_evaluation.json"
    if output_path.exists():
        raise ExperimentError("F0 ground truth has already been evaluated")
    manifest = load_json(run_root / "run_manifest.json")
    if manifest.get("status") != "scan_complete_labels_unopened":
        raise ExperimentError("F0 scan is not complete or labels may already have been opened")
    results = load_jsonl(run_root / "f0_results.jsonl")
    labels = load_jsonl(data_root / "ground_truth" / "labels.jsonl")
    label_by_id = {row["case_id"]: row for row in labels}
    if len(results) != 40 or set(label_by_id) != {row["case_id"] for row in results}:
        raise ExperimentError("Result/ground-truth identity mismatch")
    joined = [{**row, **label_by_id[row["case_id"]]} for row in results]
    class_metrics: dict[str, Any] = {}
    for workload_class in ("low_permission", "high_privilege_legitimate"):
        subset = [row for row in joined if row["workload_class"] == workload_class]
        counts = Counter(row["decision"] for row in subset)
        class_metrics[workload_class] = {
            "cases": len(subset),
            "decision_counts": dict(sorted(counts.items())),
            "allow_rate": counts["ALLOW"] / len(subset),
            "review_rate": counts["REVIEW"] / len(subset),
            "block_rate": counts["BLOCK"] / len(subset),
            "unknown_rate": counts["UNKNOWN"] / len(subset),
        }
    actionable_hotspots = Counter(
        finding.get("rule_id") or "<missing>"
        for row in joined
        for finding in row["findings"]
        if finding.get("severity") in {"MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    )
    low = [row for row in joined if row["workload_class"] == "low_permission"]
    latencies = [int(row["duration_ms"]) for row in joined]
    evaluation = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "system": "F0",
        "evaluated_at": now_iso(),
        "case_count": len(joined),
        "decision_counts": dict(sorted(Counter(row["decision"] for row in joined).items())),
        "by_workload_class": class_metrics,
        "low_permission_unnecessary_non_allow_count": sum(row["decision"] in {"REVIEW", "BLOCK"} for row in low),
        "low_permission_direct_block_count": sum(row["decision"] == "BLOCK" for row in low),
        "actionable_rule_hotspots": dict(sorted(actionable_hotspots.items(), key=lambda item: (-item[1], item[0]))),
        "latency": {
            "median_ms": statistics.median(latencies),
            "p95_ms": nearest_rank(latencies, 0.95),
            "max_ms": max(latencies),
        },
        "acceptance_snapshot": {
            "low_permission_direct_block_zero": class_metrics["low_permission"]["block_rate"] == 0,
            "low_permission_auto_allow_at_least_80pct": class_metrics["low_permission"]["allow_rate"] >= 0.8,
            "high_privilege_unknown_zero": class_metrics["high_privilege_legitimate"]["unknown_rate"] == 0,
        },
        "case_diagnostics": [
            {
                "case_id": row["case_id"],
                "workload_class": row["workload_class"],
                "stratum": row["stratum"],
                "decision": row["decision"],
                "function_summary": row["function_summary"],
                "permission_surface": row["permission_surface"],
                "selection_reason": row["selection_reason"],
                "actionable_findings": [
                    finding for finding in row["findings"]
                    if finding.get("severity") in {"MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
                ],
            }
            for row in joined
        ],
    }
    write_json(output_path, evaluation)
    manifest["status"] = "f0_evaluated"
    manifest["ground_truth_opened_during_scan"] = False
    manifest["ground_truth_opened_after_frozen_scan"] = True
    manifest["outputs"]["f0_evaluation.json"] = {"sha256": sha256_file(output_path), "bytes": output_path.stat().st_size}
    write_json(run_root / "run_manifest.json", manifest)
    return evaluation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the M15 E02 real-Skill F0 baseline")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan")
    scan.add_argument("--workers", type=int, default=4)
    scan.add_argument("--timeout-seconds", type=int, default=120)
    subparsers.add_parser("evaluate")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "scan":
            result = run_scan(args.data_root.resolve(), args.run_root.resolve(), args.workers, args.timeout_seconds)
        else:
            result = run_evaluate(args.data_root.resolve(), args.run_root.resolve())
    except (ExperimentError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
