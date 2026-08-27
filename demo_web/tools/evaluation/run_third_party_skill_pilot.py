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
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.adapters import ProcessRunner, SkillScannerAdapter  # noqa: E402
from backend.policy import evaluate_findings, load_policy, summarize  # noqa: E402
from backend.skill_static_pipeline import run_skill_static_pipeline  # noqa: E402
from tools.datasets.prepare_third_party_skill_pilot import tree_sha256  # noqa: E402
from tools.evaluation.run_skilltrustbench import sanitize_findings  # noqa: E402


RUN_ID = "2026-08-28-third-party-skill-pilot40-static-v1"
BASELINE_ID = "third-party-skill-pilot40-v1"
CASE_IDS_SHA256 = "58768c2badfe65f49f77a9a7e932b77a8d2341e6a53cf315739c5d6e8274dc53"
SOURCE_LOCK_SHA256 = "bb1be3283e9ca667aefcc090d8c7c6ddbc1374764012379950f2505c39c6bf53"
PILOT_MANIFEST_SHA256 = "90279916dc5eb2d4ad54ee42dcfcaeb2e4aafeaa85808e88778cf2f2bab44641"
INTAKE_MANIFEST_SHA256 = "e5ea72364e5b953328b51fa4eb5908e421023ed95b344807010a97376c52ff56"
DATA_ROOT = REPRODUCTION_ROOT / "datasets" / "third_party_skill_pilot40_v1"
BASELINE_ROOT = DEMO_ROOT / "baseline" / "third_party_skill_pilot40_v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "analysis" / RUN_ID
REQUIRED_ANALYZERS = {"static_analyzer", "aegis-static-v1"}
EXTERNAL_ANALYZER_TOKENS = {"llm", "virustotal", "aidefense", "behavioral"}
CLASSES = ("normal", "suspicious", "malicious")
PREDICTIONS = (*CLASSES, "abstain")
DECISION_TO_LABEL = {"ALLOW": "normal", "REVIEW": "suspicious", "BLOCK": "malicious", "UNKNOWN": "abstain"}


class EvaluationError(RuntimeError):
    """Raised when the frozen pilot or scan boundary cannot be trusted."""


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvaluationError(f"Expected JSON object: {path}")
    return payload


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def is_read_only(path: Path) -> bool:
    if os.name != "nt":
        return not os.access(path, os.W_OK)
    attributes = getattr(path.stat(), "st_file_attributes", 0)
    return bool(attributes & getattr(__import__("stat"), "FILE_ATTRIBUTE_READONLY", 1))


def verify_case(record: dict[str, Any]) -> str:
    cases_root = (DATA_ROOT / "cases").resolve()
    case_root = (DATA_ROOT / str(record["local_path"])).resolve()
    if cases_root not in case_root.parents:
        raise EvaluationError(f"Case escaped frozen root: {record['case_id']}")
    if not (case_root / "SKILL.md").is_file():
        raise EvaluationError(f"Root SKILL.md is missing: {record['case_id']}")
    files = [path for path in case_root.rglob("*") if path.is_file()]
    if not files or any(path.is_symlink() for path in files):
        raise EvaluationError(f"Empty case or link detected: {record['case_id']}")
    if any(not is_read_only(path) for path in files):
        raise EvaluationError(f"Case is not read-only: {record['case_id']}")
    actual = tree_sha256(case_root)
    if actual != record["case_tree_sha256"]:
        raise EvaluationError(f"Case tree drift: {record['case_id']}={actual}")
    return actual


def preflight() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    paths = {
        BASELINE_ROOT / "source_lock.json": SOURCE_LOCK_SHA256,
        BASELINE_ROOT / "case_ids.txt": CASE_IDS_SHA256,
        DATA_ROOT / "pilot_manifest.jsonl": PILOT_MANIFEST_SHA256,
        DATA_ROOT / "intake_manifest.json": INTAKE_MANIFEST_SHA256,
    }
    for path, expected in paths.items():
        actual = sha256_file(path)
        if actual != expected:
            raise EvaluationError(f"Frozen identity mismatch: {path.name}={actual}")
    verification = load_json(BASELINE_ROOT / "verification.json")
    contract = load_json(BASELINE_ROOT / "json" / "metric_contract.json")
    if verification.get("status") != "verified_before_first_scan":
        raise EvaluationError("Baseline verification state is not frozen")
    if contract.get("status") != "frozen_before_first_scan":
        raise EvaluationError("Metric contract is not frozen")
    records = load_jsonl(DATA_ROOT / "pilot_manifest.jsonl")
    committed_ids = (BASELINE_ROOT / "case_ids.txt").read_text(encoding="utf-8").splitlines()
    if len(records) != 40 or [row.get("case_id") for row in records] != committed_ids:
        raise EvaluationError("Manifest order or case IDs differ from the committed freeze")
    if len({row["case_id"] for row in records}) != 40:
        raise EvaluationError("Manifest contains duplicate case IDs")
    for record in records:
        verify_case(record)
    return records, contract


def validate_analyzers(analyzers: list[str]) -> None:
    normalized = {str(value).lower() for value in analyzers}
    if not REQUIRED_ANALYZERS <= normalized:
        raise EvaluationError(f"Required Cisco+Aegis analyzers are missing: {sorted(normalized)}")
    if any(token in analyzer for analyzer in normalized for token in EXTERNAL_ANALYZER_TOKENS):
        raise EvaluationError(f"External or behavioral analyzer crossed static boundary: {sorted(normalized)}")


def scan_case(adapter: SkillScannerAdapter, policy, record: dict[str, Any]) -> dict[str, Any]:
    case_root = (DATA_ROOT / str(record["local_path"])).resolve()
    before_hash = verify_case(record)
    started = time.perf_counter()
    try:
        pipeline = run_skill_static_pipeline(case_root, adapter)
        findings = pipeline["findings"]
        analyzers = pipeline["analyzers"]
        validate_analyzers(analyzers)
        evaluation = evaluate_findings(findings, policy)
        status = "completed"
        decision = evaluation.decision.value
        trace = evaluation.trace.model_dump(mode="json")
        error = None
    except Exception as exc:
        findings = []
        analyzers = []
        status = "failed"
        decision = "UNKNOWN"
        trace = {
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "rule_id": "SCAN_EXECUTION_FAILED",
            "reason": "Static pipeline failed; fail-closed UNKNOWN.",
            "matched_severities": [],
            "matched_finding_ids": [],
            "fail_closed": True,
        }
        error = {"type": type(exc).__name__, "message": "Untrusted raw error omitted."}
    duration_ms = max(1, round((time.perf_counter() - started) * 1000))
    after_hash = verify_case(record)
    if after_hash != before_hash:
        raise EvaluationError(f"Case changed during static scan: {record['case_id']}")
    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "case_id": record["case_id"],
        "dataset": record["dataset"],
        "source_kind": record["source_kind"],
        "ground_truth": record["ground_truth"],
        "metric_eligible": record["metric_eligible"],
        "risk_labels": record.get("risk_labels", []),
        "case_tree_sha256_before": before_hash,
        "case_tree_sha256_after": after_hash,
        "status": status,
        "decision": decision,
        "predicted_label": DECISION_TO_LABEL[decision],
        "duration_ms": duration_ms,
        "analyzers": analyzers,
        "summary": summarize(findings),
        "policy_trace": trace,
        "finding_index": sanitize_findings(findings),
        "error": error,
    }


def class_f1(records: list[dict[str, Any]], label: str) -> float:
    tp = sum(row["ground_truth"] == label and row["predicted_label"] == label for row in records)
    fp = sum(row["ground_truth"] != label and row["predicted_label"] == label for row in records)
    fn = sum(row["ground_truth"] == label and row["predicted_label"] != label for row in records)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)] if ordered else 0


def compute_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    strong = [row for row in results if row["metric_eligible"]]
    weak = [row for row in results if not row["metric_eligible"]]
    covered = [row for row in strong if row["predicted_label"] != "abstain"]
    malicious = [row for row in strong if row["ground_truth"] == "malicious"]
    non_normal = [row for row in strong if row["ground_truth"] in {"suspicious", "malicious"}]
    normal = [row for row in strong if row["ground_truth"] == "normal"]
    matrix = {truth: {prediction: 0 for prediction in PREDICTIONS} for truth in CLASSES}
    for row in strong:
        matrix[row["ground_truth"]][row["predicted_label"]] += 1
    per_label: dict[str, Any] = {}
    for label in (f"T{index:02d}" for index in range(1, 10)):
        matching = [row for row in strong if label in row.get("risk_labels", [])]
        detected = sum(row["predicted_label"] in {"suspicious", "malicious"} for row in matching)
        per_label[label] = {
            "support": len(matching),
            "detected": detected,
            "recall": detected / len(matching) if matching else None,
        }
    latencies = [int(row["duration_ms"]) for row in results]
    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "cases": len(results),
        "decision_counts_all40": dict(sorted(Counter(row["decision"] for row in results).items())),
        "strong_label_metrics": {
            "cases": len(strong),
            "coverage": len(covered) / len(strong),
            "failure_rate": (len(strong) - len(covered)) / len(strong),
            "strict_macro_f1": statistics.fmean(class_f1(strong, label) for label in CLASSES),
            "malicious_recall": sum(row["predicted_label"] == "malicious" for row in malicious) / len(malicious),
            "non_normal_recall": sum(row["predicted_label"] in {"suspicious", "malicious"} for row in non_normal) / len(non_normal),
            "normal_fpr": sum(row["predicted_label"] in {"suspicious", "malicious"} for row in normal) / len(normal),
            "confusion_matrix": matrix,
            "per_risk_label_recall": per_label,
        },
        "weak_negative_diagnostics": {
            "cases": len(weak),
            "scan_completion_rate": sum(row["status"] == "completed" for row in weak) / len(weak),
            "decision_counts": dict(sorted(Counter(row["decision"] for row in weak).items())),
            "weak_negative_review_rate": sum(row["decision"] == "REVIEW" for row in weak) / len(weak),
            "weak_negative_block_rate": sum(row["decision"] == "BLOCK" for row in weak) / len(weak),
        },
        "latency_all40": {
            "median_ms": statistics.median(latencies),
            "p95_ms": nearest_rank(latencies, 0.95),
            "max_ms": max(latencies),
        },
        "claim_boundary": "Accuracy metrics use only 16 strong labels; 24 weak negatives are descriptive diagnostics.",
    }


def dynamic_eligibility(
    source_records: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result_by_id = {row["case_id"]: row for row in results}
    rows: list[dict[str, Any]] = []
    for source in source_records:
        result = result_by_id[source["case_id"]]
        reasons: list[str] = []
        if not source.get("dynamic_label_eligible"):
            reasons.append("ground_truth_safety_gate")
        if not source.get("dynamic_candidate_pre_static"):
            reasons.append("no_single_conservative_python_entrypoint")
        if result["status"] != "completed":
            reasons.append("static_scan_failed")
        if result["decision"] not in {"ALLOW", "REVIEW"}:
            reasons.append("static_decision_not_eligible")
        eligible = not reasons
        rows.append({
            "case_id": source["case_id"],
            "eligible": eligible,
            "reasons": reasons,
            "static_decision": result["decision"],
            "python_entrypoints": source.get("python_entrypoints", []),
        })
    return rows


def run(output_root: Path, workers: int, timeout_seconds: int) -> dict[str, Any]:
    if not 1 <= workers <= 8:
        raise EvaluationError("workers must be between 1 and 8")
    source_records, contract = preflight()
    output_root = output_root.resolve()
    if output_root.exists() and any(output_root.iterdir()):
        raise EvaluationError(f"Output directory is not empty: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    scanner = REPRODUCTION_ROOT / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
    if not scanner.is_file():
        raise EvaluationError(f"Cisco Skill Scanner is unavailable: {scanner}")
    runner = ProcessRunner(
        timeout_seconds=timeout_seconds,
        cache_root=DEMO_ROOT / "data" / "cache" / "third_party_skill_pilot40_v1",
        extra_path=scanner.parent,
    )
    version_call = runner.run([str(scanner), "--version"])
    if version_call.returncode != 0:
        raise EvaluationError("Could not query Cisco Skill Scanner version")
    adapter = SkillScannerAdapter(scanner=scanner, runner=runner)
    policy = load_policy()
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "running",
        "started_at": now_iso(),
        "baseline_id": BASELINE_ID,
        "dataset": {"cases": 40, "case_ids_sha256": CASE_IDS_SHA256},
        "scanner": {
            "name": "Cisco Skill Scanner + Aegis static pipeline",
            "version_output": (version_call.stdout or version_call.stderr).strip().splitlines()[0],
            "executable_sha256": sha256_file(scanner),
            "timeout_seconds_per_case": timeout_seconds,
            "parallel_workers": workers,
        },
        "policy": {
            "id": policy.policy_id,
            "version": policy.version,
            "sha256": sha256_file(DEMO_ROOT / "config" / "admission_policy.yaml"),
        },
        "metric_contract": {
            "sha256": sha256_file(BASELINE_ROOT / "json" / "metric_contract.json"),
            "primary_metric": contract["primary_metric"],
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "sample_execution": False,
            "sample_install": False,
            "network_requested_by_scan_runner": False,
            "ground_truth_passed_to_scanner": False,
        },
    }
    write_json(output_root / "run_manifest.json", manifest)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="third-party-skill-scan") as executor:
        results = list(executor.map(lambda row: scan_case(adapter, policy, row), source_records))
    metrics = compute_metrics(results)
    eligibility = dynamic_eligibility(source_records, results)
    write_jsonl(output_root / "per_case_results.jsonl", results)
    write_json(output_root / "metrics.json", metrics)
    write_json(output_root / "dynamic_eligibility.json", {
        "schema_version": "1.0",
        "eligible_count": sum(row["eligible"] for row in eligibility),
        "execution_performed": False,
        "cases": eligibility,
    })
    write_jsonl(output_root / "strong_label_errors.jsonl", [
        row for row in results
        if row["metric_eligible"] and row["predicted_label"] != row["ground_truth"]
    ])
    rule_counts = Counter(
        finding["rule_id"]
        for result in results
        for finding in result["finding_index"]
        if finding.get("rule_id")
    )
    write_json(output_root / "rule_distribution.json", dict(sorted(rule_counts.items(), key=lambda item: (-item[1], item[0]))))
    manifest["status"] = "completed"
    manifest["completed_at"] = now_iso()
    manifest["wall_seconds"] = round(time.perf_counter() - started, 3)
    manifest["outputs"] = {
        name: {"sha256": sha256_file(output_root / name), "bytes": (output_root / name).stat().st_size}
        for name in (
            "per_case_results.jsonl", "metrics.json", "dynamic_eligibility.json",
            "strong_label_errors.jsonl", "rule_distribution.json",
        )
    }
    write_json(output_root / "run_manifest.json", manifest)
    return {"manifest": manifest, "metrics": metrics, "eligible_count": sum(row["eligible"] for row in eligibility)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan the frozen 40-case third-party Skill pilot.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = run(args.output, args.workers, args.timeout_seconds)
    except (EvaluationError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
