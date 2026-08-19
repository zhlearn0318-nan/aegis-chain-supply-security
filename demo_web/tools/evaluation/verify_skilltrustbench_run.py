from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from tools.evaluation.run_skilltrustbench import (  # noqa: E402
    ALLOWED_ANALYZERS,
    EvaluationError,
    compute_metrics,
    error_slices,
    load_json,
    load_jsonl,
    preflight,
    sha256_file,
    validate_resume_prefix,
    write_json,
)


SAFE_FINDING_KEYS = {"id", "rule_id", "category", "severity", "analyzer", "location"}


def verify_output_identity(output_dir: Path, manifest: dict[str, Any]) -> None:
    declared = manifest.get("outputs")
    if not isinstance(declared, dict) or not declared:
        raise EvaluationError("Run manifest has no declared output identities")
    for name, identity in declared.items():
        path = output_dir / name
        if not path.is_file():
            raise EvaluationError(f"Declared run output is missing: {name}")
        if path.stat().st_size != identity.get("bytes"):
            raise EvaluationError(f"Declared run output size differs: {name}")
        if sha256_file(path) != identity.get("sha256"):
            raise EvaluationError(f"Declared run output hash differs: {name}")


def verify_run(output_dir: Path) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    manifest = load_json(output_dir / "run_manifest.json")
    mode = str(manifest.get("mode"))
    if mode not in {"smoke", "pilot", "official10", "full"}:
        raise EvaluationError(f"Unsupported run mode: {mode}")
    context = preflight(mode)
    selected = context["selected"]
    results = load_jsonl(output_dir / "per_case_results.jsonl")
    validate_resume_prefix(results, selected, str(manifest.get("run_id")))
    if len(results) != len(selected):
        raise EvaluationError(f"Run is incomplete: {len(results)}/{len(selected)}")
    verify_output_identity(output_dir, manifest)

    analyzer_union: set[str] = set()
    blocked: list[str] = []
    scanner_ineligible: list[str] = []
    for expected, row in zip(selected, results):
        case_id = str(expected["id"])
        if row.get("ground_truth") != expected.get("judgment"):
            raise EvaluationError(f"Ground truth differs from frozen manifest: {case_id}")
        expected_hash = expected.get("case_tree_sha256")
        if row.get("case_tree_sha256_before") != expected_hash:
            raise EvaluationError(f"Before-scan tree hash differs: {case_id}")
        if row.get("case_tree_sha256_after") != expected_hash:
            raise EvaluationError(f"After-scan tree hash differs: {case_id}")
        analyzers = {str(value) for value in row.get("analyzers", [])}
        if not analyzers <= ALLOWED_ANALYZERS:
            raise EvaluationError(f"Unexpected analyzer in result: {case_id}")
        analyzer_union.update(analyzers)
        for finding in row.get("finding_index", []):
            if not set(finding) <= SAFE_FINDING_KEYS:
                raise EvaluationError(f"Unsanitized finding fields retained: {case_id}")
        if (row.get("error") or {}).get("type") == "EndpointProtectionBlocked":
            if analyzers or row.get("decision") != "UNKNOWN":
                raise EvaluationError(f"Endpoint-blocked case was not a clean abstention: {case_id}")
            blocked.append(case_id)
        if expected.get("scanner_eligible") is False:
            if analyzers or row.get("decision") != "UNKNOWN":
                raise EvaluationError(f"Scanner-ineligible case was not a clean abstention: {case_id}")
            if (row.get("error") or {}).get("type") not in {
                "EndpointProtectionBlocked", "PlatformPathIncompatible"
            }:
                raise EvaluationError(f"Scanner-ineligible case has an unexpected error type: {case_id}")
            scanner_ineligible.append(case_id)

    stored_metrics = load_json(output_dir / "metrics.json")
    recomputed_metrics = compute_metrics(results, mode)
    execution = stored_metrics.pop("execution", None)
    if stored_metrics != recomputed_metrics:
        raise EvaluationError("Stored metrics differ from metrics recomputed from per-case results")
    if execution is not None:
        active_wall_seconds = float(execution.get("active_wall_seconds", 0))
        workers = int(execution.get("parallel_workers", 0))
        if active_wall_seconds <= 0 or workers != manifest.get("scanner", {}).get("parallel_workers"):
            raise EvaluationError("Stored execution metrics differ from the frozen run contract")
        expected_rate = len(results) * 60 / active_wall_seconds
        if abs(float(execution.get("throughput_cases_per_minute", 0)) - expected_rate) > 1e-9:
            raise EvaluationError("Stored throughput differs from cases / active wall time")
    slices = error_slices(results)
    for filename, key in (
        ("false_positive_cases.jsonl", "false_positives"),
        ("false_negative_cases.jsonl", "false_negatives"),
        ("classification_errors.jsonl", "classification_errors"),
    ):
        if load_jsonl(output_dir / filename) != slices[key]:
            raise EvaluationError(f"Stored error slice differs from recomputation: {filename}")

    failures = [row for row in results if row.get("status") != "completed"]
    return {
        "status": "verified",
        "run_id": manifest["run_id"],
        "cases": len(results),
        "completed": len(results) - len(failures),
        "abstentions": len(failures),
        "abstention_types": dict(sorted(Counter(
            str((row.get("error") or {}).get("type")) for row in failures
        ).items())),
        "endpoint_protection_blocked_case_ids": blocked,
        "scanner_ineligible_case_ids": scanner_ineligible,
        "analyzers": sorted(analyzer_union),
        "eligible_hash_mismatches": 0,
        "output_identities_verified": len(manifest["outputs"]),
        "metrics_recomputed_equal": True,
        "error_slices_recomputed_equal": True,
        "raw_finding_text_retained": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a completed SkillTrustBench run artifact")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify_run(args.output_dir)
    except (EvaluationError, OSError, json.JSONDecodeError) as exc:
        print(f"verification failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if args.output:
        write_json(args.output.resolve(), result)
        print(json.dumps({
            "status": result["status"],
            "run_id": result["run_id"],
            "cases": result["cases"],
            "abstentions": result["abstentions"],
            "output": str(args.output.resolve()),
        }, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
