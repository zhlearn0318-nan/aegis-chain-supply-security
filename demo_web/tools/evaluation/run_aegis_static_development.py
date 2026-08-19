from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.analyzers.aegis_static import ANALYZER_ID, analyze_skill_tree  # noqa: E402
from backend.policy import evaluate_findings  # noqa: E402
from tools.datasets.prepare_skilltrustbench import tree_sha256  # noqa: E402
from tools.evaluation.run_skilltrustbench import (  # noqa: E402
    DECISION_TO_LABEL,
    EvaluationError,
    compute_metrics,
    load_json,
    load_jsonl,
    sha256_file,
    write_json,
    write_jsonl,
)


RUN_ID = "2026-08-16-aegis-static-rules-dev-v4"
SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
BASELINE_ID = "skilltrustbench-v1.0-full5520-cisco-static-v1"
PARENT_RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
BASELINE_ROOT = DEMO_ROOT / "baseline" / "skilltrustbench_v1_0" / "full_cisco_static_v1"
PARENT_RUN_ROOT = DEMO_ROOT / "artifacts" / "analysis" / PARENT_RUN_ID
CASES_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
CONTROL_GROUPS = {
    "control_normal_true_negative",
    "control_suspicious_correct",
    "control_malicious_correct",
}
TARGET_GROUPS = {"miss_wild_real_world", "miss_T06_persistence"}
PROTECTED_OUTPUTS = {
    "per_case_augmented.jsonl", "metrics.json", "evaluation_summary.json",
    "run_manifest.json", "run.log",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compact_aegis_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": item["id"],
            "rule_id": item["rule_id"],
            "category": item["category"],
            "severity": item["severity"],
            "analyzer": item["analyzer"],
            "location": item["location"],
            "evidence_codes": (
                item["evidence"].split(";", 1)[0].removeprefix("correlated_features=").split(",")
                if item.get("evidence") else []
            ),
        }
        for item in findings
    ]


def metric_record(row: dict[str, Any], decision: str, duration_ms: int) -> dict[str, Any]:
    return {
        "ground_truth": row["ground_truth"],
        "predicted_label": DECISION_TO_LABEL[decision],
        "decision": decision,
        "risk_labels": row.get("risk_labels") or [],
        "duration_ms": duration_ms,
    }


def summarize(
    development: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    by_id = {str(row["case_id"]): row for row in development}
    transitions = Counter(f"{row['baseline_decision']}->{row['enhanced_decision']}" for row in results)
    rule_counts = Counter(
        finding["rule_id"] for row in results for finding in row["aegis_findings"]
    )
    rule_group_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for row in results:
        for finding in row["aegis_findings"]:
            rule_group_counts[finding["rule_id"]][row["selection_group"]] += 1

    controls = [row for row in results if row["selection_group"] in CONTROL_GROUPS]
    target = [row for row in results if row["selection_group"] in TARGET_GROUPS]
    rescued = [
        row for row in target
        if row["baseline_decision"] == "ALLOW" and row["enhanced_decision"] in {"REVIEW", "BLOCK"}
    ]
    t06 = [row for row in results if row["selection_group"] == "miss_T06_persistence"]
    wild = [row for row in results if row["selection_group"] == "miss_wild_real_world"]
    control_regressions = [row for row in controls if row["baseline_decision"] != row["enhanced_decision"]]
    normal_escalations = [
        row for row in results
        if by_id[row["case_id"]]["ground_truth"] == "normal"
        and row["baseline_decision"] != row["enhanced_decision"]
    ]
    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "scope": "selected_development_diagnostics_not_final_generalization",
        "cases": len(results),
        "decision_transitions": dict(sorted(transitions.items())),
        "aegis_rule_case_counts": dict(sorted(rule_counts.items())),
        "aegis_rule_selection_group_counts": {
            rule: dict(sorted(counts.items())) for rule, counts in sorted(rule_group_counts.items())
        },
        "targeted_slices": {
            "cases": len(target),
            "rescued_to_review_or_block": len(rescued),
            "rescue_rate": len(rescued) / len(target) if target else 0.0,
            "T06_persistence": {
                "cases": len(t06),
                "review_or_block": sum(row["enhanced_decision"] != "ALLOW" for row in t06),
                "block": sum(row["enhanced_decision"] == "BLOCK" for row in t06),
            },
            "wild_real_world": {
                "cases": len(wild),
                "review_or_block": sum(row["enhanced_decision"] != "ALLOW" for row in wild),
                "block": sum(row["enhanced_decision"] == "BLOCK" for row in wild),
            },
        },
        "correct_controls": {
            "cases": len(controls),
            "unchanged": len(controls) - len(control_regressions),
            "decision_regressions": len(control_regressions),
            "regression_case_ids": [row["case_id"] for row in control_regressions],
        },
        "normal_decision_escalations": {
            "cases": len(normal_escalations),
            "case_ids": [row["case_id"] for row in normal_escalations],
        },
        "aegis_latency_ms": {
            "total": sum(row["aegis_duration_ms"] for row in results),
            "mean": (
                sum(row["aegis_duration_ms"] for row in results) / len(results) if results else 0.0
            ),
            "max": max((row["aegis_duration_ms"] for row in results), default=0),
        },
    }


def run(output_dir: Path) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = sorted(name for name in PROTECTED_OUTPUTS if (output_dir / name).exists())
    if existing:
        raise EvaluationError(f"Output directory already contains completed-run files: {existing}")

    freeze_manifest_path = BASELINE_ROOT / "freeze_manifest.json"
    freeze_digest_path = BASELINE_ROOT / "FREEZE_SHA256.txt"
    freeze_manifest = load_json(freeze_manifest_path)
    expected_freeze_digest = freeze_digest_path.read_text(encoding="utf-8").split()[0]
    if freeze_manifest.get("baseline_id") != BASELINE_ID:
        raise EvaluationError("Frozen baseline identity differs")
    if sha256_file(freeze_manifest_path) != expected_freeze_digest:
        raise EvaluationError("Frozen baseline manifest digest differs")

    split_manifest = load_json(SPLIT_ROOT / "split_manifest.json")
    if split_manifest.get("split_id") != SPLIT_ID:
        raise EvaluationError("Development split identity differs")
    development_path = SPLIT_ROOT / "development_cases.jsonl"
    development = load_jsonl(development_path)
    if len(development) != 120:
        raise EvaluationError(f"Expected 120 development cases, got {len(development)}")

    parent_results_path = PARENT_RUN_ROOT / "per_case_results.jsonl"
    expected_parent_sha = next(
        item["sha256"] for item in freeze_manifest["source_artifacts"]
        if item["path"].endswith("per_case_results.jsonl")
    )
    if sha256_file(parent_results_path) != expected_parent_sha:
        raise EvaluationError("Frozen parent per-case results digest differs")
    parent_results = {row["case_id"]: row for row in load_jsonl(parent_results_path)}

    started_at = now_iso()
    started = time.perf_counter()
    log_lines = [f"{started_at} run_start id={RUN_ID} development_cases=120 regression_opened=0"]
    results: list[dict[str, Any]] = []
    baseline_metric_rows: list[dict[str, Any]] = []
    enhanced_metric_rows: list[dict[str, Any]] = []
    for development_row in development:
        case_id = str(development_row["case_id"])
        parent = parent_results.get(case_id)
        if not parent or parent.get("status") != "completed":
            raise EvaluationError(f"Development case lacks a completed frozen parent result: {case_id}")
        if parent.get("decision") != development_row.get("baseline_decision"):
            raise EvaluationError(f"Development baseline decision differs from parent: {case_id}")
        case_root = (CASES_ROOT / case_id).resolve()
        if not case_root.is_dir() or case_root.parent != CASES_ROOT.resolve():
            raise EvaluationError(f"Development case directory is missing or out of scope: {case_id}")
        expected_hash = str(development_row["case_tree_sha256"])
        before_hash = tree_sha256(case_root)
        if before_hash != expected_hash:
            raise EvaluationError(f"Development case hash differs before analysis: {case_id}")
        case_started = time.perf_counter()
        aegis_findings, aegis_analyzers = analyze_skill_tree(case_root)
        aegis_duration_ms = max(1, round((time.perf_counter() - case_started) * 1000))
        after_hash = tree_sha256(case_root)
        if after_hash != expected_hash:
            raise EvaluationError(f"Development case hash differs after analysis: {case_id}")

        merged_findings = list(parent.get("finding_index") or []) + aegis_findings
        evaluation = evaluate_findings(merged_findings)
        enhanced_decision = evaluation.decision.value
        baseline_duration_ms = int(parent.get("duration_ms") or 0)
        result = {
            "schema_version": "1.0",
            "run_id": RUN_ID,
            "case_id": case_id,
            "selection_group": development_row["selection_group"],
            "ground_truth": development_row["ground_truth"],
            "risk_labels": development_row.get("risk_labels") or [],
            "baseline_decision": parent["decision"],
            "enhanced_decision": enhanced_decision,
            "baseline_predicted_label": parent["predicted_label"],
            "enhanced_predicted_label": DECISION_TO_LABEL[enhanced_decision],
            "decision_changed": parent["decision"] != enhanced_decision,
            "aegis_findings": compact_aegis_findings(aegis_findings),
            "aegis_analyzers": aegis_analyzers,
            "enhanced_policy_trace": evaluation.trace.model_dump(mode="json"),
            "baseline_duration_ms": baseline_duration_ms,
            "aegis_duration_ms": aegis_duration_ms,
            "estimated_enhanced_duration_ms": baseline_duration_ms + aegis_duration_ms,
            "case_tree_sha256_before": before_hash,
            "case_tree_sha256_after": after_hash,
            "raw_text_retained": False,
        }
        results.append(result)
        baseline_metric_rows.append(metric_record(
            development_row, parent["decision"], baseline_duration_ms
        ))
        enhanced_metric_rows.append(metric_record(
            development_row, enhanced_decision, baseline_duration_ms + aegis_duration_ms
        ))
        log_lines.append(
            f"{now_iso()} case_end id={case_id} baseline={parent['decision']} "
            f"enhanced={enhanced_decision} aegis_findings={len(aegis_findings)} "
            f"aegis_duration_ms={aegis_duration_ms} hash_unchanged=true"
        )

    diagnostics = summarize(development, results)
    baseline_metrics = compute_metrics(baseline_metric_rows, "smoke")
    enhanced_metrics = compute_metrics(enhanced_metric_rows, "smoke")
    for metrics in (baseline_metrics, enhanced_metrics):
        metrics["scope"] = "selected_development_diagnostics"
        metrics["warning"] = "Error-selected development metrics are not final generalization estimates."
    metrics_payload = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "baseline": baseline_metrics,
        "enhanced": enhanced_metrics,
        "diagnostics": diagnostics,
    }
    elapsed_seconds = round(time.perf_counter() - started, 3)
    write_jsonl(output_dir / "per_case_augmented.jsonl", results)
    write_json(output_dir / "metrics.json", metrics_payload)
    evaluation_summary = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "claim_verdict": (
            "supported_on_development_set"
            if diagnostics["targeted_slices"]["rescued_to_review_or_block"] > 0
            and diagnostics["correct_controls"]["decision_regressions"] == 0
            and diagnostics["normal_decision_escalations"]["cases"] == 0
            else "revise_rules"
        ),
        "takeaway": (
            f"Aegis changed {sum(row['decision_changed'] for row in results)}/120 development decisions; "
            f"rescued {diagnostics['targeted_slices']['rescued_to_review_or_block']}/"
            f"{diagnostics['targeted_slices']['cases']} targeted misses; "
            f"correct-control regressions={diagnostics['correct_controls']['decision_regressions']}."
        ),
        "evidence_boundary": [
            "The development set was selected using frozen baseline errors and is diagnostic, not an independent benchmark.",
            "No regression sample content was opened in this run.",
            "Aegis used bounded read-only text analysis; no sample was executed, imported, installed, or fetched from the network.",
        ],
        "next_action": (
            "freeze_rule_family_then_run_sealed_regression_once"
            if diagnostics["correct_controls"]["decision_regressions"] == 0
            and diagnostics["normal_decision_escalations"]["cases"] == 0
            else "calibrate_rules_on_development_controls"
        ),
    }
    write_json(output_dir / "evaluation_summary.json", evaluation_summary)
    log_lines.append(
        f"{now_iso()} run_end status=completed elapsed_seconds={elapsed_seconds} "
        f"regression_opened=0"
    )
    (output_dir / "run.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "completed",
        "experiment_tier": "auxiliary/dev",
        "started_at": started_at,
        "completed_at": now_iso(),
        "elapsed_seconds": elapsed_seconds,
        "baseline": {
            "baseline_id": BASELINE_ID,
            "parent_run_id": PARENT_RUN_ID,
            "freeze_manifest_sha256": expected_freeze_digest,
            "per_case_results_sha256": expected_parent_sha,
            "mutation": False,
        },
        "dataset": {
            "split_id": SPLIT_ID,
            "development_cases": len(development),
            "development_cases_sha256": sha256_file(development_path),
            "regression_cases_opened": 0,
            "regression_content_inspected": False,
        },
        "analyzer": {
            "id": ANALYZER_ID,
            "source": "backend/analyzers/aegis_static.py",
            "source_sha256": sha256_file(DEMO_ROOT / "backend" / "analyzers" / "aegis_static.py"),
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "sample_execution": False,
            "sample_import": False,
            "sample_install": False,
            "network_fetch": False,
            "raw_sample_text_retained": False,
        },
        "outputs": {
            name: {"sha256": sha256_file(output_dir / name), "bytes": (output_dir / name).stat().st_size}
            for name in ("per_case_augmented.jsonl", "metrics.json", "evaluation_summary.json", "run.log")
        },
        "claim_boundary": "Selected development diagnostics only; sealed regression and final evaluation remain pending.",
    }
    write_json(output_dir / "run_manifest.json", manifest)
    return {
        "run_id": RUN_ID,
        "status": "completed",
        "development_cases": len(results),
        "regression_cases_opened": 0,
        "diagnostics": diagnostics,
        "output_dir": str(output_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Aegis Static v1 on the authorized development split")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        result = run(args.output_dir)
    except (EvaluationError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Aegis development evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
