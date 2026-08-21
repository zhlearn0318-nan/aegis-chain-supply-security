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

from backend.analyzers.aegis_static import analyze_skill_tree  # noqa: E402
from backend.analyzers.sensitive_flow import (  # noqa: E402
    ANALYZER_ID,
    analyze_sensitive_flows,
)
from backend.policy import evaluate_findings  # noqa: E402
from tools.datasets.prepare_skilltrustbench import tree_sha256  # noqa: E402
from tools.evaluation.run_skilltrustbench import (  # noqa: E402
    EvaluationError,
    load_json,
    load_jsonl,
    sha256_file,
    write_json,
    write_jsonl,
)


RUN_ID = "2026-08-21-aegis-sensitive-flow-dev-v1"
SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
PARENT_RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
STATIC_BASELINE_RUN_ID = "2026-08-16-aegis-static-rules-dev-v4"
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
PARENT_RUN_ROOT = DEMO_ROOT / "artifacts" / "analysis" / PARENT_RUN_ID
STATIC_BASELINE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / STATIC_BASELINE_RUN_ID
CASES_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
CONTROL_GROUPS = {
    "control_normal_true_negative",
    "control_suspicious_correct",
    "control_malicious_correct",
}
PROTECTED_OUTPUTS = {
    "per_case_sensitive_flow.jsonl",
    "metrics.json",
    "evaluation_summary.json",
    "run_manifest.json",
    "run.log",
}
DECISION_RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2, "UNKNOWN": 3}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compact_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for item in findings:
        prefix = str(item.get("evidence") or "").split(";", 1)[0]
        evidence_codes = prefix.removeprefix("verified_flow=").split(",") if prefix else []
        compact.append({
            "id": item["id"],
            "rule_id": item["rule_id"],
            "category": item["category"],
            "severity": item["severity"],
            "analyzer": item["analyzer"],
            "location": item["location"],
            "evidence_codes": evidence_codes,
        })
    return compact


def is_upgrade(before: str, after: str) -> bool:
    return DECISION_RANK.get(after, 3) > DECISION_RANK.get(before, 3)


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    transitions = Counter(
        f"{row['pre_sensitive_flow_decision']}->{row['post_sensitive_flow_decision']}"
        for row in results
    )
    rule_counts = Counter(
        finding["rule_id"]
        for row in results
        for finding in row["sensitive_flow_findings"]
    )
    rule_groups: dict[str, Counter[str]] = defaultdict(Counter)
    rule_truth: dict[str, Counter[str]] = defaultdict(Counter)
    for row in results:
        for finding in row["sensitive_flow_findings"]:
            rule_groups[finding["rule_id"]][row["selection_group"]] += 1
            rule_truth[finding["rule_id"]][row["ground_truth"]] += 1

    hits = [row for row in results if row["sensitive_flow_findings"]]
    decision_changes = [row for row in results if row["decision_changed"]]
    upgrades = [
        row for row in results
        if is_upgrade(row["pre_sensitive_flow_decision"], row["post_sensitive_flow_decision"])
    ]
    non_normal_upgrades = [row for row in upgrades if row["ground_truth"] != "normal"]
    normal_upgrades = [row for row in upgrades if row["ground_truth"] == "normal"]
    controls = [row for row in results if row["selection_group"] in CONTROL_GROUPS]
    control_changes = [row for row in controls if row["decision_changed"]]
    static_differences = [row for row in results if not row["static_baseline_equivalent"]]
    hash_mismatches = [
        row for row in results
        if row["case_tree_sha256_before"] != row["case_tree_sha256_after"]
    ]
    latencies = [row["sensitive_flow_duration_ms"] for row in results]
    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "scope": "all_120_visible_development_cases_not_final_generalization",
        "cases": len(results),
        "ground_truth_counts": dict(sorted(Counter(
            row["ground_truth"] for row in results
        ).items())),
        "selection_group_counts": dict(sorted(Counter(
            row["selection_group"] for row in results
        ).items())),
        "decision_transitions": dict(sorted(transitions.items())),
        "analyzer_hits": {
            "cases": len(hits),
            "findings": sum(len(row["sensitive_flow_findings"]) for row in results),
            "case_ids": [row["case_id"] for row in hits],
            "rule_case_counts": dict(sorted(rule_counts.items())),
            "rule_ground_truth_counts": {
                rule: dict(sorted(counts.items())) for rule, counts in sorted(rule_truth.items())
            },
            "rule_selection_group_counts": {
                rule: dict(sorted(counts.items())) for rule, counts in sorted(rule_groups.items())
            },
        },
        "decision_effect": {
            "changed": len(decision_changes),
            "changed_case_ids": [row["case_id"] for row in decision_changes],
            "non_normal_upgrades": len(non_normal_upgrades),
            "non_normal_upgrade_case_ids": [row["case_id"] for row in non_normal_upgrades],
            "normal_upgrades": len(normal_upgrades),
            "normal_upgrade_case_ids": [row["case_id"] for row in normal_upgrades],
        },
        "correct_controls": {
            "cases": len(controls),
            "unchanged": len(controls) - len(control_changes),
            "decision_changes": len(control_changes),
            "changed_case_ids": [row["case_id"] for row in control_changes],
        },
        "static_baseline_equivalence": {
            "cases": len(results),
            "equivalent": len(results) - len(static_differences),
            "differences": len(static_differences),
            "difference_case_ids": [row["case_id"] for row in static_differences],
        },
        "integrity": {
            "hash_mismatches": len(hash_mismatches),
            "mismatch_case_ids": [row["case_id"] for row in hash_mismatches],
            "regression_cases_opened": 0,
        },
        "sensitive_flow_latency_ms": {
            "total": sum(latencies),
            "mean": sum(latencies) / len(latencies) if latencies else 0.0,
            "max": max(latencies, default=0),
        },
    }


def classify(metrics: dict[str, Any]) -> tuple[str, str, str]:
    effect = metrics["decision_effect"]
    if (
        metrics["static_baseline_equivalence"]["differences"]
        or metrics["integrity"]["hash_mismatches"]
        or effect["normal_upgrades"]
    ):
        return (
            "revise_analyzer",
            "development_guard_failed",
            "inspect normal upgrades or baseline/integrity differences before adding rule coverage",
        )
    if effect["non_normal_upgrades"]:
        return (
            "supported_on_development_set",
            "mechanism_supported_on_visible_development_cases",
            "review hit precision, then prepare a separately authorized sealed-regression gate",
        )
    return (
        "mechanism_only_no_development_rescue",
        "inconclusive_for_detection_gain",
        "retain passing unit controls and extend bounded flow coverage on development data",
    )


def run(output_dir: Path) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = sorted(name for name in PROTECTED_OUTPUTS if (output_dir / name).exists())
    if existing:
        raise EvaluationError(f"Output directory already contains completed-run files: {existing}")

    split_manifest = load_json(SPLIT_ROOT / "split_manifest.json")
    if split_manifest.get("split_id") != SPLIT_ID:
        raise EvaluationError("Development split identity differs")
    development_path = SPLIT_ROOT / "development_cases.jsonl"
    development = load_jsonl(development_path)
    if len(development) != 120:
        raise EvaluationError(f"Expected 120 development cases, got {len(development)}")

    parent_results_path = PARENT_RUN_ROOT / "per_case_results.jsonl"
    parent_results = {str(row["case_id"]): row for row in load_jsonl(parent_results_path)}
    static_results_path = STATIC_BASELINE_ROOT / "per_case_augmented.jsonl"
    static_results = {str(row["case_id"]): row for row in load_jsonl(static_results_path)}

    started_at = now_iso()
    started = time.perf_counter()
    log_lines = [
        f"{started_at} run_start id={RUN_ID} development_cases=120 regression_opened=0"
    ]
    results: list[dict[str, Any]] = []
    for development_row in development:
        case_id = str(development_row["case_id"])
        parent = parent_results.get(case_id)
        static_baseline = static_results.get(case_id)
        if not parent or parent.get("status") != "completed" or not static_baseline:
            raise EvaluationError(f"Missing completed parent or static baseline: {case_id}")
        case_root = (CASES_ROOT / case_id).resolve()
        if not case_root.is_dir() or case_root.parent != CASES_ROOT.resolve():
            raise EvaluationError(f"Development case directory is missing or out of scope: {case_id}")
        expected_hash = str(development_row["case_tree_sha256"])
        before_hash = tree_sha256(case_root)
        if before_hash != expected_hash:
            raise EvaluationError(f"Development case hash differs before analysis: {case_id}")

        static_findings, _ = analyze_skill_tree(case_root)
        pre_flow_findings = list(parent.get("finding_index") or []) + static_findings
        pre_flow_evaluation = evaluate_findings(pre_flow_findings)
        pre_flow_decision = pre_flow_evaluation.decision.value
        current_static_rules = sorted(str(item["rule_id"]) for item in static_findings)
        frozen_static_rules = sorted(
            str(item["rule_id"])
            for item in (static_baseline.get("aegis_findings") or [])
        )
        static_equivalent = (
            pre_flow_decision == static_baseline["enhanced_decision"]
            and current_static_rules == frozen_static_rules
        )

        flow_started = time.perf_counter()
        flow_findings, flow_analyzers = analyze_sensitive_flows(case_root)
        flow_duration_ms = max(1, round((time.perf_counter() - flow_started) * 1000))
        post_flow_evaluation = evaluate_findings(pre_flow_findings + flow_findings)
        post_flow_decision = post_flow_evaluation.decision.value
        after_hash = tree_sha256(case_root)
        if after_hash != expected_hash:
            raise EvaluationError(f"Development case hash differs after analysis: {case_id}")

        result = {
            "schema_version": "1.0",
            "run_id": RUN_ID,
            "case_id": case_id,
            "selection_group": development_row["selection_group"],
            "ground_truth": development_row["ground_truth"],
            "risk_labels": development_row.get("risk_labels") or [],
            "pre_sensitive_flow_decision": pre_flow_decision,
            "post_sensitive_flow_decision": post_flow_decision,
            "decision_changed": pre_flow_decision != post_flow_decision,
            "static_baseline_equivalent": static_equivalent,
            "sensitive_flow_findings": compact_findings(flow_findings),
            "sensitive_flow_analyzers": flow_analyzers,
            "post_sensitive_flow_policy_trace": post_flow_evaluation.trace.model_dump(mode="json"),
            "sensitive_flow_duration_ms": flow_duration_ms,
            "case_tree_sha256_before": before_hash,
            "case_tree_sha256_after": after_hash,
            "raw_text_retained": False,
        }
        results.append(result)
        log_lines.append(
            f"{now_iso()} case_end id={case_id} pre={pre_flow_decision} "
            f"post={post_flow_decision} flow_findings={len(flow_findings)} "
            f"flow_duration_ms={flow_duration_ms} hash_unchanged=true"
        )

    metrics = summarize(results)
    verdict, claim_update, next_action = classify(metrics)
    elapsed_seconds = round(time.perf_counter() - started, 3)
    write_jsonl(output_dir / "per_case_sensitive_flow.jsonl", results)
    write_json(output_dir / "metrics.json", metrics)
    evaluation_summary = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "claim_verdict": verdict,
        "outcome_summary": (
            f"Sensitive Flow hit {metrics['analyzer_hits']['cases']}/120 cases; "
            f"non-normal upgrades={metrics['decision_effect']['non_normal_upgrades']}; "
            f"normal upgrades={metrics['decision_effect']['normal_upgrades']}."
        ),
        "evaluation_summary": (
            "The separate exact-flow analyzer was paired with the accepted Cisco+Aegis Static v4 "
            "decision for every visible development case."
        ),
        "claim_update": claim_update,
        "baseline_relation": "additive_policy_changing_analyzer_after_aegis_static_v4",
        "failure_mode": "none" if verdict == "supported_on_development_set" else verdict,
        "next_action": next_action,
        "evidence_boundary": [
            "All 120 cases are visible development diagnostics, not an independent benchmark.",
            "The 600-case regression set remained sealed and no regression sample content was opened.",
            "No sample was executed, imported, installed, or fetched from the network.",
            "Only compact rule, severity, path, line, and normalized evidence codes were retained.",
        ],
    }
    write_json(output_dir / "evaluation_summary.json", evaluation_summary)
    log_lines.append(
        f"{now_iso()} run_end status=completed verdict={verdict} "
        f"elapsed_seconds={elapsed_seconds} regression_opened=0"
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
        "command": [sys.executable, *sys.argv],
        "baseline": {
            "parent_cisco_run_id": PARENT_RUN_ID,
            "parent_per_case_sha256": sha256_file(parent_results_path),
            "aegis_static_run_id": STATIC_BASELINE_RUN_ID,
            "aegis_static_per_case_sha256": sha256_file(static_results_path),
            "static_equivalence_differences": metrics["static_baseline_equivalence"]["differences"],
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
            "source": "backend/analyzers/sensitive_flow.py",
            "source_sha256": sha256_file(
                DEMO_ROOT / "backend" / "analyzers" / "sensitive_flow.py"
            ),
            "policy_effect": "CRITICAL or HIGH only for proven source-to-payload variable flow",
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
            name: {
                "sha256": sha256_file(output_dir / name),
                "bytes": (output_dir / name).stat().st_size,
            }
            for name in (
                "per_case_sensitive_flow.jsonl",
                "metrics.json",
                "evaluation_summary.json",
                "run.log",
            )
        },
        "claim_boundary": (
            "Visible-development mechanism evidence only; no sealed-regression or final-performance claim."
        ),
    }
    write_json(output_dir / "run_manifest.json", manifest)
    return {
        "run_id": RUN_ID,
        "status": "completed",
        "claim_verdict": verdict,
        "development_cases": len(results),
        "regression_cases_opened": 0,
        "metrics": metrics,
        "output_dir": str(output_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate Aegis Sensitive Flow v1 on all visible development cases"
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        result = run(args.output_dir)
    except (EvaluationError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Sensitive Flow evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
