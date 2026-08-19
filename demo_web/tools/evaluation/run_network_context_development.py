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
from backend.analyzers.network_context import ANALYZER_ID, analyze_network_context  # noqa: E402
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


RUN_ID = "2026-08-18-aegis-network-context-dev-v3"
SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
PARENT_RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
STATIC_BASELINE_RUN_ID = "2026-08-16-aegis-static-rules-dev-v4"
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
PARENT_RUN_ROOT = DEMO_ROOT / "artifacts" / "analysis" / PARENT_RUN_ID
STATIC_BASELINE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / STATIC_BASELINE_RUN_ID
CASES_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
SELECTED_GROUPS = {
    "fp_network_context",
    "control_normal_true_negative",
    "control_suspicious_correct",
    "control_malicious_correct",
}
PROTECTED_OUTPUTS = {
    "per_case_context.jsonl", "metrics.json", "evaluation_summary.json",
    "run_manifest.json", "run.log",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compact_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": item["id"],
            "rule_id": item["rule_id"],
            "category": item["category"],
            "severity": item["severity"],
            "analyzer": item["analyzer"],
            "location": item["location"],
            "context_features": (
                item["evidence"].split(";", 1)[0]
                .removeprefix("context_features=").split(",")
                if item.get("evidence") else []
            ),
        }
        for item in findings
    ]


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    network_fp = [row for row in results if row["selection_group"] == "fp_network_context"]
    controls = [row for row in results if row["selection_group"].startswith("control_")]
    rule_counts = Counter(
        finding["rule_id"] for row in results for finding in row["context_findings"]
    )
    rule_groups: dict[str, Counter[str]] = defaultdict(Counter)
    for row in results:
        for finding in row["context_findings"]:
            rule_groups[finding["rule_id"]][row["selection_group"]] += 1
    context_covered = [row for row in network_fp if row["context_findings"]]
    declared = [
        row for row in network_fp
        if any(
            finding["rule_id"] in {
                "AEGIS_CONTEXT_NETWORK_CAPABILITY_DECLARED",
                "AEGIS_CONTEXT_NETWORK_CAPABILITY_DECLARED_NO_DIRECT_PRIMITIVE",
            }
            for finding in row["context_findings"]
        )
    ]
    undeclared = [
        row for row in network_fp
        if any(
            finding["rule_id"] == "AEGIS_CONTEXT_NETWORK_BEHAVIOR_UNDECLARED"
            for finding in row["context_findings"]
        )
    ]
    decision_changes = [row for row in results if row["decision_changed"]]
    static_differences = [row for row in results if not row["static_baseline_equivalent"]]
    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "scope": "network_context_auxiliary_development_diagnostics",
        "cases": len(results),
        "selection_group_counts": dict(sorted(Counter(
            row["selection_group"] for row in results
        ).items())),
        "network_false_positive_context": {
            "cases": len(network_fp),
            "with_context_evidence": len(context_covered),
            "coverage": len(context_covered) / len(network_fp) if network_fp else 0.0,
            "declared_network_capability": len(declared),
            "undeclared_network_capability": len(undeclared),
            "declared_with_direct_primitive": sum(
                any(finding["rule_id"] == "AEGIS_CONTEXT_NETWORK_CAPABILITY_DECLARED"
                    for finding in row["context_findings"])
                for row in network_fp
            ),
            "declared_without_direct_primitive": sum(
                any(finding["rule_id"] == "AEGIS_CONTEXT_NETWORK_CAPABILITY_DECLARED_NO_DIRECT_PRIMITIVE"
                    for finding in row["context_findings"])
                for row in network_fp
            ),
            "mock_or_local_only_declared": sum(
                any(finding["rule_id"] == "AEGIS_CONTEXT_NETWORK_MOCK_OR_LOCAL_ONLY_DECLARED"
                    for finding in row["context_findings"])
                for row in network_fp
            ),
            "read_only_network_behavior": sum(
                any(finding["rule_id"] == "AEGIS_CONTEXT_READ_ONLY_NETWORK_BEHAVIOR"
                    for finding in row["context_findings"])
                for row in network_fp
            ),
            "outbound_declared": sum(
                any(finding["rule_id"] == "AEGIS_CONTEXT_OUTBOUND_BEHAVIOR_DECLARED"
                    for finding in row["context_findings"])
                for row in network_fp
            ),
            "outbound_not_explicitly_declared": sum(
                any(finding["rule_id"] == "AEGIS_CONTEXT_OUTBOUND_BEHAVIOR_NOT_EXPLICITLY_DECLARED"
                    for finding in row["context_findings"])
                for row in network_fp
            ),
        },
        "advisory_sensitive_flow": {
            "sensitive_source_with_outbound_sink": rule_counts.get(
                "AEGIS_CONTEXT_SENSITIVE_SOURCE_WITH_OUTBOUND_SINK", 0
            ),
            "credential_used_for_network_auth": rule_counts.get(
                "AEGIS_CONTEXT_CREDENTIAL_USED_FOR_NETWORK_AUTH", 0
            ),
            "policy_changing_findings": sum(
                finding["severity"] != "INFO"
                for row in results for finding in row["context_findings"]
            ),
        },
        "decision_invariance": {
            "cases": len(results),
            "unchanged": len(results) - len(decision_changes),
            "changed": len(decision_changes),
            "changed_case_ids": [row["case_id"] for row in decision_changes],
        },
        "controls": {
            "cases": len(controls),
            "unchanged": sum(not row["decision_changed"] for row in controls),
        },
        "static_baseline_equivalence": {
            "cases": len(results),
            "equivalent": len(results) - len(static_differences),
            "differences": len(static_differences),
            "difference_case_ids": [row["case_id"] for row in static_differences],
        },
        "context_rule_case_counts": dict(sorted(rule_counts.items())),
        "context_rule_selection_group_counts": {
            rule: dict(sorted(groups.items())) for rule, groups in sorted(rule_groups.items())
        },
        "context_latency_ms": {
            "total": sum(row["context_duration_ms"] for row in results),
            "mean": (
                sum(row["context_duration_ms"] for row in results) / len(results)
                if results else 0.0
            ),
            "max": max((row["context_duration_ms"] for row in results), default=0),
        },
    }


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
    development = [
        row for row in load_jsonl(development_path)
        if row["selection_group"] in SELECTED_GROUPS
    ]
    if len(development) != 36:
        raise EvaluationError(f"Expected 36 selected development cases, got {len(development)}")
    if Counter(row["selection_group"] for row in development)["fp_network_context"] != 16:
        raise EvaluationError("Expected 16 network false-positive development cases")

    parent_results_path = PARENT_RUN_ROOT / "per_case_results.jsonl"
    parent_results = {row["case_id"]: row for row in load_jsonl(parent_results_path)}
    static_results_path = STATIC_BASELINE_ROOT / "per_case_augmented.jsonl"
    static_results = {row["case_id"]: row for row in load_jsonl(static_results_path)}

    started_at = now_iso()
    started = time.perf_counter()
    log_lines = [
        f"{started_at} run_start id={RUN_ID} selected_cases=36 regression_opened=0"
    ]
    results: list[dict[str, Any]] = []
    for selected in development:
        case_id = str(selected["case_id"])
        parent = parent_results.get(case_id)
        static_baseline = static_results.get(case_id)
        if not parent or parent.get("status") != "completed" or not static_baseline:
            raise EvaluationError(f"Missing completed parent or static baseline: {case_id}")
        case_root = (CASES_ROOT / case_id).resolve()
        if not case_root.is_dir() or case_root.parent != CASES_ROOT.resolve():
            raise EvaluationError(f"Development case directory is missing or out of scope: {case_id}")
        expected_hash = str(selected["case_tree_sha256"])
        before_hash = tree_sha256(case_root)
        if before_hash != expected_hash:
            raise EvaluationError(f"Case hash differs before context analysis: {case_id}")

        static_findings, _ = analyze_skill_tree(case_root)
        pre_context_findings = list(parent.get("finding_index") or []) + static_findings
        pre_context_decision = evaluate_findings(pre_context_findings).decision.value
        current_static_rules = sorted(str(item["rule_id"]) for item in static_findings)
        frozen_static_rules = sorted(
            str(item["rule_id"]) for item in static_baseline.get("aegis_findings") or []
        )
        static_equivalent = (
            pre_context_decision == static_baseline["enhanced_decision"]
            and current_static_rules == frozen_static_rules
        )

        context_started = time.perf_counter()
        context_findings, context_analyzers = analyze_network_context(
            case_root, list(parent.get("finding_index") or [])
        )
        context_duration_ms = max(1, round((time.perf_counter() - context_started) * 1000))
        if any(finding["severity"] != "INFO" for finding in context_findings):
            raise EvaluationError(f"Context analyzer emitted policy-changing severity: {case_id}")
        post_context_findings = pre_context_findings + context_findings
        evaluation = evaluate_findings(post_context_findings)
        post_context_decision = evaluation.decision.value
        after_hash = tree_sha256(case_root)
        if after_hash != expected_hash:
            raise EvaluationError(f"Case hash differs after context analysis: {case_id}")

        result = {
            "schema_version": "1.0",
            "run_id": RUN_ID,
            "case_id": case_id,
            "selection_group": selected["selection_group"],
            "ground_truth": selected["ground_truth"],
            "risk_labels": selected.get("risk_labels") or [],
            "pre_context_decision": pre_context_decision,
            "post_context_decision": post_context_decision,
            "decision_changed": pre_context_decision != post_context_decision,
            "static_baseline_equivalent": static_equivalent,
            "context_findings": compact_findings(context_findings),
            "context_analyzers": context_analyzers,
            "post_context_policy_trace": evaluation.trace.model_dump(mode="json"),
            "context_duration_ms": context_duration_ms,
            "case_tree_sha256_before": before_hash,
            "case_tree_sha256_after": after_hash,
            "raw_text_retained": False,
        }
        results.append(result)
        log_lines.append(
            f"{now_iso()} case_end id={case_id} pre={pre_context_decision} "
            f"post={post_context_decision} context_findings={len(context_findings)} "
            f"context_duration_ms={context_duration_ms} hash_unchanged=true"
        )

    metrics = summarize(results)
    if metrics["static_baseline_equivalence"]["differences"]:
        raise EvaluationError("Current Aegis Static results differ from accepted v4 baseline")
    elapsed_seconds = round(time.perf_counter() - started, 3)
    write_jsonl(output_dir / "per_case_context.jsonl", results)
    write_json(output_dir / "metrics.json", metrics)
    supported = (
        metrics["network_false_positive_context"]["with_context_evidence"] > 0
        and metrics["decision_invariance"]["changed"] == 0
        and metrics["advisory_sensitive_flow"]["policy_changing_findings"] == 0
    )
    evaluation_summary = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "claim_verdict": "supported_on_development_set" if supported else "revise_context_model",
        "outcome_summary": (
            f"Context evidence covered {metrics['network_false_positive_context']['with_context_evidence']}/16 "
            f"network false-positive cases; decision changes={metrics['decision_invariance']['changed']}/36."
        ),
        "evaluation_summary": "INFO-only sidecar context was evaluated against the accepted Aegis Static v4 decisions.",
        "claim_update": "mechanism_supported_on_selected_development_cases" if supported else "inconclusive",
        "baseline_relation": "additive_info_only_sidecar_to_aegis_static_v4",
        "failure_mode": "none" if supported else "context_coverage_or_invariance_failure",
        "next_action": "review_context_precision_then_extend_to_filesystem_context" if supported else "calibrate_on_selected_development_cases",
        "evidence_boundary": [
            "The 36 cases are selected development diagnostics, not an independent performance benchmark.",
            "Context findings are INFO-only and do not suppress, downgrade, or replace Cisco findings.",
            "No regression sample content was opened; no sample was executed, imported, installed, or fetched from the network.",
        ],
    }
    write_json(output_dir / "evaluation_summary.json", evaluation_summary)
    log_lines.append(
        f"{now_iso()} run_end status=completed elapsed_seconds={elapsed_seconds} "
        f"decision_changes={metrics['decision_invariance']['changed']} regression_opened=0"
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
            "development_selection": sorted(SELECTED_GROUPS),
            "selected_cases": len(development),
            "network_false_positive_cases": 16,
            "correct_controls": 20,
            "development_cases_sha256": sha256_file(development_path),
            "regression_cases_opened": 0,
            "regression_content_inspected": False,
        },
        "analyzer": {
            "id": ANALYZER_ID,
            "source": "backend/analyzers/network_context.py",
            "source_sha256": sha256_file(
                DEMO_ROOT / "backend" / "analyzers" / "network_context.py"
            ),
            "policy_effect": "INFO-only; no suppression or severity mutation",
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
            for name in ("per_case_context.jsonl", "metrics.json", "evaluation_summary.json", "run.log")
        },
        "claim_boundary": "Selected development mechanism evidence only; no decision or final-performance claim.",
    }
    write_json(output_dir / "run_manifest.json", manifest)
    return {
        "run_id": RUN_ID,
        "status": "completed",
        "selected_cases": len(results),
        "regression_cases_opened": 0,
        "metrics": metrics,
        "output_dir": str(output_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate INFO-only Aegis network context on selected development cases")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        result = run(args.output_dir)
    except (EvaluationError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Network context evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
