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
from backend.analyzers.enterprise_controls import (  # noqa: E402
    ANALYZER_ID,
    analyze_enterprise_controls,
)
from backend.analyzers.sensitive_flow import analyze_sensitive_flows  # noqa: E402
from backend.analyzers.untrusted_exec_flow import analyze_untrusted_exec_flows  # noqa: E402
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


RUN_ID = "2026-08-22-aegis-enterprise-controls-dev-v3"
SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
PARENT_RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
STATIC_RUN_ID = "2026-08-16-aegis-static-rules-dev-v4"
SENSITIVE_RUN_ID = "2026-08-21-aegis-sensitive-flow-dev-v1"
UNTRUSTED_RUN_ID = "2026-08-21-aegis-untrusted-exec-flow-dev-v2"
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
PARENT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / PARENT_RUN_ID
STATIC_ROOT = DEMO_ROOT / "artifacts" / "experiment" / STATIC_RUN_ID
SENSITIVE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / SENSITIVE_RUN_ID
UNTRUSTED_ROOT = DEMO_ROOT / "artifacts" / "experiment" / UNTRUSTED_RUN_ID
CASES_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
CONTROL_GROUPS = {
    "control_normal_true_negative", "control_suspicious_correct", "control_malicious_correct",
}
OUTPUT_NAMES = (
    "per_case_enterprise_controls.jsonl", "metrics.json", "evaluation_summary.json",
    "summary.md", "claim_validation.md", "run.log",
)
PROTECTED_OUTPUTS = {*OUTPUT_NAMES, "run_manifest.json", "artifact_manifest.json"}
DECISION_RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2, "UNKNOWN": 3}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compact(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in findings:
        prefix = str(item.get("evidence") or "").split(";", 1)[0]
        rows.append({
            "id": item["id"], "rule_id": item["rule_id"], "category": item["category"],
            "severity": item["severity"], "analyzer": item["analyzer"],
            "location": item["location"],
            "evidence_codes": prefix.removeprefix("verified_features=").split(",") if prefix else [],
        })
    return rows


def rule_ids(findings: list[dict[str, Any]]) -> list[str]:
    return sorted(str(item["rule_id"]) for item in findings)


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    transitions = Counter(
        f"{row['pre_enterprise_decision']}->{row['post_enterprise_decision']}" for row in results
    )
    rule_counts = Counter(
        finding["rule_id"] for row in results for finding in row["enterprise_findings"]
    )
    groups: dict[str, Counter[str]] = defaultdict(Counter)
    truths: dict[str, Counter[str]] = defaultdict(Counter)
    for row in results:
        for finding in row["enterprise_findings"]:
            groups[finding["rule_id"]][row["selection_group"]] += 1
            truths[finding["rule_id"]][row["ground_truth"]] += 1
    hits = [row for row in results if row["enterprise_findings"]]
    changes = [row for row in results if row["decision_changed"]]
    upgrades = [
        row for row in results
        if DECISION_RANK[row["post_enterprise_decision"]] > DECISION_RANK[row["pre_enterprise_decision"]]
    ]
    non_normal = [row for row in upgrades if row["ground_truth"] != "normal"]
    normal = [row for row in upgrades if row["ground_truth"] == "normal"]
    controls = [row for row in results if row["selection_group"] in CONTROL_GROUPS]
    control_changes = [row for row in controls if row["decision_changed"]]
    prior_diff = [row for row in results if not row["prior_layers_equivalent"]]
    hash_diff = [
        row for row in results
        if row["case_tree_sha256_before"] != row["case_tree_sha256_after"]
    ]
    latency = [row["enterprise_duration_ms"] for row in results]
    return {
        "schema_version": "1.0", "run_id": RUN_ID,
        "scope": "all_120_visible_development_cases_not_final_generalization",
        "cases": len(results),
        "ground_truth_counts": dict(sorted(Counter(row["ground_truth"] for row in results).items())),
        "decision_transitions": dict(sorted(transitions.items())),
        "analyzer_hits": {
            "cases": len(hits), "findings": sum(len(row["enterprise_findings"]) for row in results),
            "case_ids": [row["case_id"] for row in hits],
            "rule_case_counts": dict(sorted(rule_counts.items())),
            "rule_ground_truth_counts": {rule: dict(sorted(value.items())) for rule, value in sorted(truths.items())},
            "rule_selection_group_counts": {rule: dict(sorted(value.items())) for rule, value in sorted(groups.items())},
        },
        "decision_effect": {
            "changed": len(changes), "changed_case_ids": [row["case_id"] for row in changes],
            "non_normal_upgrades": len(non_normal),
            "non_normal_upgrade_case_ids": [row["case_id"] for row in non_normal],
            "normal_upgrades": len(normal),
            "normal_upgrade_case_ids": [row["case_id"] for row in normal],
        },
        "correct_controls": {
            "cases": len(controls), "unchanged": len(controls) - len(control_changes),
            "decision_changes": len(control_changes),
            "changed_case_ids": [row["case_id"] for row in control_changes],
        },
        "prior_layers_equivalence": {
            "cases": len(results), "equivalent": len(results) - len(prior_diff),
            "differences": len(prior_diff), "difference_case_ids": [row["case_id"] for row in prior_diff],
        },
        "integrity": {
            "hash_mismatches": len(hash_diff), "mismatch_case_ids": [row["case_id"] for row in hash_diff],
            "regression_cases_opened": 0,
        },
        "enterprise_latency_ms": {
            "total": sum(latency), "mean": sum(latency) / len(latency) if latency else 0.0,
            "max": max(latency, default=0),
        },
    }


def classify(metrics: dict[str, Any]) -> tuple[str, dict[str, str]]:
    effect = metrics["decision_effect"]
    guards_fail = (
        metrics["prior_layers_equivalence"]["differences"]
        or metrics["integrity"]["hash_mismatches"]
        or effect["normal_upgrades"]
        or metrics["correct_controls"]["decision_changes"]
    )
    if guards_fail:
        return "revise_analyzer", {
            "takeaway": "Enterprise controls failed a normal-safety, integrity, or comparability guard.",
            "claim_update": "weakens", "baseline_relation": "not_comparable",
            "comparability": "low", "failure_mode": "evaluation", "next_action": "revise_idea",
        }
    if effect["non_normal_upgrades"]:
        return "supported_on_development_set", {
            "takeaway": "Enterprise controls rescued non-normal development cases with zero normal upgrades.",
            "claim_update": "strengthens", "baseline_relation": "better",
            "comparability": "high", "failure_mode": "none", "next_action": "continue",
        }
    return "mechanism_only_no_development_rescue", {
        "takeaway": "Enterprise controls are executable and non-regressive but add no development rescue.",
        "claim_update": "narrows", "baseline_relation": "mixed",
        "comparability": "high", "failure_mode": "direction", "next_action": "continue",
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
    development = load_jsonl(development_path)
    if len(development) != 120:
        raise EvaluationError(f"Expected 120 development cases, got {len(development)}")
    parent_path = PARENT_ROOT / "per_case_results.jsonl"
    static_path = STATIC_ROOT / "per_case_augmented.jsonl"
    sensitive_path = SENSITIVE_ROOT / "per_case_sensitive_flow.jsonl"
    untrusted_path = UNTRUSTED_ROOT / "per_case_untrusted_exec_flow.jsonl"
    parent = {str(row["case_id"]): row for row in load_jsonl(parent_path)}
    static = {str(row["case_id"]): row for row in load_jsonl(static_path)}
    sensitive = {str(row["case_id"]): row for row in load_jsonl(sensitive_path)}
    untrusted = {str(row["case_id"]): row for row in load_jsonl(untrusted_path)}

    started_at = now_iso()
    started = time.perf_counter()
    logs = [f"{started_at} run_start id={RUN_ID} development_cases=120 regression_opened=0"]
    results: list[dict[str, Any]] = []
    for row in development:
        case_id = str(row["case_id"])
        parent_row, static_row = parent.get(case_id), static.get(case_id)
        sensitive_row, untrusted_row = sensitive.get(case_id), untrusted.get(case_id)
        if not parent_row or parent_row.get("status") != "completed" or not all((static_row, sensitive_row, untrusted_row)):
            raise EvaluationError(f"Missing completed prior-layer result: {case_id}")
        case_root = (CASES_ROOT / case_id).resolve()
        if not case_root.is_dir() or case_root.parent != CASES_ROOT.resolve():
            raise EvaluationError(f"Development case missing or out of scope: {case_id}")
        expected_hash = str(row["case_tree_sha256"])
        before_hash = tree_sha256(case_root)
        if before_hash != expected_hash:
            raise EvaluationError(f"Case hash differs before analysis: {case_id}")

        static_findings, _ = analyze_skill_tree(case_root)
        sensitive_findings, _ = analyze_sensitive_flows(case_root)
        untrusted_findings, _ = analyze_untrusted_exec_flows(case_root)
        prior_findings = list(parent_row.get("finding_index") or []) + static_findings + sensitive_findings + untrusted_findings
        prior_decision = evaluate_findings(prior_findings).decision.value
        prior_equivalent = (
            rule_ids(static_findings) == rule_ids(static_row.get("aegis_findings") or [])
            and rule_ids(sensitive_findings) == rule_ids(sensitive_row.get("sensitive_flow_findings") or [])
            and rule_ids(untrusted_findings) == rule_ids(untrusted_row.get("untrusted_exec_findings") or [])
            and prior_decision == untrusted_row["post_untrusted_exec_decision"]
        )
        analysis_started = time.perf_counter()
        findings, analyzers = analyze_enterprise_controls(case_root)
        duration_ms = max(1, round((time.perf_counter() - analysis_started) * 1000))
        evaluation = evaluate_findings(prior_findings + findings)
        post_decision = evaluation.decision.value
        after_hash = tree_sha256(case_root)
        if after_hash != expected_hash:
            raise EvaluationError(f"Case hash differs after analysis: {case_id}")
        result = {
            "schema_version": "1.0", "run_id": RUN_ID, "case_id": case_id,
            "selection_group": row["selection_group"], "ground_truth": row["ground_truth"],
            "risk_labels": row.get("risk_labels") or [],
            "pre_enterprise_decision": prior_decision, "post_enterprise_decision": post_decision,
            "decision_changed": prior_decision != post_decision,
            "prior_layers_equivalent": prior_equivalent,
            "enterprise_findings": compact(findings), "enterprise_analyzers": analyzers,
            "post_enterprise_policy_trace": evaluation.trace.model_dump(mode="json"),
            "enterprise_duration_ms": duration_ms,
            "case_tree_sha256_before": before_hash, "case_tree_sha256_after": after_hash,
            "raw_text_retained": False,
        }
        results.append(result)
        logs.append(
            f"{now_iso()} case_end id={case_id} pre={prior_decision} post={post_decision} "
            f"findings={len(findings)} duration_ms={duration_ms} hash_unchanged=true"
        )

    metrics = summarize(results)
    verdict, evaluation_summary = classify(metrics)
    elapsed = round(time.perf_counter() - started, 3)
    write_jsonl(output_dir / OUTPUT_NAMES[0], results)
    write_json(output_dir / "metrics.json", metrics)
    write_json(output_dir / "evaluation_summary.json", {
        "schema_version": "1.0", "run_id": RUN_ID, "claim_verdict": verdict,
        "evaluation_summary": evaluation_summary,
        "evidence_boundary": [
            "Visible 120-case development diagnostics only.",
            "The 600-case regression set remained sealed.",
            "No sample execution, import, installation, or network fetch occurred.",
            "No raw sample text or matched values were retained.",
        ],
    })
    summary = "\n".join([
        "# Enterprise Controls v1 Summary", "", f"- verdict: `{verdict}`",
        f"- hit cases/findings: {metrics['analyzer_hits']['cases']}/{metrics['analyzer_hits']['findings']}",
        f"- non-normal upgrades: {metrics['decision_effect']['non_normal_upgrades']}",
        f"- normal upgrades: {metrics['decision_effect']['normal_upgrades']}",
        f"- prior-layer differences: {metrics['prior_layers_equivalence']['differences']}",
        f"- hash mismatches: {metrics['integrity']['hash_mismatches']}",
        "- regression opened: 0", "", evaluation_summary["takeaway"],
    ])
    (output_dir / "summary.md").write_text(summary + "\n", encoding="utf-8")
    claim = "\n".join([
        "# Claim Validation", "", "| Claim | Expected | Observed | Verdict |", "|---|---:|---:|---|",
        f"| Non-normal rescue | >=1 | {metrics['decision_effect']['non_normal_upgrades']} | {'supported' if metrics['decision_effect']['non_normal_upgrades'] else 'inconclusive'} |",
        f"| Normal upgrades | 0 | {metrics['decision_effect']['normal_upgrades']} | {'supported' if not metrics['decision_effect']['normal_upgrades'] else 'refuted'} |",
        f"| Prior differences | 0 | {metrics['prior_layers_equivalence']['differences']} | {'supported' if not metrics['prior_layers_equivalence']['differences'] else 'refuted'} |",
    ])
    (output_dir / "claim_validation.md").write_text(claim + "\n", encoding="utf-8")
    logs.append(f"{now_iso()} run_end status=completed verdict={verdict} elapsed_seconds={elapsed} regression_opened=0")
    (output_dir / "run.log").write_text("\n".join(logs) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "1.0", "run_id": RUN_ID, "status": "completed",
        "experiment_tier": "auxiliary/dev", "started_at": started_at, "completed_at": now_iso(),
        "elapsed_seconds": elapsed, "command": [sys.executable, *sys.argv], "seed": None,
        "randomness": "none; deterministic static analysis and fixed split",
        "baseline": {
            "parent_cisco_run_id": PARENT_RUN_ID, "parent_sha256": sha256_file(parent_path),
            "static_run_id": STATIC_RUN_ID, "static_sha256": sha256_file(static_path),
            "sensitive_run_id": SENSITIVE_RUN_ID, "sensitive_sha256": sha256_file(sensitive_path),
            "untrusted_run_id": UNTRUSTED_RUN_ID, "untrusted_sha256": sha256_file(untrusted_path),
            "prior_layer_differences": metrics["prior_layers_equivalence"]["differences"],
        },
        "dataset": {
            "split_id": SPLIT_ID, "development_cases": len(development),
            "development_cases_sha256": sha256_file(development_path),
            "regression_cases_opened": 0, "regression_content_inspected": False,
        },
        "analyzer": {
            "id": ANALYZER_ID, "source": "backend/analyzers/enterprise_controls.py",
            "source_sha256": sha256_file(DEMO_ROOT / "backend" / "analyzers" / "enterprise_controls.py"),
        },
        "environment": {
            "python": sys.version, "platform": platform.platform(), "gpu_required": False,
            "sample_execution": False, "sample_import": False, "sample_install": False,
            "network_fetch": False, "raw_sample_text_retained": False,
        },
        "outputs": {
            name: {"sha256": sha256_file(output_dir / name), "bytes": (output_dir / name).stat().st_size}
            for name in OUTPUT_NAMES
        },
        "claim_boundary": "Visible-development mechanism evidence only; no final-performance claim.",
    }
    write_json(output_dir / "run_manifest.json", manifest)
    artifacts = {
        name: {"sha256": sha256_file(output_dir / name), "bytes": (output_dir / name).stat().st_size}
        for name in ("PLAN.md", "CHECKLIST.md", *OUTPUT_NAMES, "run_manifest.json")
    }
    write_json(output_dir / "artifact_manifest.json", {"schema_version": "1.0", "run_id": RUN_ID, "artifacts": artifacts})
    return {"run_id": RUN_ID, "status": "completed", "claim_verdict": verdict, "metrics": metrics, "regression_cases_opened": 0}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Enterprise Controls on visible development cases")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        result = run(args.output_dir)
    except (EvaluationError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Enterprise Controls evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
