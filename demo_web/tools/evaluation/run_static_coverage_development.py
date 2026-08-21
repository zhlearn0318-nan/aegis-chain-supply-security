from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.analyzers.aegis_static import analyze_skill_tree  # noqa: E402
from backend.analyzers.enterprise_controls import analyze_enterprise_controls  # noqa: E402
from backend.analyzers.sensitive_flow import analyze_sensitive_flows  # noqa: E402
from backend.analyzers.static_coverage import ANALYZER_ID, analyze_static_coverage  # noqa: E402
from backend.analyzers.untrusted_exec_flow import analyze_untrusted_exec_flows  # noqa: E402
from backend.policy import evaluate_findings  # noqa: E402
from tools.datasets.prepare_skilltrustbench import tree_sha256  # noqa: E402
from tools.evaluation.run_skilltrustbench import (  # noqa: E402
    EvaluationError, load_json, load_jsonl, sha256_file, write_json, write_jsonl,
)


RUN_ID = "2026-08-22-aegis-static-coverage-dev-v2"
SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
PARENT_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
STATIC_ID = "2026-08-16-aegis-static-rules-dev-v4"
SENSITIVE_ID = "2026-08-21-aegis-sensitive-flow-dev-v1"
UNTRUSTED_ID = "2026-08-21-aegis-untrusted-exec-flow-dev-v2"
ENTERPRISE_ID = "2026-08-21-aegis-enterprise-controls-dev-v2"
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
PARENT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / PARENT_ID
STATIC_ROOT = DEMO_ROOT / "artifacts" / "experiment" / STATIC_ID
SENSITIVE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / SENSITIVE_ID
UNTRUSTED_ROOT = DEMO_ROOT / "artifacts" / "experiment" / UNTRUSTED_ID
ENTERPRISE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / ENTERPRISE_ID
CASES_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
CONTROL_GROUPS = {"control_normal_true_negative", "control_suspicious_correct", "control_malicious_correct"}
OUTPUTS = (
    "per_case_static_coverage.jsonl", "metrics.json", "evaluation_summary.json",
    "summary.md", "claim_validation.md", "run.log",
)
PROTECTED = {*OUTPUTS, "run_manifest.json", "artifact_manifest.json"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ids(findings: list[dict[str, Any]]) -> list[str]:
    return sorted(str(item["rule_id"]) for item in findings)


def compact(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for item in findings:
        evidence = str(item.get("evidence") or "")
        result.append({
            "id": item["id"], "rule_id": item["rule_id"], "severity": item["severity"],
            "analyzer": item["analyzer"], "location": item["location"],
            "coverage_code": evidence.split(";", 1)[0],
        })
    return result


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    gaps = [
        (row, finding) for row in rows for finding in row["coverage_findings"]
        if finding["rule_id"] != "AEGIS_STATIC_COVERAGE_SUMMARY"
    ]
    changes = [row for row in rows if row["decision_changed"]]
    normals = [row for row in changes if row["ground_truth"] == "normal"]
    controls = [row for row in rows if row["selection_group"] in CONTROL_GROUPS]
    control_changes = [row for row in controls if row["decision_changed"]]
    prior_diff = [row for row in rows if not row["prior_layers_equivalent"]]
    hash_diff = [row for row in rows if row["before_sha256"] != row["after_sha256"]]
    rule_counts = Counter(finding["rule_id"] for _, finding in gaps)
    latency = [row["coverage_duration_ms"] for row in rows]
    return {
        "schema_version": "1.0", "run_id": RUN_ID, "cases": len(rows),
        "coverage_summaries": sum(
            any(item["rule_id"] == "AEGIS_STATIC_COVERAGE_SUMMARY" for item in row["coverage_findings"])
            for row in rows
        ),
        "coverage_gaps": {
            "cases": len({row["case_id"] for row, _ in gaps}), "findings": len(gaps),
            "case_ids": sorted({row["case_id"] for row, _ in gaps}),
            "rule_counts": dict(sorted(rule_counts.items())),
        },
        "decision_effect": {
            "changed": len(changes), "changed_case_ids": [row["case_id"] for row in changes],
            "normal_upgrades": len(normals), "normal_upgrade_case_ids": [row["case_id"] for row in normals],
        },
        "correct_controls": {
            "cases": len(controls), "decision_changes": len(control_changes),
            "changed_case_ids": [row["case_id"] for row in control_changes],
        },
        "prior_layers_equivalence": {
            "differences": len(prior_diff), "difference_case_ids": [row["case_id"] for row in prior_diff],
        },
        "integrity": {
            "hash_mismatches": len(hash_diff), "mismatch_case_ids": [row["case_id"] for row in hash_diff],
            "regression_cases_opened": 0,
        },
        "coverage_latency_ms": {
            "total": sum(latency), "mean": sum(latency) / len(latency) if latency else 0.0,
            "max": max(latency, default=0),
        },
    }


def run(output_dir: Path) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = sorted(name for name in PROTECTED if (output_dir / name).exists())
    if existing:
        raise EvaluationError(f"Output directory already contains completed-run files: {existing}")
    split_manifest = load_json(SPLIT_ROOT / "split_manifest.json")
    if split_manifest.get("split_id") != SPLIT_ID:
        raise EvaluationError("Development split identity differs")
    development_path = SPLIT_ROOT / "development_cases.jsonl"
    development = load_jsonl(development_path)
    if len(development) != 120:
        raise EvaluationError(f"Expected 120 development cases, got {len(development)}")
    paths = {
        "parent": PARENT_ROOT / "per_case_results.jsonl",
        "static": STATIC_ROOT / "per_case_augmented.jsonl",
        "sensitive": SENSITIVE_ROOT / "per_case_sensitive_flow.jsonl",
        "untrusted": UNTRUSTED_ROOT / "per_case_untrusted_exec_flow.jsonl",
        "enterprise": ENTERPRISE_ROOT / "per_case_enterprise_controls.jsonl",
    }
    frozen = {
        name: {str(row["case_id"]): row for row in load_jsonl(path)} for name, path in paths.items()
    }
    started_at = now_iso()
    started = time.perf_counter()
    logs = [f"{started_at} run_start id={RUN_ID} development_cases=120 regression_opened=0"]
    rows: list[dict[str, Any]] = []
    for dev in development:
        case_id = str(dev["case_id"])
        prior_rows = {name: values.get(case_id) for name, values in frozen.items()}
        if any(value is None for value in prior_rows.values()) or prior_rows["parent"].get("status") != "completed":
            raise EvaluationError(f"Missing prior result: {case_id}")
        case_root = (CASES_ROOT / case_id).resolve()
        expected_hash = str(dev["case_tree_sha256"])
        before = tree_sha256(case_root)
        if before != expected_hash:
            raise EvaluationError(f"Case hash differs before analysis: {case_id}")
        static_findings, _ = analyze_skill_tree(case_root)
        sensitive_findings, _ = analyze_sensitive_flows(case_root)
        untrusted_findings, _ = analyze_untrusted_exec_flows(case_root)
        enterprise_findings, _ = analyze_enterprise_controls(case_root)
        prior_findings = (
            list(prior_rows["parent"].get("finding_index") or []) + static_findings
            + sensitive_findings + untrusted_findings + enterprise_findings
        )
        prior_decision = evaluate_findings(prior_findings).decision.value
        equivalent = (
            ids(static_findings) == ids(prior_rows["static"].get("aegis_findings") or [])
            and ids(sensitive_findings) == ids(prior_rows["sensitive"].get("sensitive_flow_findings") or [])
            and ids(untrusted_findings) == ids(prior_rows["untrusted"].get("untrusted_exec_findings") or [])
            and ids(enterprise_findings) == ids(prior_rows["enterprise"].get("enterprise_findings") or [])
            and prior_decision == prior_rows["enterprise"]["post_enterprise_decision"]
        )
        analysis_started = time.perf_counter()
        findings, analyzers = analyze_static_coverage(case_root)
        duration = max(1, round((time.perf_counter() - analysis_started) * 1000))
        evaluation = evaluate_findings(prior_findings + findings)
        after = tree_sha256(case_root)
        if after != expected_hash:
            raise EvaluationError(f"Case hash differs after analysis: {case_id}")
        row = {
            "schema_version": "1.0", "run_id": RUN_ID, "case_id": case_id,
            "selection_group": dev["selection_group"], "ground_truth": dev["ground_truth"],
            "pre_coverage_decision": prior_decision,
            "post_coverage_decision": evaluation.decision.value,
            "decision_changed": prior_decision != evaluation.decision.value,
            "prior_layers_equivalent": equivalent,
            "coverage_findings": compact(findings), "coverage_analyzers": analyzers,
            "coverage_duration_ms": duration, "before_sha256": before, "after_sha256": after,
            "raw_text_retained": False,
        }
        rows.append(row)
        logs.append(
            f"{now_iso()} case_end id={case_id} pre={prior_decision} post={evaluation.decision.value} "
            f"findings={len(findings)} duration_ms={duration} hash_unchanged=true"
        )
    metrics = summarize(rows)
    guard_failure = (
        metrics["coverage_summaries"] != 120
        or metrics["prior_layers_equivalence"]["differences"]
        or metrics["integrity"]["hash_mismatches"]
        or metrics["decision_effect"]["normal_upgrades"]
        or metrics["correct_controls"]["decision_changes"]
    )
    verdict = "revise_analyzer" if guard_failure else "supported_on_development_set"
    evaluation_summary = {
        "takeaway": (
            "Coverage proof failed a completeness or non-regression guard."
            if guard_failure else
            "All development Skills received coverage summaries without prior-layer, integrity, normal, or control regressions."
        ),
        "claim_update": "weakens" if guard_failure else "strengthens",
        "baseline_relation": "not_comparable" if guard_failure else "better",
        "comparability": "low" if guard_failure else "high",
        "failure_mode": "evaluation" if guard_failure else "none",
        "next_action": "revise_idea" if guard_failure else "continue",
    }
    elapsed = round(time.perf_counter() - started, 3)
    write_jsonl(output_dir / OUTPUTS[0], rows)
    write_json(output_dir / "metrics.json", metrics)
    write_json(output_dir / "evaluation_summary.json", {
        "schema_version": "1.0", "run_id": RUN_ID, "claim_verdict": verdict,
        "evaluation_summary": evaluation_summary,
        "evidence_boundary": ["120 visible development cases only", "600 regression cases sealed", "no sample execution or archive expansion"],
    })
    (output_dir / "summary.md").write_text(
        "\n".join([
            "# Static Coverage v1 Summary", "", f"- verdict: `{verdict}`",
            f"- summaries: {metrics['coverage_summaries']}/120",
            f"- gap cases/findings: {metrics['coverage_gaps']['cases']}/{metrics['coverage_gaps']['findings']}",
            f"- decision changes: {metrics['decision_effect']['changed']}",
            f"- normal upgrades: {metrics['decision_effect']['normal_upgrades']}",
            f"- prior differences: {metrics['prior_layers_equivalence']['differences']}",
            "- regression opened: 0", "", evaluation_summary["takeaway"], "",
        ]), encoding="utf-8"
    )
    (output_dir / "claim_validation.md").write_text(
        "\n".join([
            "# Claim Validation", "", "| Claim | Expected | Observed | Verdict |", "|---|---:|---:|---|",
            f"| Coverage summaries | 120 | {metrics['coverage_summaries']} | {'supported' if metrics['coverage_summaries'] == 120 else 'refuted'} |",
            f"| Normal upgrades | 0 | {metrics['decision_effect']['normal_upgrades']} | {'supported' if not metrics['decision_effect']['normal_upgrades'] else 'refuted'} |",
            f"| Prior differences | 0 | {metrics['prior_layers_equivalence']['differences']} | {'supported' if not metrics['prior_layers_equivalence']['differences'] else 'refuted'} |",
            "",
        ]), encoding="utf-8"
    )
    logs.append(f"{now_iso()} run_end status=completed verdict={verdict} elapsed_seconds={elapsed} regression_opened=0")
    (output_dir / "run.log").write_text("\n".join(logs) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "1.0", "run_id": RUN_ID, "status": "completed", "experiment_tier": "auxiliary/dev",
        "started_at": started_at, "completed_at": now_iso(), "elapsed_seconds": elapsed,
        "command": [sys.executable, *sys.argv], "seed": None, "randomness": "none",
        "baseline": {name: {"run_id": run_id, "sha256": sha256_file(paths[name])} for name, run_id in (
            ("parent", PARENT_ID), ("static", STATIC_ID), ("sensitive", SENSITIVE_ID),
            ("untrusted", UNTRUSTED_ID), ("enterprise", ENTERPRISE_ID),
        )},
        "dataset": {"split_id": SPLIT_ID, "development_cases": 120, "development_cases_sha256": sha256_file(development_path), "regression_cases_opened": 0},
        "analyzer": {"id": ANALYZER_ID, "source": "backend/analyzers/static_coverage.py", "source_sha256": sha256_file(DEMO_ROOT / "backend" / "analyzers" / "static_coverage.py")},
        "environment": {"python": sys.version, "platform": platform.platform(), "gpu_required": False, "sample_execution": False, "archive_expansion": False, "raw_sample_text_retained": False},
        "outputs": {name: {"sha256": sha256_file(output_dir / name), "bytes": (output_dir / name).stat().st_size} for name in OUTPUTS},
    }
    write_json(output_dir / "run_manifest.json", manifest)
    artifacts = {name: {"sha256": sha256_file(output_dir / name), "bytes": (output_dir / name).stat().st_size} for name in ("PLAN.md", "CHECKLIST.md", *OUTPUTS, "run_manifest.json")}
    write_json(output_dir / "artifact_manifest.json", {"schema_version": "1.0", "run_id": RUN_ID, "artifacts": artifacts})
    return {"run_id": RUN_ID, "status": "completed", "claim_verdict": verdict, "metrics": metrics}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate static coverage proof on visible development cases")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        result = run(args.output_dir)
    except (EvaluationError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Static coverage evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
