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
from backend.analyzers.filesystem_context import (  # noqa: E402
    ANALYZER_ID,
    analyze_filesystem_context,
)
from backend.analyzers.network_context import analyze_network_context  # noqa: E402
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


RUN_ID = "2026-08-18-aegis-filesystem-context-dev-v1"
SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
PARENT_RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
STATIC_BASELINE_RUN_ID = "2026-08-16-aegis-static-rules-dev-v4"
NETWORK_BASELINE_RUN_ID = "2026-08-18-aegis-network-context-dev-v3"
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
PARENT_RUN_ROOT = DEMO_ROOT / "artifacts" / "analysis" / PARENT_RUN_ID
STATIC_BASELINE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / STATIC_BASELINE_RUN_ID
NETWORK_BASELINE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / NETWORK_BASELINE_RUN_ID
CASES_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
SELECTED_GROUPS = {
    "fp_filesystem_context",
    "control_normal_true_negative",
    "control_suspicious_correct",
    "control_malicious_correct",
}
PROTECTED_OUTPUTS = {
    "per_case_context.jsonl", "metrics.json", "metrics.md",
    "evaluation_summary.json", "run_manifest.json", "artifact_manifest.json",
    "run.log", "bash.log", "runlog.summary.md", "summary.md", "claim_validation.md",
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


def has_rule(row: dict[str, Any], *rule_ids: str) -> bool:
    expected = set(rule_ids)
    return any(
        finding["rule_id"] in expected for finding in row["filesystem_context_findings"]
    )


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    target = [row for row in results if row["selection_group"] == "fp_filesystem_context"]
    controls = [row for row in results if row["selection_group"].startswith("control_")]
    rule_counts = Counter(
        finding["rule_id"]
        for row in results for finding in row["filesystem_context_findings"]
    )
    rule_groups: dict[str, Counter[str]] = defaultdict(Counter)
    for row in results:
        for finding in row["filesystem_context_findings"]:
            rule_groups[finding["rule_id"]][row["selection_group"]] += 1
    decision_changes = [row for row in results if row["decision_changed"]]
    static_differences = [row for row in results if not row["static_baseline_equivalent"]]
    hash_differences = [row for row in results if not row["case_hash_unchanged"]]
    target_covered = [row for row in target if row["filesystem_context_findings"]]

    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "scope": "filesystem_context_auxiliary_development_diagnostics",
        "cases": len(results),
        "selection_group_counts": dict(sorted(Counter(
            row["selection_group"] for row in results
        ).items())),
        "filesystem_false_positive_context": {
            "cases": len(target),
            "with_context_evidence": len(target_covered),
            "coverage": len(target_covered) / len(target) if target else 0.0,
            "declared_filesystem_capability": sum(has_rule(
                row,
                "AEGIS_CONTEXT_FILESYSTEM_CAPABILITY_DECLARED",
                "AEGIS_CONTEXT_FILESYSTEM_CAPABILITY_DECLARED_NO_DIRECT_PRIMITIVE",
            ) for row in target),
            "undeclared_filesystem_behavior": sum(has_rule(
                row, "AEGIS_CONTEXT_FILESYSTEM_BEHAVIOR_UNDECLARED"
            ) for row in target),
            "read_only_behavior": sum(has_rule(
                row, "AEGIS_CONTEXT_READ_ONLY_FILESYSTEM_BEHAVIOR"
            ) for row in target),
            "write_behavior_declared": sum(has_rule(
                row, "AEGIS_CONTEXT_FILE_WRITE_BEHAVIOR_DECLARED"
            ) for row in target),
            "write_behavior_not_explicitly_declared": sum(has_rule(
                row, "AEGIS_CONTEXT_FILE_WRITE_BEHAVIOR_NOT_EXPLICITLY_DECLARED"
            ) for row in target),
            "workspace_or_temp_path": sum(has_rule(
                row, "AEGIS_CONTEXT_WORKSPACE_OR_TEMP_PATH"
            ) for row in target),
            "sensitive_path_access": sum(has_rule(
                row, "AEGIS_CONTEXT_SENSITIVE_PATH_ACCESS"
            ) for row in target),
            "system_path_access": sum(has_rule(
                row, "AEGIS_CONTEXT_SYSTEM_PATH_ACCESS"
            ) for row in target),
            "overwrite_capable_write": sum(has_rule(
                row, "AEGIS_CONTEXT_OVERWRITE_CAPABLE_FILE_WRITE"
            ) for row in target),
            "destructive_mutation_declared": sum(has_rule(
                row, "AEGIS_CONTEXT_DESTRUCTIVE_FILE_MUTATION_DECLARED"
            ) for row in target),
            "destructive_mutation_not_explicitly_declared": sum(has_rule(
                row, "AEGIS_CONTEXT_DESTRUCTIVE_FILE_MUTATION_NOT_EXPLICITLY_DECLARED"
            ) for row in target),
            "recursive_mutation": sum(has_rule(
                row, "AEGIS_CONTEXT_RECURSIVE_FILESYSTEM_MUTATION"
            ) for row in target),
            "path_containment_guard": sum(has_rule(
                row, "AEGIS_CONTEXT_PATH_CONTAINMENT_GUARD"
            ) for row in target),
        },
        "policy_safety": {
            "policy_changing_filesystem_findings": sum(
                finding["severity"] != "INFO"
                for row in results for finding in row["filesystem_context_findings"]
            ),
            "decision_invariance_cases": len(results),
            "decision_unchanged": len(results) - len(decision_changes),
            "decision_changed": len(decision_changes),
            "changed_case_ids": [row["case_id"] for row in decision_changes],
        },
        "controls": {
            "cases": len(controls),
            "unchanged": sum(not row["decision_changed"] for row in controls),
            "changed": sum(row["decision_changed"] for row in controls),
        },
        "static_baseline_equivalence": {
            "cases": len(results),
            "equivalent": len(results) - len(static_differences),
            "differences": len(static_differences),
            "difference_case_ids": [row["case_id"] for row in static_differences],
        },
        "sample_integrity": {
            "cases": len(results),
            "unchanged": len(results) - len(hash_differences),
            "differences": len(hash_differences),
            "difference_case_ids": [row["case_id"] for row in hash_differences],
        },
        "filesystem_rule_case_counts": dict(sorted(rule_counts.items())),
        "filesystem_rule_selection_group_counts": {
            rule: dict(sorted(groups.items())) for rule, groups in sorted(rule_groups.items())
        },
        "filesystem_context_latency_ms": {
            "total": sum(row["filesystem_context_duration_ms"] for row in results),
            "mean": (
                sum(row["filesystem_context_duration_ms"] for row in results) / len(results)
                if results else 0.0
            ),
            "max": max((row["filesystem_context_duration_ms"] for row in results), default=0),
        },
        "regression_cases_opened": 0,
    }


def metrics_markdown(metrics: dict[str, Any]) -> str:
    target = metrics["filesystem_false_positive_context"]
    safety = metrics["policy_safety"]
    controls = metrics["controls"]
    integrity = metrics["sample_integrity"]
    latency = metrics["filesystem_context_latency_ms"]
    return "\n".join([
        "# Aegis Filesystem Context v1 指标",
        "",
        f"- 固定开发样本：{metrics['cases']}（文件系统误报 8，正确对照 20）",
        f"- 目标上下文覆盖：{target['with_context_evidence']}/{target['cases']}（{target['coverage']:.2%}）",
        f"- 声明/未声明：{target['declared_filesystem_capability']}/{target['undeclared_filesystem_behavior']}",
        f"- 只读/声明写入/未显式声明写入：{target['read_only_behavior']}/{target['write_behavior_declared']}/{target['write_behavior_not_explicitly_declared']}",
        f"- 普通工作区或临时路径/敏感路径/系统路径：{target['workspace_or_temp_path']}/{target['sensitive_path_access']}/{target['system_path_access']}",
        f"- 覆盖能力/删除或移除/递归修改/路径边界保护：{target['overwrite_capable_write']}/{target['destructive_mutation_declared'] + target['destructive_mutation_not_explicitly_declared']}/{target['recursive_mutation']}/{target['path_containment_guard']}",
        f"- 非 INFO Finding：{safety['policy_changing_filesystem_findings']}",
        f"- 决策不变：{safety['decision_unchanged']}/{safety['decision_invariance_cases']}",
        f"- 正确对照不变：{controls['unchanged']}/{controls['cases']}",
        f"- 样本树哈希不变：{integrity['unchanged']}/{integrity['cases']}",
        f"- 平均/最大分析耗时：{latency['mean']:.2f}/{latency['max']} ms",
        "- 回归样本正文打开数：0",
        "",
    ])


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
    counts = Counter(row["selection_group"] for row in development)
    if len(development) != 28 or counts["fp_filesystem_context"] != 8:
        raise EvaluationError(
            f"Expected 28 selected cases including 8 filesystem false positives, got {len(development)}/{counts['fp_filesystem_context']}"
        )

    parent_results_path = PARENT_RUN_ROOT / "per_case_results.jsonl"
    parent_results = {row["case_id"]: row for row in load_jsonl(parent_results_path)}
    static_results_path = STATIC_BASELINE_ROOT / "per_case_augmented.jsonl"
    static_results = {row["case_id"]: row for row in load_jsonl(static_results_path)}

    started_at = now_iso()
    started = time.perf_counter()
    log_lines = [
        f"{started_at} run_start id={RUN_ID} selected_cases=28 regression_opened=0"
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
            raise EvaluationError(f"Case hash differs before filesystem context analysis: {case_id}")

        cisco_findings = list(parent.get("finding_index") or [])
        static_findings, _ = analyze_skill_tree(case_root)
        current_static_rules = sorted(str(item["rule_id"]) for item in static_findings)
        frozen_static_rules = sorted(
            str(item["rule_id"]) for item in static_baseline.get("aegis_findings") or []
        )
        static_decision = evaluate_findings(cisco_findings + static_findings).decision.value
        static_equivalent = (
            static_decision == static_baseline["enhanced_decision"]
            and current_static_rules == frozen_static_rules
        )

        network_findings, network_analyzers = analyze_network_context(
            case_root, cisco_findings
        )
        pre_filesystem_findings = cisco_findings + static_findings + network_findings
        pre_filesystem_decision = evaluate_findings(pre_filesystem_findings).decision.value

        context_started = time.perf_counter()
        filesystem_findings, filesystem_analyzers = analyze_filesystem_context(
            case_root, cisco_findings
        )
        context_duration_ms = max(
            1, round((time.perf_counter() - context_started) * 1000)
        )
        if any(finding["severity"] != "INFO" for finding in filesystem_findings):
            raise EvaluationError(
                f"Filesystem context analyzer emitted policy-changing severity: {case_id}"
            )
        evaluation = evaluate_findings(pre_filesystem_findings + filesystem_findings)
        post_filesystem_decision = evaluation.decision.value
        after_hash = tree_sha256(case_root)
        hash_unchanged = before_hash == after_hash == expected_hash
        if not hash_unchanged:
            raise EvaluationError(f"Case hash differs after context analysis: {case_id}")

        result = {
            "schema_version": "1.0",
            "run_id": RUN_ID,
            "case_id": case_id,
            "selection_group": selected["selection_group"],
            "ground_truth": selected["ground_truth"],
            "risk_labels": selected.get("risk_labels") or [],
            "pre_filesystem_decision": pre_filesystem_decision,
            "post_filesystem_decision": post_filesystem_decision,
            "decision_changed": pre_filesystem_decision != post_filesystem_decision,
            "static_baseline_equivalent": static_equivalent,
            "network_context_finding_count": len(network_findings),
            "network_context_analyzers": network_analyzers,
            "filesystem_context_findings": compact_findings(filesystem_findings),
            "filesystem_context_analyzers": filesystem_analyzers,
            "post_filesystem_policy_trace": evaluation.trace.model_dump(mode="json"),
            "filesystem_context_duration_ms": context_duration_ms,
            "case_tree_sha256_before": before_hash,
            "case_tree_sha256_after": after_hash,
            "case_hash_unchanged": hash_unchanged,
            "raw_text_retained": False,
        }
        results.append(result)
        log_lines.append(
            f"{now_iso()} case_end id={case_id} pre={pre_filesystem_decision} "
            f"post={post_filesystem_decision} filesystem_findings={len(filesystem_findings)} "
            f"context_duration_ms={context_duration_ms} hash_unchanged=true"
        )

    metrics = summarize(results)
    if metrics["static_baseline_equivalence"]["differences"]:
        raise EvaluationError("Current Aegis Static results differ from accepted v4 baseline")
    elapsed_seconds = round(time.perf_counter() - started, 3)
    target = metrics["filesystem_false_positive_context"]
    supported = (
        target["with_context_evidence"] == 8
        and target["declared_filesystem_capability"] == 7
        and target["undeclared_filesystem_behavior"] == 1
        and metrics["policy_safety"]["policy_changing_filesystem_findings"] == 0
        and metrics["policy_safety"]["decision_changed"] == 0
        and metrics["controls"]["unchanged"] == 20
        and metrics["static_baseline_equivalence"]["differences"] == 0
        and metrics["sample_integrity"]["differences"] == 0
        and metrics["regression_cases_opened"] == 0
    )
    verdict = "supported_on_development_set" if supported else "revise_context_model"

    write_jsonl(output_dir / "per_case_context.jsonl", results)
    write_json(output_dir / "metrics.json", metrics)
    (output_dir / "metrics.md").write_text(metrics_markdown(metrics), encoding="utf-8")
    evaluation_summary = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "claim_verdict": verdict,
        "evaluation_summary": {
            "takeaway": (
                f"INFO-only filesystem context covered {target['with_context_evidence']}/8 target development cases with {metrics['policy_safety']['decision_changed']}/28 decision changes."
            ),
            "claim_update": "strengthens" if supported else "weakens",
            "baseline_relation": "mixed" if supported else "not_comparable",
            "comparability": "high",
            "failure_mode": "none" if supported else "evaluation",
            "next_action": "continue" if supported else "revise_idea",
        },
        "evidence_boundary": [
            "The 28 cases are selected development diagnostics, not an independent performance benchmark.",
            "Filesystem context findings are INFO-only and do not suppress, downgrade, or replace Cisco findings.",
            "Path correlations are bounded static co-occurrence and do not prove runtime path binding or data flow.",
            "No regression sample content was opened; no sample was executed, imported, installed, or fetched from the network.",
        ],
    }
    write_json(output_dir / "evaluation_summary.json", evaluation_summary)

    claim_validation = "\n".join([
        "# Claim validation",
        "",
        "| Claim | Metric | Expected | Observed | Verdict |",
        "|---|---|---:|---:|---|",
        f"| 目标样本获得文件系统上下文 | target coverage | 8/8 | {target['with_context_evidence']}/8 | {'supported' if target['with_context_evidence'] == 8 else 'refuted'} |",
        f"| 声明识别与冻结人工特征一致 | declared / undeclared | 7 / 1 | {target['declared_filesystem_capability']} / {target['undeclared_filesystem_behavior']} | {'supported' if target['declared_filesystem_capability'] == 7 and target['undeclared_filesystem_behavior'] == 1 else 'refuted'} |",
        f"| 新层不改变准入决策 | decision changed | 0/28 | {metrics['policy_safety']['decision_changed']}/28 | {'supported' if metrics['policy_safety']['decision_changed'] == 0 else 'refuted'} |",
        f"| 正确对照不回退 | controls unchanged | 20/20 | {metrics['controls']['unchanged']}/20 | {'supported' if metrics['controls']['unchanged'] == 20 else 'refuted'} |",
        f"| 既有 Static v4 可比 | static differences | 0/28 | {metrics['static_baseline_equivalence']['differences']}/28 | {'supported' if metrics['static_baseline_equivalence']['differences'] == 0 else 'refuted'} |",
        f"| 样本保持只读 | hash differences | 0/28 | {metrics['sample_integrity']['differences']}/28 | {'supported' if metrics['sample_integrity']['differences'] == 0 else 'refuted'} |",
        "",
        "边界：这些结论只支持开发集上的解释机制，不支持‘误报率已经下降’或‘命中样本已被证明安全’。",
        "",
    ])
    (output_dir / "claim_validation.md").write_text(claim_validation, encoding="utf-8")

    summary = "\n".join([
        "# Aegis Filesystem Context v1 开发实验总结",
        "",
        f"- 状态：{'success' if supported else 'partial'}；结论：`{verdict}`。",
        f"- 目标覆盖：{target['with_context_evidence']}/8；决策变化：{metrics['policy_safety']['decision_changed']}/28；正确对照不变：{metrics['controls']['unchanged']}/20。",
        f"- Static v4 差异：{metrics['static_baseline_equivalence']['differences']}；样本哈希差异：{metrics['sample_integrity']['differences']}；回归读取：0。",
        "- 解释：新增层能够区分声明/未声明读写、普通/敏感路径以及覆盖、删除、递归修改和路径边界保护，但不改变门禁。",
        "- 限制：静态共现不等于精确路径绑定或真实数据流；开发样本不能代表独立回归性能。",
        f"- 下一步：{'冻结 v1 并开发 command context INFO-only 证据。' if supported else '仅在固定 8 条目标开发样本上校准并使用新 run id。'}",
        "",
    ])
    (output_dir / "summary.md").write_text(summary, encoding="utf-8")

    log_lines.append(
        f"{now_iso()} run_end status={'completed' if supported else 'partial'} "
        f"elapsed_seconds={elapsed_seconds} target_coverage={target['with_context_evidence']}/8 "
        f"decision_changes={metrics['policy_safety']['decision_changed']} regression_opened=0"
    )
    log_text = "\n".join(log_lines) + "\n"
    (output_dir / "run.log").write_text(log_text, encoding="utf-8")
    (output_dir / "bash.log").write_text(
        "# bash_exec unavailable in this Codex runtime; equivalent exec_command run events follow.\n"
        + log_text,
        encoding="utf-8",
    )
    (output_dir / "runlog.summary.md").write_text(
        "\n".join([
            "# Run log summary",
            "",
            f"- start: {started_at}",
            f"- elapsed: {elapsed_seconds} seconds",
            "- command: " + " ".join([sys.executable, *sys.argv]),
            "- selected cases: 28; regression opened: 0",
            f"- final status: {'completed' if supported else 'partial'}",
            "- execution interface: exec_command (bash_exec/artifact interfaces unavailable)",
            "",
        ]),
        encoding="utf-8",
    )

    output_names = [
        "per_case_context.jsonl", "metrics.json", "metrics.md", "evaluation_summary.json",
        "run.log", "bash.log", "runlog.summary.md", "summary.md", "claim_validation.md",
    ]
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "completed" if supported else "partial",
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
            "aegis_network_context_run_id": NETWORK_BASELINE_RUN_ID,
            "aegis_network_metrics_sha256": sha256_file(NETWORK_BASELINE_ROOT / "metrics.json"),
            "static_equivalence_differences": metrics["static_baseline_equivalence"]["differences"],
        },
        "dataset": {
            "split_id": SPLIT_ID,
            "development_selection": sorted(SELECTED_GROUPS),
            "selected_cases": len(development),
            "filesystem_false_positive_cases": 8,
            "correct_controls": 20,
            "development_cases_sha256": sha256_file(development_path),
            "regression_cases_opened": 0,
            "regression_content_inspected": False,
        },
        "analyzer": {
            "id": ANALYZER_ID,
            "source": "backend/analyzers/filesystem_context.py",
            "source_sha256": sha256_file(
                DEMO_ROOT / "backend" / "analyzers" / "filesystem_context.py"
            ),
            "policy_effect": "INFO-only; no suppression, severity mutation, or gate change",
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "gpu_used": False,
            "docker_used": False,
            "network_fetch": False,
            "sample_execution": False,
            "sample_import": False,
            "sample_install": False,
            "raw_sample_text_retained": False,
            "execution_interface": "exec_command; required bash_exec/artifact interfaces unavailable",
        },
        "outputs": {
            name: {
                "sha256": sha256_file(output_dir / name),
                "bytes": (output_dir / name).stat().st_size,
            }
            for name in output_names
        },
        "claim_boundary": "Selected development mechanism evidence only; no false-positive-rate reduction or final-performance claim.",
        "next_action": "command_context_info_only" if supported else "filesystem_context_calibration",
    }
    write_json(output_dir / "run_manifest.json", manifest)
    artifact_manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "canonical_manifest": "run_manifest.json",
        "plan": "PLAN.md",
        "checklist": "CHECKLIST.md",
        "evidence_files": {
            name: {
                "sha256": sha256_file(output_dir / name),
                "bytes": (output_dir / name).stat().st_size,
            }
            for name in [*output_names, "run_manifest.json", "PLAN.md", "CHECKLIST.md"]
        },
    }
    write_json(output_dir / "artifact_manifest.json", artifact_manifest)

    return {
        "run_id": RUN_ID,
        "status": manifest["status"],
        "selected_cases": len(results),
        "regression_cases_opened": 0,
        "metrics": metrics,
        "output_dir": str(output_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate INFO-only Aegis filesystem context on selected development cases"
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        result = run(args.output_dir)
    except (EvaluationError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(
            f"Filesystem context evaluation failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
