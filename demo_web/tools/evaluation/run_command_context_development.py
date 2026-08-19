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
from backend.analyzers.command_context import ANALYZER_ID, analyze_command_context  # noqa: E402
from backend.analyzers.filesystem_context import analyze_filesystem_context  # noqa: E402
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


RUN_ID = "2026-08-18-aegis-command-context-dev-v1"
SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
PARENT_RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
STATIC_BASELINE_RUN_ID = "2026-08-16-aegis-static-rules-dev-v4"
NETWORK_BASELINE_RUN_ID = "2026-08-18-aegis-network-context-dev-v3"
FILESYSTEM_BASELINE_RUN_ID = "2026-08-18-aegis-filesystem-context-dev-v2"
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
PARENT_RUN_ROOT = DEMO_ROOT / "artifacts" / "analysis" / PARENT_RUN_ID
STATIC_BASELINE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / STATIC_BASELINE_RUN_ID
NETWORK_BASELINE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / NETWORK_BASELINE_RUN_ID
FILESYSTEM_BASELINE_ROOT = DEMO_ROOT / "artifacts" / "experiment" / FILESYSTEM_BASELINE_RUN_ID
CASES_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
SELECTED_GROUPS = {
    "fp_command_context",
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
        finding["rule_id"] in expected for finding in row["command_context_findings"]
    )


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    target = [row for row in results if row["selection_group"] == "fp_command_context"]
    controls = [row for row in results if row["selection_group"].startswith("control_")]
    rule_counts = Counter(
        finding["rule_id"] for row in results for finding in row["command_context_findings"]
    )
    rule_groups: dict[str, Counter[str]] = defaultdict(Counter)
    for row in results:
        for finding in row["command_context_findings"]:
            rule_groups[finding["rule_id"]][row["selection_group"]] += 1
    decision_changes = [row for row in results if row["decision_changed"]]
    static_differences = [row for row in results if not row["static_baseline_equivalent"]]
    hash_differences = [row for row in results if not row["case_hash_unchanged"]]
    target_covered = [row for row in target if row["command_context_findings"]]

    target_rule_metrics = {
        "declared_command_capability": (
            "AEGIS_CONTEXT_COMMAND_CAPABILITY_DECLARED",
            "AEGIS_CONTEXT_COMMAND_CAPABILITY_DECLARED_NO_DIRECT_PRIMITIVE",
        ),
        "undeclared_command_behavior": ("AEGIS_CONTEXT_COMMAND_BEHAVIOR_UNDECLARED",),
        "process_import_without_call": ("AEGIS_CONTEXT_PROCESS_API_IMPORTED_WITHOUT_CALL",),
        "security_test_fixture": ("AEGIS_CONTEXT_SECURITY_TEST_FIXTURE",),
        "dangerous_text_in_test_fixture": ("AEGIS_CONTEXT_DANGEROUS_COMMAND_TEXT_IN_TEST_FIXTURE",),
        "argument_vector_call": ("AEGIS_CONTEXT_ARGUMENT_VECTOR_PROCESS_CALL",),
        "shell_string_call": ("AEGIS_CONTEXT_SHELL_STRING_PROCESS_CALL",),
        "shell_script_workflow": ("AEGIS_CONTEXT_SHELL_SCRIPT_WORKFLOW",),
        "fixed_executable": ("AEGIS_CONTEXT_FIXED_EXECUTABLE_PROCESS_CALL",),
        "dynamic_executable": ("AEGIS_CONTEXT_DYNAMIC_EXECUTABLE_PROCESS_CALL",),
        "stdin_channel": ("AEGIS_CONTEXT_COMMAND_INPUT_VIA_STDIN",),
        "user_input_near_process": ("AEGIS_CONTEXT_USER_INPUT_NEAR_PROCESS_CALL",),
        "environment_near_process": ("AEGIS_CONTEXT_ENVIRONMENT_INPUT_NEAR_PROCESS_CALL",),
        "file_input_near_process": ("AEGIS_CONTEXT_FILE_INPUT_NEAR_PROCESS_CALL",),
        "sanitization_guard": ("AEGIS_CONTEXT_COMMAND_SANITIZATION_GUARD",),
        "read_only_system_command": ("AEGIS_CONTEXT_READ_ONLY_SYSTEM_COMMAND",),
        "named_business_tool": ("AEGIS_CONTEXT_NAMED_BUSINESS_TOOL_COMMAND",),
        "quoted_shell_variable": ("AEGIS_CONTEXT_QUOTED_SHELL_VARIABLE",),
        "download_command": ("AEGIS_CONTEXT_DOWNLOAD_COMMAND_PRESENT",),
        "destructive_command": ("AEGIS_CONTEXT_DESTRUCTIVE_COMMAND_PRESENT",),
        "privileged_command": ("AEGIS_CONTEXT_PRIVILEGED_COMMAND_PRESENT",),
        "persistence_command": ("AEGIS_CONTEXT_PERSISTENCE_COMMAND_PRESENT",),
        "package_install_command": ("AEGIS_CONTEXT_PACKAGE_INSTALL_COMMAND_PRESENT",),
    }
    mechanism_counts = {
        metric: sum(has_rule(row, *rules) for row in target)
        for metric, rules in target_rule_metrics.items()
    }
    mechanism_checks = {
        "import_only_present": mechanism_counts["process_import_without_call"] >= 1,
        "security_fixture_present": mechanism_counts["security_test_fixture"] >= 3,
        "argument_vector_present": mechanism_counts["argument_vector_call"] >= 2,
        "shell_string_present": mechanism_counts["shell_string_call"] >= 1,
        "shell_script_present": mechanism_counts["shell_script_workflow"] >= 1,
    }

    return {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "scope": "command_context_auxiliary_development_diagnostics",
        "cases": len(results),
        "selection_group_counts": dict(sorted(Counter(
            row["selection_group"] for row in results
        ).items())),
        "command_false_positive_context": {
            "cases": len(target),
            "with_context_evidence": len(target_covered),
            "coverage": len(target_covered) / len(target) if target else 0.0,
            **mechanism_counts,
            "mechanism_checks": mechanism_checks,
            "mechanism_checks_passed": sum(mechanism_checks.values()),
            "mechanism_checks_total": len(mechanism_checks),
        },
        "policy_safety": {
            "policy_changing_command_findings": sum(
                finding["severity"] != "INFO"
                for row in results for finding in row["command_context_findings"]
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
        "command_rule_case_counts": dict(sorted(rule_counts.items())),
        "command_rule_selection_group_counts": {
            rule: dict(sorted(groups.items())) for rule, groups in sorted(rule_groups.items())
        },
        "command_context_latency_ms": {
            "total": sum(row["command_context_duration_ms"] for row in results),
            "mean": (
                sum(row["command_context_duration_ms"] for row in results) / len(results)
                if results else 0.0
            ),
            "max": max((row["command_context_duration_ms"] for row in results), default=0),
        },
        "regression_cases_opened": 0,
    }


def metrics_markdown(metrics: dict[str, Any]) -> str:
    target = metrics["command_false_positive_context"]
    safety = metrics["policy_safety"]
    controls = metrics["controls"]
    latency = metrics["command_context_latency_ms"]
    return "\n".join([
        "# Aegis Command Context v1 指标",
        "",
        f"- 固定开发样本：{metrics['cases']}（命令误报 6，正确对照 20）",
        f"- 目标上下文覆盖：{target['with_context_evidence']}/{target['cases']}（{target['coverage']:.2%}）",
        f"- 机制检查：{target['mechanism_checks_passed']}/{target['mechanism_checks_total']}",
        f"- 已声明/未声明/仅导入：{target['declared_command_capability']}/{target['undeclared_command_behavior']}/{target['process_import_without_call']}",
        f"- 安全测试夹具/测试危险文本：{target['security_test_fixture']}/{target['dangerous_text_in_test_fixture']}",
        f"- argv/shell 字符串/shell 脚本：{target['argument_vector_call']}/{target['shell_string_call']}/{target['shell_script_workflow']}",
        f"- 固定/动态可执行文件/stdin：{target['fixed_executable']}/{target['dynamic_executable']}/{target['stdin_channel']}",
        f"- 用户/环境/文件来源近邻：{target['user_input_near_process']}/{target['environment_near_process']}/{target['file_input_near_process']}",
        f"- 只读系统命令/业务工具/变量引用：{target['read_only_system_command']}/{target['named_business_tool']}/{target['quoted_shell_variable']}",
        f"- 非 INFO Finding：{safety['policy_changing_command_findings']}",
        f"- 决策不变：{safety['decision_unchanged']}/{safety['decision_invariance_cases']}",
        f"- 正确对照不变：{controls['unchanged']}/{controls['cases']}",
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
    if len(development) != 26 or counts["fp_command_context"] != 6:
        raise EvaluationError(
            f"Expected 26 selected cases including 6 command false positives, got {len(development)}/{counts['fp_command_context']}"
        )

    parent_results_path = PARENT_RUN_ROOT / "per_case_results.jsonl"
    parent_results = {row["case_id"]: row for row in load_jsonl(parent_results_path)}
    static_results_path = STATIC_BASELINE_ROOT / "per_case_augmented.jsonl"
    static_results = {row["case_id"]: row for row in load_jsonl(static_results_path)}

    started_at = now_iso()
    started = time.perf_counter()
    log_lines = [
        f"{started_at} run_start id={RUN_ID} selected_cases=26 regression_opened=0"
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
            raise EvaluationError(f"Case hash differs before command context analysis: {case_id}")

        cisco_findings = list(parent.get("finding_index") or [])
        static_findings, _ = analyze_skill_tree(case_root)
        static_decision = evaluate_findings(cisco_findings + static_findings).decision.value
        current_static_rules = sorted(str(item["rule_id"]) for item in static_findings)
        frozen_static_rules = sorted(
            str(item["rule_id"]) for item in static_baseline.get("aegis_findings") or []
        )
        static_equivalent = (
            static_decision == static_baseline["enhanced_decision"]
            and current_static_rules == frozen_static_rules
        )

        network_findings, network_analyzers = analyze_network_context(case_root, cisco_findings)
        filesystem_findings, filesystem_analyzers = analyze_filesystem_context(
            case_root, cisco_findings
        )
        pre_command_findings = (
            cisco_findings + static_findings + network_findings + filesystem_findings
        )
        pre_command_decision = evaluate_findings(pre_command_findings).decision.value

        context_started = time.perf_counter()
        command_findings, command_analyzers = analyze_command_context(
            case_root, cisco_findings
        )
        context_duration_ms = max(
            1, round((time.perf_counter() - context_started) * 1000)
        )
        if any(finding["severity"] != "INFO" for finding in command_findings):
            raise EvaluationError(
                f"Command context analyzer emitted policy-changing severity: {case_id}"
            )
        evaluation = evaluate_findings(pre_command_findings + command_findings)
        post_command_decision = evaluation.decision.value
        after_hash = tree_sha256(case_root)
        hash_unchanged = before_hash == after_hash == expected_hash
        if not hash_unchanged:
            raise EvaluationError(f"Case hash differs after command context analysis: {case_id}")

        result = {
            "schema_version": "1.0",
            "run_id": RUN_ID,
            "case_id": case_id,
            "selection_group": selected["selection_group"],
            "ground_truth": selected["ground_truth"],
            "risk_labels": selected.get("risk_labels") or [],
            "pre_command_decision": pre_command_decision,
            "post_command_decision": post_command_decision,
            "decision_changed": pre_command_decision != post_command_decision,
            "static_baseline_equivalent": static_equivalent,
            "network_context_finding_count": len(network_findings),
            "filesystem_context_finding_count": len(filesystem_findings),
            "network_context_analyzers": network_analyzers,
            "filesystem_context_analyzers": filesystem_analyzers,
            "command_context_findings": compact_findings(command_findings),
            "command_context_analyzers": command_analyzers,
            "post_command_policy_trace": evaluation.trace.model_dump(mode="json"),
            "command_context_duration_ms": context_duration_ms,
            "case_tree_sha256_before": before_hash,
            "case_tree_sha256_after": after_hash,
            "case_hash_unchanged": hash_unchanged,
            "raw_text_retained": False,
        }
        results.append(result)
        log_lines.append(
            f"{now_iso()} case_end id={case_id} pre={pre_command_decision} "
            f"post={post_command_decision} command_findings={len(command_findings)} "
            f"context_duration_ms={context_duration_ms} hash_unchanged=true"
        )

    metrics = summarize(results)
    if metrics["static_baseline_equivalence"]["differences"]:
        raise EvaluationError("Current Aegis Static results differ from accepted v4 baseline")
    elapsed_seconds = round(time.perf_counter() - started, 3)
    target = metrics["command_false_positive_context"]
    supported = (
        target["with_context_evidence"] == 6
        and target["mechanism_checks_passed"] == target["mechanism_checks_total"]
        and metrics["policy_safety"]["policy_changing_command_findings"] == 0
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
                f"INFO-only command context covered {target['with_context_evidence']}/6 target development cases with {metrics['policy_safety']['decision_changed']}/26 decision changes."
            ),
            "claim_update": "strengthens" if supported else "weakens",
            "baseline_relation": "mixed" if supported else "not_comparable",
            "comparability": "high",
            "failure_mode": "none" if supported else "evaluation",
            "next_action": "continue" if supported else "revise_idea",
        },
        "evidence_boundary": [
            "The 26 cases are selected development diagnostics, not an independent performance benchmark.",
            "Command context findings are INFO-only and do not suppress, downgrade, replace, or duplicate-upgrade Cisco/Aegis findings.",
            "Input-to-process correlations are bounded static co-occurrence and do not prove executable or argument data flow.",
            "No regression content was opened; no sample was executed, imported, installed, or fetched from the network.",
        ],
    }
    write_json(output_dir / "evaluation_summary.json", evaluation_summary)

    claim_validation = "\n".join([
        "# Claim validation",
        "",
        "| Claim | Metric | Expected | Observed | Verdict |",
        "|---|---|---:|---:|---|",
        f"| 目标样本获得命令上下文 | target coverage | 6/6 | {target['with_context_evidence']}/6 | {'supported' if target['with_context_evidence'] == 6 else 'refuted'} |",
        f"| 关键机制均被覆盖 | mechanism checks | 5/5 | {target['mechanism_checks_passed']}/5 | {'supported' if target['mechanism_checks_passed'] == 5 else 'refuted'} |",
        f"| 新层不改变准入决策 | decision changed | 0/26 | {metrics['policy_safety']['decision_changed']}/26 | {'supported' if metrics['policy_safety']['decision_changed'] == 0 else 'refuted'} |",
        f"| 正确对照不回退 | controls unchanged | 20/20 | {metrics['controls']['unchanged']}/20 | {'supported' if metrics['controls']['unchanged'] == 20 else 'refuted'} |",
        f"| Static v4 可比 | static differences | 0/26 | {metrics['static_baseline_equivalence']['differences']}/26 | {'supported' if metrics['static_baseline_equivalence']['differences'] == 0 else 'refuted'} |",
        f"| 样本保持只读 | hash differences | 0/26 | {metrics['sample_integrity']['differences']}/26 | {'supported' if metrics['sample_integrity']['differences'] == 0 else 'refuted'} |",
        "",
        "边界：这些结论只支持开发集上的解释机制，不支持误报率下降、样本安全或真实命令数据流声明。",
        "",
    ])
    (output_dir / "claim_validation.md").write_text(claim_validation, encoding="utf-8")

    summary = "\n".join([
        "# Aegis Command Context v1 开发实验总结",
        "",
        f"- 状态：{'success' if supported else 'partial'}；结论：`{verdict}`。",
        f"- 目标覆盖：{target['with_context_evidence']}/6；机制检查：{target['mechanism_checks_passed']}/5。",
        f"- 决策变化：{metrics['policy_safety']['decision_changed']}/26；正确对照不变：{metrics['controls']['unchanged']}/20。",
        f"- Static v4 差异：{metrics['static_baseline_equivalence']['differences']}；样本哈希差异：{metrics['sample_integrity']['differences']}；回归读取：0。",
        "- 解释：新增层区分仅导入、测试夹具、argv、shell 字符串、shell 脚本、参数来源和危险命令，不参与门禁。",
        "- 限制：静态共现不证明参数数据流，开发样本不能代表独立回归性能。",
        f"- 下一步：{'冻结 Command Context v1，并评估动态 fixture 与封存回归的先后顺序。' if supported else '仅在固定 6 条目标开发样本上校准并使用新 run id。'}",
        "",
    ])
    (output_dir / "summary.md").write_text(summary, encoding="utf-8")

    log_lines.append(
        f"{now_iso()} run_end status={'completed' if supported else 'partial'} "
        f"elapsed_seconds={elapsed_seconds} target_coverage={target['with_context_evidence']}/6 "
        f"mechanism_checks={target['mechanism_checks_passed']}/5 "
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
            "# Run log summary", "", f"- start: {started_at}",
            f"- elapsed: {elapsed_seconds} seconds",
            "- command: " + " ".join([sys.executable, *sys.argv]),
            "- selected cases: 26; regression opened: 0",
            f"- final status: {'completed' if supported else 'partial'}",
            "- execution interface: exec_command (bash_exec/artifact interfaces unavailable)", "",
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
            "aegis_filesystem_context_run_id": FILESYSTEM_BASELINE_RUN_ID,
            "aegis_filesystem_metrics_sha256": sha256_file(FILESYSTEM_BASELINE_ROOT / "metrics.json"),
            "static_equivalence_differences": metrics["static_baseline_equivalence"]["differences"],
        },
        "dataset": {
            "split_id": SPLIT_ID,
            "development_selection": sorted(SELECTED_GROUPS),
            "selected_cases": len(development),
            "command_false_positive_cases": 6,
            "correct_controls": 20,
            "development_cases_sha256": sha256_file(development_path),
            "regression_cases_opened": 0,
            "regression_content_inspected": False,
        },
        "analyzer": {
            "id": ANALYZER_ID,
            "source": "backend/analyzers/command_context.py",
            "source_sha256": sha256_file(
                DEMO_ROOT / "backend" / "analyzers" / "command_context.py"
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
        "claim_boundary": "Selected development mechanism evidence only; no false-positive-rate reduction, sample-safety, or command-data-flow claim.",
        "next_action": "decide_dynamic_fixture_or_sealed_regression" if supported else "command_context_calibration",
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
        description="Evaluate INFO-only Aegis command context on selected development cases"
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        result = run(args.output_dir)
    except (EvaluationError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(
            f"Command context evaluation failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
