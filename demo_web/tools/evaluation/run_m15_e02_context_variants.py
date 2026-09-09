from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.analyzers.finding_context import (  # noqa: E402
    PROTECTED_COMPLETE_RULES,
    apply_finding_context,
)
from backend.policy import evaluate_findings, load_policy, summarize  # noqa: E402
from tools.datasets.prepare_m15_e02_real_skill_corpus import (  # noqa: E402
    DEFAULT_OUTPUT as DEFAULT_DATA_ROOT,
    sha256_file,
    verify_scan_inputs,
)


RUN_ID = "2026-09-08-m15-e02-static-false-positive-v5"
DEFAULT_RUN_ROOT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
STAGES = ("F1", "F2", "F3")
CISCO_COMPLETE_COMMAND_RULES = {
    "COMMAND_INJECTION_EVAL",
    "COMMAND_INJECTION_JS_CHILD_PROCESS",
    "COMMAND_INJECTION_OS_SYSTEM",
    "COMMAND_INJECTION_SUBPROCESS_SHELL_TRUE",
}


class VariantError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise VariantError(f"Expected JSON object: {path}")
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


def protected_severity_map(findings: list[dict[str, Any]]) -> dict[str, str]:
    return {
        str(item.get("id")): str(item.get("severity"))
        for item in findings
        if str(item.get("rule_id") or "") in PROTECTED_COMPLETE_RULES
    }


def generate_variants(data_root: Path, run_root: Path) -> dict[str, Any]:
    manifest_path = run_root / "context_variants_manifest.json"
    if manifest_path.exists():
        raise VariantError("Context variants are already frozen")
    verification = verify_scan_inputs(data_root)
    f0_manifest = load_json(run_root / "run_manifest.json")
    if f0_manifest.get("status") != "f0_evaluated":
        raise VariantError("A valid frozen F0 result is required")
    if f0_manifest["dataset"]["scan_input_tree_sha256"] != verification["scan_input_tree_sha256"]:
        raise VariantError("F0 dataset identity drifted")
    scan_rows = {row["case_id"]: row for row in load_jsonl(data_root / "scan_manifest.jsonl")}
    f0_rows = load_jsonl(run_root / "f0_results.jsonl")
    policy = load_policy()
    outputs: dict[str, Any] = {}
    for stage in STAGES:
        stage_rows: list[dict[str, Any]] = []
        protected_downgrades: list[str] = []
        for f0 in f0_rows:
            row = dict(f0)
            row["system"] = stage
            if f0.get("status") != "completed":
                stage_rows.append(row)
                continue
            source = scan_rows[f0["case_id"]]
            skill_root = data_root / source["local_path"]
            transformed = apply_finding_context(skill_root, f0["findings"], stage)
            before = protected_severity_map(f0["findings"])
            after = protected_severity_map(transformed)
            if before != after:
                protected_downgrades.append(f0["case_id"])
            evaluation = evaluate_findings(transformed, policy)
            row["decision"] = evaluation.decision.value
            row["policy_trace"] = evaluation.trace.model_dump(mode="json")
            row["summary"] = summarize(transformed)
            row["findings"] = transformed
            row["context_suppression_count"] = sum(
                item.get("context_disposition") == "SUPPRESSED_TO_INFO" for item in transformed
            )
            stage_rows.append(row)
        if protected_downgrades:
            raise VariantError(f"{stage} downgraded protected complete findings: {protected_downgrades}")
        output_path = run_root / f"{stage.casefold()}_results.jsonl"
        write_jsonl(output_path, stage_rows)
        outputs[output_path.name] = {
            "sha256": sha256_file(output_path),
            "decision_counts": dict(sorted(Counter(row["decision"] for row in stage_rows).items())),
            "suppressed_to_info": sum(row.get("context_suppression_count", 0) for row in stage_rows),
            "protected_complete_downgrades": 0,
        }
    after_verification = verify_scan_inputs(data_root)
    if after_verification["scan_input_tree_sha256"] != verification["scan_input_tree_sha256"]:
        raise VariantError("Dataset changed while generating variants")
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "variants_frozen_labels_not_reopened",
        "created_at": now_iso(),
        "f0_results_sha256": sha256_file(run_root / "f0_results.jsonl"),
        "dataset_scan_input_tree_sha256": verification["scan_input_tree_sha256"],
        "sample_execution": False,
        "vendor_rescans": 0,
        "labels_opened_by_variant_generation": False,
        "outputs": outputs,
    }
    write_json(manifest_path, manifest)
    return manifest


def _metrics(rows: list[dict[str, Any]], labels: dict[str, dict[str, Any]]) -> dict[str, Any]:
    joined = [{**row, **labels[row["case_id"]]} for row in rows]
    by_class: dict[str, Any] = {}
    for name in ("low_permission", "high_privilege_legitimate"):
        subset = [row for row in joined if row["workload_class"] == name]
        counts = Counter(row["decision"] for row in subset)
        by_class[name] = {
            "cases": len(subset),
            "decision_counts": dict(sorted(counts.items())),
            "allow_rate": counts["ALLOW"] / len(subset),
            "review_rate": counts["REVIEW"] / len(subset),
            "block_rate": counts["BLOCK"] / len(subset),
            "unknown_rate": counts["UNKNOWN"] / len(subset),
        }
    low = [row for row in joined if row["workload_class"] == "low_permission"]
    suppressions = [
        (row["case_id"], finding)
        for row in joined
        for finding in row["findings"]
        if finding.get("context_disposition") == "SUPPRESSED_TO_INFO"
    ]
    high_blocks: list[dict[str, Any]] = []
    for row in joined:
        if row["workload_class"] != "high_privilege_legitimate" or row["decision"] != "BLOCK":
            continue
        blockers = [
            item for item in row["findings"] if item.get("severity") in {"HIGH", "CRITICAL"}
        ]
        complete = [
            item for item in blockers
            if item.get("rule_id") in PROTECTED_COMPLETE_RULES | CISCO_COMPLETE_COMMAND_RULES
        ]
        high_blocks.append({
            "case_id": row["case_id"],
            "complete_chain_present": bool(complete),
            "blocking_rules": sorted({str(item.get("rule_id")) for item in blockers}),
            "complete_chain_rules": sorted({str(item.get("rule_id")) for item in complete}),
        })
    return {
        "decision_counts": dict(sorted(Counter(row["decision"] for row in joined).items())),
        "by_workload_class": by_class,
        "low_permission_unnecessary_non_allow_count": sum(row["decision"] in {"REVIEW", "BLOCK"} for row in low),
        "low_permission_direct_block_count": sum(row["decision"] == "BLOCK" for row in low),
        "suppressed_to_info_count": len(suppressions),
        "suppression_reason_counts": dict(sorted(Counter(
            str(finding.get("context_rule_id")) for _, finding in suppressions
        ).items())),
        "suppressed_case_count": len({case_id for case_id, _ in suppressions}),
        "high_privilege_blocks": high_blocks,
        "all_high_privilege_blocks_have_complete_chain": all(item["complete_chain_present"] for item in high_blocks),
    }


def evaluate_variants(data_root: Path, run_root: Path) -> dict[str, Any]:
    output_path = run_root / "context_variants_evaluation.json"
    if output_path.exists():
        raise VariantError("Context variants have already been evaluated")
    manifest = load_json(run_root / "context_variants_manifest.json")
    if manifest.get("status") != "variants_frozen_labels_not_reopened":
        raise VariantError("Variant outputs are not frozen")
    labels = {row["case_id"]: row for row in load_jsonl(data_root / "ground_truth" / "labels.jsonl")}
    systems = {"F0": load_jsonl(run_root / "f0_results.jsonl")}
    systems.update({stage: load_jsonl(run_root / f"{stage.casefold()}_results.jsonl") for stage in STAGES})
    metrics = {name: _metrics(rows, labels) for name, rows in systems.items()}
    f0_nonallow = metrics["F0"]["low_permission_unnecessary_non_allow_count"]
    for name in STAGES:
        current = metrics[name]["low_permission_unnecessary_non_allow_count"]
        metrics[name]["low_permission_non_allow_relative_reduction_vs_f0"] = (
            (f0_nonallow - current) / f0_nonallow if f0_nonallow else 0.0
        )
    transitions: dict[str, Any] = {}
    f0_by_id = {row["case_id"]: row for row in systems["F0"]}
    for stage in STAGES:
        transitions[stage] = dict(sorted(Counter(
            f"{f0_by_id[row['case_id']]['decision']}->{row['decision']}" for row in systems[stage]
        ).items()))
    f3 = metrics["F3"]
    acceptance = {
        "low_permission_direct_block_zero": f3["low_permission_direct_block_count"] == 0,
        "low_permission_auto_allow_at_least_80pct": f3["by_workload_class"]["low_permission"]["allow_rate"] >= 0.8,
        "high_privilege_unknown_zero": f3["by_workload_class"]["high_privilege_legitimate"]["unknown_rate"] == 0,
        "unnecessary_non_allow_relative_reduction_at_least_30pct": f3["low_permission_non_allow_relative_reduction_vs_f0"] >= 0.3,
        "suppressed_findings_retained_as_info": f3["suppressed_to_info_count"] > 0,
        "protected_complete_high_downgrades_zero": all(
            manifest["outputs"][f"{stage.casefold()}_results.jsonl"]["protected_complete_downgrades"] == 0
            for stage in STAGES
        ),
        "all_high_privilege_blocks_have_complete_chain": f3["all_high_privilege_blocks_have_complete_chain"],
    }
    result = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "evaluated_at": now_iso(),
        "metrics": metrics,
        "transitions_vs_f0": transitions,
        "acceptance_real_skill_corpus": acceptance,
        "real_skill_acceptance_passed": all(acceptance.values()),
        "malicious_regression_status": "PENDING",
        "product_activation_status": "NOT_AUTHORIZED_UNTIL_MALICIOUS_REGRESSION_PASSES",
    }
    write_json(output_path, result)
    return result


def report(run_root: Path) -> str:
    evaluation = load_json(run_root / "context_variants_evaluation.json")
    metrics = evaluation["metrics"]
    lines = [
        "# M15 E02 真实 Skill 静态误报治理阶段结果",
        "",
        "> 说明：真实合法 Skill 兼容性门已评测；恶意回归门尚未完成，因此当前候选不得直接进入产品。",
        "",
        "## F0–F3 结果",
        "",
        "| 系统 | 总判定 | 低权限 ALLOW | 低权限 BLOCK | 低权限 UNKNOWN | 低权限无必要非放行 | INFO 保留 |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in ("F0", *STAGES):
        item = metrics[name]
        low = item["by_workload_class"]["low_permission"]
        lines.append(
            f"| {name} | {item['decision_counts']} | {low['allow_rate']:.1%} | {low['block_rate']:.1%} | "
            f"{low['unknown_rate']:.1%} | {item['low_permission_unnecessary_non_allow_count']} | {item['suppressed_to_info_count']} |"
        )
    f3 = metrics["F3"]
    lines.extend([
        "",
        "## 当前结论",
        "",
        f"- 低权限自动放行率：{f3['by_workload_class']['low_permission']['allow_rate']:.1%}；",
        f"- 低权限直接阻断：{f3['low_permission_direct_block_count']}；",
        f"- 无必要 REVIEW/BLOCK 相对 F0 减少：{f3['low_permission_non_allow_relative_reduction_vs_f0']:.1%}；",
        f"- 被抑制发现仍以 INFO 留存：{f3['suppressed_to_info_count']} 条；",
        f"- 完整高风险规则被降级：0 条；",
        f"- 真实 Skill 兼容性接受门：{'通过' if evaluation['real_skill_acceptance_passed'] else '未通过'}；",
        "- 恶意回归门：待运行。只有回归下降不超过 2 个百分点后，才能决定是否接入 OpenClaw 正式准入。",
        "",
        "## 高权限直接阻断解释",
        "",
    ])
    for item in f3["high_privilege_blocks"]:
        lines.append(
            f"- `{item['case_id']}`：完整链规则 {', '.join(item['complete_chain_rules']) or '无'}；"
            f"其余阻断规则 {', '.join(item['blocking_rules']) or '无'}。"
        )
    text = "\n".join(lines) + "\n"
    path = run_root / "REPORT_CONTEXT_VARIANTS.md"
    path.write_text(text, encoding="utf-8", newline="\n")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and evaluate M15 E02 F1-F3 variants")
    parser.add_argument("command", choices=("generate", "evaluate", "report"))
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            result: Any = generate_variants(args.data_root.resolve(), args.run_root.resolve())
        elif args.command == "evaluate":
            result = evaluate_variants(args.data_root.resolve(), args.run_root.resolve())
        else:
            result = {"report": str((args.run_root / "REPORT_CONTEXT_VARIANTS.md").resolve()), "text": report(args.run_root.resolve())}
    except (VariantError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
