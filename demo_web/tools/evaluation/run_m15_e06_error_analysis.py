from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
PARENT = DEMO_ROOT / "artifacts" / "experiment" / "2026-09-06-m15-e01-static-ablation-v5" / "validation_scan" / "evaluated_results.jsonl"
DATA_ROOT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_m15_e01_v1" / "validation"
CONTRACT = DEMO_ROOT / "config" / "m15_e06_error_analysis_v2.json"
OUTPUT = DEMO_ROOT / "artifacts" / "analysis" / "2026-09-09-m15-e06-error-analysis-v2"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def primary_category(row: dict[str, Any]) -> str:
    values = row.get("attack_category_codes") or []
    return str(values[0]) if values else "unclassified_benchmark_label"


def error_kind(row: dict[str, Any]) -> str | None:
    label = str(row["label"])
    decision = str(row["systems"]["S5"]["decision"])
    if label == "1" and decision == "ALLOW":
        return "false_negative"
    if label == "0" and decision in {"REVIEW", "BLOCK", "UNKNOWN"}:
        return "false_positive"
    return None


def stratified_false_negatives(rows: list[dict[str, Any]], limit: int = 60) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if error_kind(row) == "false_negative":
            groups[(primary_category(row), str(row["source_id"]))].append(row)
    for values in groups.values():
        values.sort(key=lambda row: hashlib.sha256(str(row["case_id"]).encode()).hexdigest())
    selected: list[dict[str, Any]] = []
    families: set[str] = set()
    for unique_only in (True, False):
        while len(selected) < limit:
            changed = False
            for key in sorted(groups):
                values = groups[key]
                chosen_index = next((i for i, row in enumerate(values) if not unique_only or str(row["structural_family_id"]) not in families), None)
                if chosen_index is None:
                    continue
                row = values.pop(chosen_index)
                selected.append(row)
                families.add(str(row["structural_family_id"]))
                changed = True
                if len(selected) == limit:
                    break
            if not changed:
                break
    if len(selected) != limit:
        raise RuntimeError(f"Unable to select {limit} false negatives; got {len(selected)}")
    return selected


def text_for(row: dict[str, Any]) -> str:
    path = DATA_ROOT / "cases" / str(row["case_id"]) / "SKILL.md"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def intent(text: str) -> str:
    lower = text.casefold()
    if re.search(r"\b(example|test|detect|prevent|reject|avoid|security|warning|never|do not)\b", lower):
        return "defensive_example_or_prohibition"
    if re.search(r"\b(password|credential|token|secret|api key|private key|upload|exfil|send)\b", lower):
        return "sensitive_data_or_outbound_instruction"
    if re.search(r"\b(execute|command|shell|powershell|subprocess|eval|install|download|run)\b", lower):
        return "execution_or_install_instruction"
    if re.search(r"\b(if|when|unless|after|before|whenever|condition)\b", lower):
        return "conditional_workflow_instruction"
    return "general_agent_instruction"


def finding_context(text: str, system: dict[str, Any], rule_id: str, radius: int = 3) -> str:
    lines = text.splitlines()
    for item in system.get("finding_index") or []:
        if item.get("rule_id") != rule_id:
            continue
        line = (item.get("location") or {}).get("line")
        if isinstance(line, int) and line >= 1:
            start = max(0, line - 1 - radius)
            end = min(len(lines), line + radius)
            return "\n".join(lines[start:end])
    return ""


FN_CAUSES = {
    "execution_code_delivery": "implicit_execution_semantics",
    "instruction_goal_memory_manipulation": "contextual_instruction_paraphrase",
    "privilege_tool_authority_abuse": "authority_boundary_semantics",
    "resource_availability_abuse": "resource_abuse_semantics",
    "credential_access": "natural_language_sensitive_flow",
    "data_exfiltration_disclosure": "natural_language_sensitive_flow",
    "dependency_supply_chain": "dependency_instruction_semantics",
    "integrity_output_manipulation": "integrity_manipulation_semantics",
    "persistence_control": "persistence_semantics",
    "defense_evasion_obfuscation": "obfuscation_or_evasion_variant",
    "discovery_reconnaissance": "reconnaissance_semantics",
    "unclassified_benchmark_label": "label_or_context_boundary",
}


ROUTES = {
    "implicit_execution_semantics": "完整包脚本/能力图 + 动态验证；文本快照只能 REVIEW",
    "contextual_instruction_paraphrase": "语义模型与同义改写开发集",
    "authority_boundary_semantics": "政企权限/确认语义规则 + 人工复核",
    "resource_abuse_semantics": "资源滥用规则 + 动态限额验证",
    "natural_language_sensitive_flow": "敏感源到外部汇语义规则 + 动态诱饵",
    "dependency_instruction_semantics": "依赖完整性与远程安装链规则",
    "integrity_manipulation_semantics": "输出/审计完整性语义规则",
    "persistence_semantics": "持久化规则 + 隔离动态验证",
    "obfuscation_or_evasion_variant": "解码/规范化 + 模型复核",
    "reconnaissance_semantics": "敏感发现行为规则",
    "label_or_context_boundary": "人工复核标签与补充上下文",
    "defensive_or_prohibitive_context": "扩大安全语境降级规则并配套恶意反例",
    "benign_conditional_workflow": "缩小条件触发窗口，要求同窗高风险汇点",
    "materialization_or_scanner_failure": "修复输入物化/解析，保持 UNKNOWN 失败关闭",
    "static_context_scope_error": "可达性、文件角色和数据流上下文分析",
    "label_boundary_or_quoted_context": "引用/示例边界识别 + 人工复核",
    "parser_or_format_ambiguity": "文件格式识别与解析错误治理",
    "other_review_boundary": "人工复核并补充针对性正常反例",
}


def fp_cause(row: dict[str, Any], text: str, rules: set[str]) -> str:
    decision = str(row["systems"]["S5"]["decision"])
    if decision == "UNKNOWN":
        return "materialization_or_scanner_failure"
    if "AEGIS_SEMANTIC_CONDITIONAL_RISK_TRIGGER" in rules:
        local = finding_context(text, row["systems"]["S5"], "AEGIS_SEMANTIC_CONDITIONAL_RISK_TRIGGER")
        return "defensive_or_prohibitive_context" if intent(local or text) == "defensive_example_or_prohibition" else "benign_conditional_workflow"
    if "AEGIS_SEMANTIC_CONCEALED_RISKY_BEHAVIOR" in rules:
        return "label_boundary_or_quoted_context"
    if rules & {"PIPELINE_TAINT_FLOW", "AEGIS_PARTIAL_PERSISTENCE_INDICATOR"}:
        return "static_context_scope_error"
    if rules & {"FILE_MAGIC_MISMATCH", "AEGIS_STATIC_TEXT_DECODE_LOSS"}:
        return "parser_or_format_ambiguity"
    return "other_review_boundary"


def annotate(row: dict[str, Any]) -> dict[str, Any]:
    kind = error_kind(row)
    text = text_for(row)
    system = row["systems"]["S5"]
    rules = {str(item.get("rule_id") or "") for item in system.get("finding_index") or []} - {""}
    if kind == "false_negative":
        cause = FN_CAUSES.get(primary_category(row), "other_semantic_gap")
    elif kind == "false_positive":
        cause = fp_cause(row, text, rules)
    else:
        cause = None
    local_context = ""
    for candidate in ("AEGIS_SEMANTIC_CONDITIONAL_RISK_TRIGGER", "AEGIS_SEMANTIC_CONCEALED_RISKY_BEHAVIOR", "AEGIS_ML_TEXT_RISK_REVIEW"):
        local_context = finding_context(text, system, candidate)
        if local_context:
            break
    normalized = " ".join(text.split())
    return {
        "case_id": row["case_id"], "benchmark_id": row["benchmark_id"], "error_kind": kind,
        "ground_truth": "malicious" if str(row["label"]) == "1" else "benign",
        "s5_decision": system["decision"], "source_id": row["source_id"], "source_name": row["source_name"],
        "structural_family_id": row["structural_family_id"], "attack_categories": row.get("attack_category_codes") or [],
        "intent_context": intent(local_context or text) if text else "content_unavailable", "failure_cause": cause,
        "recommended_disposition": ("REVIEW" if kind == "false_negative" else "ALLOW") if kind else system["decision"],
        "recommended_route": ROUTES.get(cause, "当前案例为正确检出，用作答辩对照") if cause else "当前案例为正确检出，用作答辩对照",
        "finding_rule_ids": sorted(rules), "text_length": len(text),
        "text_sha256_verified": bool(text) and hashlib.sha256(text.encode("utf-8")).hexdigest() == row.get("skill_text_sha256"),
        "excerpt": normalized[:360], "finding_context": " ".join(local_context.split())[:600], "single_annotator": True,
    }


def representative_cases(all_rows: list[dict[str, Any]], annotations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chosen: list[tuple[str, dict[str, Any]]] = []
    used: set[str] = set()

    def take(role: str, predicate) -> None:
        candidates = sorted((row for row in all_rows if str(row["case_id"]) not in used and predicate(row)), key=lambda row: str(row["case_id"]))
        if candidates:
            chosen.append((role, candidates[0]))
            used.add(str(candidates[0]["case_id"]))

    take("成功检出_BLOCK", lambda r: str(r["label"]) == "1" and r["systems"]["S5"]["decision"] == "BLOCK")
    take("成功检出_模型增量REVIEW", lambda r: str(r["label"]) == "1" and r["systems"]["S4"]["decision"] == "ALLOW" and r["systems"]["S5"]["decision"] == "REVIEW")
    take("漏报_执行语义", lambda r: error_kind(r) == "false_negative" and primary_category(r) == "execution_code_delivery")
    take("漏报_指令操控", lambda r: error_kind(r) == "false_negative" and primary_category(r) == "instruction_goal_memory_manipulation")
    take("误报_条件语义", lambda r: error_kind(r) == "false_positive" and any(x.get("rule_id") == "AEGIS_SEMANTIC_CONDITIONAL_RISK_TRIGGER" for x in r["systems"]["S5"].get("finding_index") or []))
    take("误报_BLOCK边界", lambda r: str(r["label"]) == "0" and r["systems"]["S5"]["decision"] == "BLOCK")
    take("UNKNOWN_输入边界", lambda r: str(r["label"]) == "0" and r["systems"]["S5"]["decision"] == "UNKNOWN")
    take("成功检出_REVIEW", lambda r: str(r["label"]) == "1" and r["systems"]["S5"]["decision"] == "REVIEW")
    result = []
    annotation_map = {row["case_id"]: row for row in annotations}
    for role, row in chosen:
        item = annotation_map.get(row["case_id"]) or annotate(row)
        result.append({"role": role, **item})
    return result


def main() -> int:
    if OUTPUT.exists() and any(OUTPUT.iterdir()):
        raise RuntimeError(f"Refusing to overwrite {OUTPUT}")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    if digest(PARENT) != contract["parent_results_sha256"]:
        raise RuntimeError("Parent lockbox result hash drift")
    rows = [json.loads(line) for line in PARENT.read_text(encoding="utf-8").splitlines() if line]
    selected_raw = stratified_false_negatives(rows, 60)
    selected_raw.extend(sorted((row for row in rows if error_kind(row) == "false_positive"), key=lambda row: str(row["case_id"])))
    annotations = [annotate(row) for row in selected_raw]
    causes = Counter((row["error_kind"], row["failure_cause"]) for row in annotations)
    proposals = [
        {"error_kind": kind, "failure_cause": cause, "support_cases": count, "recommended_route": ROUTES.get(cause), "same_lockbox_retuning_forbidden": True}
        for (kind, cause), count in sorted(causes.items(), key=lambda item: (-item[1], item[0])) if count >= 5
    ]
    representatives = representative_cases(rows, annotations)
    explicit = sum(row["failure_cause"] not in {"other_semantic_gap", "other_review_boundary"} for row in annotations)
    summary = {
        "schema_version": "1.0", "parent_cases": len(rows), "false_negatives_available": sum(error_kind(r) == "false_negative" for r in rows),
        "false_positives_available": sum(error_kind(r) == "false_positive" for r in rows),
        "false_negatives_analyzed": sum(r["error_kind"] == "false_negative" for r in annotations),
        "false_positives_analyzed": sum(r["error_kind"] == "false_positive" for r in annotations),
        "analyzed_cases": len(annotations), "explicitly_classified": explicit,
        "classified_fraction": explicit / len(annotations),
        "top_false_negative_causes": [{"cause": c, "count": n} for (k, c), n in causes.most_common() if k == "false_negative"][:5],
        "top_false_positive_causes": [{"cause": c, "count": n} for (k, c), n in causes.most_common() if k == "false_positive"][:5],
        "supported_proposals": len(proposals), "representative_cases": len(representatives),
        "second_annotator": False, "cohens_kappa": None,
    }
    summary["passed"] = len(annotations) == 114 and summary["classified_fraction"] >= 0.9 and len(representatives) >= 6
    write_jsonl(OUTPUT / "sample_manifest.jsonl", [{k: row[k] for k in ("case_id", "benchmark_id", "error_kind", "source_id", "structural_family_id", "attack_categories")} for row in annotations])
    write_jsonl(OUTPUT / "annotations.jsonl", annotations)
    write_json(OUTPUT / "proposals.json", proposals)
    write_json(OUTPUT / "representative_cases.json", representatives)
    write_json(OUTPUT / "summary.json", summary)
    write_json(OUTPUT / "run_manifest.json", {
        "schema_version": "1.0", "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "contract_sha256": digest(CONTRACT), "parent_results_sha256": digest(PARENT),
        "analysis_mode": contract["analysis_mode"], "rule_changes_made": False,
    })
    report = [
        "# E06 错误分析自动汇总", "", f"- 分析：{len(annotations)} 条（漏报 60，误报/UNKNOWN 54）",
        f"- 明确归因：{explicit}/{len(annotations)}（{summary['classified_fraction']:.1%}）", f"- 答辩案例：{len(representatives)} 个", f"- 完成门：{'通过' if summary['passed'] else '未通过'}", "",
        "## 前五类漏报原因", "", "| 原因 | 数量 |", "|---|---:|",
        *[f"| {x['cause']} | {x['count']} |" for x in summary["top_false_negative_causes"]], "", "## 前五类误报原因", "", "| 原因 | 数量 |", "|---|---:|",
        *[f"| {x['cause']} | {x['count']} |" for x in summary["top_false_positive_causes"]], "",
        "> 本报告是固定量表的单标注者事后诊断。它用于解释锁箱结果和设计新实验，不是重新计算的独立性能提升。", "",
    ]
    (OUTPUT / "REPORT.md").write_text("\n".join(report), encoding="utf-8", newline="\n")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
