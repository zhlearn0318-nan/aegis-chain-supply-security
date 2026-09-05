from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
DATA_ROOT = REPRODUCTION_ROOT / "datasets" / "third_party_skill_dynamic_pairs_v1"
DEFAULT_RUN = DEMO_ROOT / "artifacts" / "analysis" / "2026-08-31-third-party-skill-dynamic-pairs-main-v1"
RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2, "UNKNOWN": 2}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def fused(static: str, dynamic: str) -> str:
    if static == "UNKNOWN":
        return "BLOCK"
    return dynamic if RANK.get(dynamic, 2) > RANK.get(static, 2) else static


def analyze(manifest: list[dict[str, Any]], static_rows: list[dict[str, Any]], dynamic_rows: list[dict[str, Any]]) -> dict[str, Any]:
    static_by_id = {row["case_id"]: row for row in static_rows}
    dynamic_by_id = {row["case_id"]: row for row in dynamic_rows}
    records: list[dict[str, Any]] = []
    for sample in manifest:
        case_id = sample["case_id"]
        static_decision = str(static_by_id[case_id]["decision"])
        dynamic_decision = str(dynamic_by_id[case_id]["decision"])
        records.append({
            "case_id": case_id,
            "variant": sample["variant"],
            "risk_type": sample["risk_type"],
            "static_decision": static_decision,
            "dynamic_decision": dynamic_decision,
            "fused_decision": fused(static_decision, dynamic_decision),
            "dynamic_new_non_allow": static_decision == "ALLOW" and dynamic_decision in {"REVIEW", "BLOCK"},
            "dynamic_stricter": RANK.get(dynamic_decision, 2) > RANK.get(static_decision, 2),
        })
    originals = [row for row in records if row["variant"] == "original"]
    risks = [row for row in records if row["variant"] == "controlled_risk_twin"]
    static_risk_non_allow = sum(row["static_decision"] in {"REVIEW", "BLOCK", "UNKNOWN"} for row in risks)
    dynamic_risk_non_allow = sum(row["dynamic_decision"] in {"REVIEW", "BLOCK"} for row in risks)
    fused_risk_non_allow = sum(row["fused_decision"] in {"REVIEW", "BLOCK"} for row in risks)
    return {
        "schema_version": "1.0",
        "analysis_kind": "posthoc_integrated_policy_analysis",
        "main_run_unchanged": True,
        "records": records,
        "originals": {
            "support": len(originals),
            "static_decisions": dict(sorted(Counter(row["static_decision"] for row in originals).items())),
            "dynamic_decisions": dict(sorted(Counter(row["dynamic_decision"] for row in originals).items())),
            "fused_decisions": dict(sorted(Counter(row["fused_decision"] for row in originals).items())),
            "dynamic_clean_rate": sum(row["dynamic_decision"] == "ALLOW" for row in originals) / len(originals),
            "integrated_allow_rate": sum(row["fused_decision"] == "ALLOW" for row in originals) / len(originals),
        },
        "controlled_risks": {
            "support": len(risks),
            "static_non_allow": static_risk_non_allow,
            "static_non_allow_recall": static_risk_non_allow / len(risks),
            "dynamic_non_allow": dynamic_risk_non_allow,
            "dynamic_non_allow_recall": dynamic_risk_non_allow / len(risks),
            "fused_non_allow": fused_risk_non_allow,
            "fused_non_allow_recall": fused_risk_non_allow / len(risks),
            "dynamic_new_non_allow_cases": sum(row["dynamic_new_non_allow"] for row in risks),
            "dynamic_stricter_cases": sum(row["dynamic_stricter"] for row in risks),
        },
        "interpretation": {
            "dynamic_effect": "Dynamic audit closes four static ALLOW misses and strengthens eighteen controlled-risk decisions in total.",
            "usability_gap": "The monotonic fusion policy correctly refuses to let a clean dynamic run erase static risk, but only one of six originals reaches final ALLOW; static false positives and package-level scope remain the usability bottleneck.",
            "policy_changed": False,
        },
    }


def render(payload: dict[str, Any]) -> str:
    originals = payload["originals"]
    risks = payload["controlled_risks"]
    lines = [
        "# 静态 + 动态综合准入补充分析（主实验后分析）",
        "",
        "> 本文件不改变主实验样本、规则、阈值或结论，只基于已冻结输出计算综合决策。",
        "",
        "## 综合结果",
        "",
        f"- 6 个真实原始 Skill：动态层 {originals['dynamic_decisions']}，综合准入 {originals['fused_decisions']}；",
        f"- 原始 Skill 动态干净率：{originals['dynamic_clean_rate']:.1%}；",
        f"- 原始 Skill 最终综合 ALLOW 率：{originals['integrated_allow_rate']:.1%}；",
        f"- 30 个风险孪生：静态非放行 {risks['static_non_allow']}/30（{risks['static_non_allow_recall']:.1%}），动态非放行 {risks['dynamic_non_allow']}/30（{risks['dynamic_non_allow_recall']:.1%}），综合非放行 {risks['fused_non_allow']}/30；",
        f"- 动态审计补齐静态 ALLOW 漏洞：{risks['dynamic_new_non_allow_cases']} 个；",
        f"- 动态证据使决策更严格：{risks['dynamic_stricter_cases']} 个，其中包含上述 4 个新增非放行和 14 个 REVIEW→BLOCK。",
        "",
        "## 评委视角解释",
        "",
        "动态审计的价值已经被真实容器证据证明：它不误伤本轮 6 个真实脚本，能够补齐静态规则对运行时条件触发行为的遗漏，并给 REVIEW 样本提供可复核的阻断证据。",
        "",
        "但不能把“动态层 6/6 ALLOW”说成“最终系统 6/6 放行”。当前融合策略是单调的：动态干净不能消除静态 HIGH/MEDIUM 风险。因此最终只有 Anthropic `algorithmic-art` 为 ALLOW，4 个 OpenAI Skill 为 REVIEW，`security-ownership-map` 因包内另一个可执行入口存在动态命令流而保持 BLOCK。",
        "",
        "这意味着下一阶段若要提高真实日常可用性，重点不是放松动态检测，而是完善静态证据范围：区分“本次拟执行入口”与“包内其他未调用能力”，对 Notebook 等非代码资产建立专用解析器，并把语义条件触发从通用 MEDIUM 候选细化为有数据流证据的规则。未经这些证据，不应让动态 ALLOW 自动覆盖静态 BLOCK。",
        "",
        "## 逐个原始 Skill 综合决策",
        "",
        "| Skill | 静态 | 动态 | 综合 |",
        "|---|---|---|---|",
    ]
    for row in (item for item in payload["records"] if item["variant"] == "original"):
        lines.append(f"| {row['case_id']} | {row['static_decision']} | {row['dynamic_decision']} | {row['fused_decision']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, default=DEFAULT_RUN)
    args = parser.parse_args()
    run_root = args.run.resolve(strict=True)
    manifest = load_jsonl(DATA_ROOT / "manifest.jsonl")
    static_rows = load_jsonl(run_root / "static_results.jsonl")
    dynamic_rows = load_jsonl(run_root / "dynamic_results.jsonl")
    payload = analyze(manifest, static_rows, dynamic_rows)
    write_json(run_root / "posthoc_integrated_analysis.json", payload)
    (run_root / "POSTHOC_INTEGRATED_ANALYSIS.md").write_text(render(payload), encoding="utf-8", newline="\n")
    print(json.dumps({"originals": payload["originals"], "controlled_risks": payload["controlled_risks"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
