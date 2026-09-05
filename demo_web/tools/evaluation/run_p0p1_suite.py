from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.analyzers.skill_capability_alignment import analyze_skill_capability_alignment
from backend.analyzers.skill_semantic import analyze_skill_semantics
from backend.policy import evaluate_findings


DEFAULT_CASES = DEMO_ROOT / "config" / "p0p1_development_cases.json"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "p0p1" / "development-v1"


def _safe_root(workspace: Path, case_id: str) -> Path:
    root = workspace / case_id.lower()
    root.mkdir(parents=True, exist_ok=False)
    return root


def run(cases_path: Path, output: Path) -> dict:
    payload = json.loads(cases_path.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise ValueError("cases must be a list")
    workspace = output / "workspace"
    if output.exists():
        shutil.rmtree(output)
    workspace.mkdir(parents=True)
    prior_mode = os.environ.get("AEGIS_SEMANTIC_MODEL_MODE")
    os.environ["AEGIS_SEMANTIC_MODEL_MODE"] = "disabled"
    records: list[dict] = []
    started = time.perf_counter()
    try:
        for case in cases:
            case_id = str(case["id"])
            root = _safe_root(workspace, case_id)
            (root / "SKILL.md").write_text(str(case["manifest"]), encoding="utf-8")
            for relative, content in (case.get("files") or {}).items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(str(content), encoding="utf-8")
            semantic, _ = analyze_skill_semantics(root)
            alignment, _ = analyze_skill_capability_alignment(root)
            findings = [*semantic, *alignment]
            decision = evaluate_findings(findings).decision.value
            records.append({
                "id": case_id,
                "label": case["label"],
                "expected": case["expected"],
                "actual": decision,
                "passed": decision == case["expected"],
                "rule_ids": sorted({str(item.get("rule_id") or "") for item in findings}),
            })
    finally:
        if prior_mode is None:
            os.environ.pop("AEGIS_SEMANTIC_MODEL_MODE", None)
        else:
            os.environ["AEGIS_SEMANTIC_MODEL_MODE"] = prior_mode
        shutil.rmtree(workspace, ignore_errors=True)
    malicious = [item for item in records if item["label"] == "malicious"]
    benign = [item for item in records if item["label"] == "benign"]
    result = {
        "schema_version": "1.0",
        "suite_id": payload["suite_id"],
        "claim_boundary": payload["claim_boundary"],
        "cases": len(records),
        "passed": sum(item["passed"] for item in records),
        "exact_match_rate": sum(item["passed"] for item in records) / len(records),
        "malicious_non_allow_recall": sum(item["actual"] != "ALLOW" for item in malicious) / len(malicious),
        "benign_allow_rate": sum(item["actual"] == "ALLOW" for item in benign) / len(benign),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "records": records,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [
        "# OpenClaw Skill P0/P1 机制集结果",
        "",
        f"- 用例：{result['cases']}",
        f"- 精确决策匹配：{result['passed']}/{result['cases']}（{result['exact_match_rate']:.1%}）",
        f"- 恶意/可疑非放行召回：{result['malicious_non_allow_recall']:.1%}",
        f"- 正常样本放行率：{result['benign_allow_rate']:.1%}",
        f"- 耗时：{result['duration_ms']} ms",
        "",
        f"> {result['claim_boundary']}",
        "",
        "| ID | 标签 | 预期 | 实际 | 结果 |",
        "|---|---|---|---|---|",
        *[f"| {item['id']} | {item['label']} | {item['expected']} | {item['actual']} | {'PASS' if item['passed'] else 'FAIL'} |" for item in records],
    ]
    (output / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = run(args.cases, args.output)
    print(json.dumps({key: result[key] for key in ("cases", "passed", "exact_match_rate", "malicious_non_allow_recall", "benign_allow_rate", "duration_ms")}, ensure_ascii=False))
    return 0 if result["passed"] == result["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
