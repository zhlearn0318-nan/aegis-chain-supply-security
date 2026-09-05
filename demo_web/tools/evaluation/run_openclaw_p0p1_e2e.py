from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.openclaw_install_policy import evaluate_install_request


SAMPLES = DEMO_ROOT / "demo_samples" / "p0p1_runtime"
OUTPUT = DEMO_ROOT / "artifacts" / "p0p1" / "openclaw-e2e-v2"
CASES = {"python_safe": "allow", "python_bad": "block", "node_safe": "allow", "node_bad": "block", "shell_safe": "allow", "shell_bad": "block"}


def run() -> dict:
    # This suite represents the formal OpenClaw deployment profile, where every
    # Skill install request must complete the dynamic sandbox before admission.
    os.environ["AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY"] = "required"
    records = []
    started = time.perf_counter()
    for name, expected in CASES.items():
        response = evaluate_install_request({
            "protocolVersion": 1,
            "openclawVersion": "2026.7.1-2",
            "targetType": "skill",
            "targetName": f"aegis-e2e-{name.replace('_', '-')}",
            "sourcePath": str((SAMPLES / name).resolve(strict=True)),
            "sourcePathKind": "directory",
            "source": {"kind": "p0p1-acceptance", "mutable": False},
            "origin": {"type": "aegis-evaluation"},
            "request": {"kind": "skill-preflight", "mode": "scan-only"},
        })
        decision = str(response.get("decision") or "block")
        records.append({
            "sample": name,
            "expected": expected,
            "actual": decision,
            "passed": decision == expected,
            "reason": response.get("reason"),
            "rule_ids": [str(item.get("ruleId") or "") for item in response.get("findings") or []],
        })
    result = {
        "schema_version": "1.0",
        "suite_id": "aegis-openclaw-install-policy-p0p1-e2e-v2",
        "cases": len(records),
        "passed": sum(item["passed"] for item in records),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "records": records,
        "environment": {
            "dynamic_policy": os.getenv("AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY"),
            "semantic_model_mode": os.getenv("AEGIS_SEMANTIC_MODEL_MODE"),
            "external_llm_opt_in": os.getenv("AEGIS_EXTERNAL_LLM_OPT_IN"),
        },
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [
        "# OpenClaw 正式安装准入 P0/P1 端到端验收",
        "",
        f"- 通过：{result['passed']}/{result['cases']}",
        f"- 耗时：{result['duration_ms']} ms",
        "- 链路：OpenClaw 协议请求 → Cisco + Aegis 静态 → P0 语义/一致性 → P1 动态路由 → 单调证据融合 → 正式响应",
        "",
        "| 样本 | 预期 | 实际 | 主要规则 | 结果 |",
        "|---|---|---|---|---|",
        *[f"| {item['sample']} | {item['expected']} | {item['actual']} | {','.join(item['rule_ids']) or 'none'} | {'PASS' if item['passed'] else 'FAIL'} |" for item in records],
    ]
    (OUTPUT / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    result = run()
    print(json.dumps({key: result[key] for key in ("cases", "passed", "duration_ms")}, ensure_ascii=False))
    raise SystemExit(0 if result["passed"] == result["cases"] else 1)
