from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.dynamic_audit.docker_backend import _docker_prefix, discover_docker_cli, run_docker_cli
from backend.dynamic_audit.skill_sandbox_multiruntime import BACKEND_ID, CONFIG_PATH, run_skill_sandbox_v2


DEFAULT_SAMPLES = DEMO_ROOT / "demo_samples" / "p0p1_runtime"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "p0p1" / "dynamic-acceptance-v1"
EXPECTED = {
    "python_safe": "ALLOW",
    "python_bad": "BLOCK",
    "node_safe": "ALLOW",
    "node_bad": "BLOCK",
    "shell_safe": "ALLOW",
    "shell_bad": "BLOCK",
}


def compact(result: dict) -> dict:
    runs = result.get("runs") if isinstance(result.get("runs"), list) else []
    return {
        "backend_id": result.get("backend_id"),
        "decision": result.get("decision"),
        "status": result.get("status"),
        "duration_ms": result.get("duration_ms"),
        "entrypoint_plan": result.get("entrypoint_plan"),
        "rule_ids": sorted({str(item.get("rule_id") or "") for item in result.get("findings") or []}),
        "runs": [
            {
                "runtime": item.get("runtime"),
                "entrypoint": item.get("entrypoint"),
                "success": item.get("success"),
                "image_gates_all": bool(item.get("image_gates")) and all(item.get("image_gates", {}).values()),
                "inspect_gates_all": bool(item.get("inspect_gates")) and all(item.get("inspect_gates", {}).values()),
                "cleanup": item.get("cleanup"),
                "collector": (item.get("runner") or {}).get("collector"),
                "round_ids": [round_item.get("id") for round_item in (item.get("runner") or {}).get("rounds") or []],
                "event_count": len((item.get("runner") or {}).get("events") or []),
                "evaluation": item.get("evaluation"),
                "error": item.get("error"),
            }
            for item in runs if isinstance(item, dict)
        ],
    }


def run(samples: Path, output: Path) -> dict:
    records: list[dict] = []
    started = time.perf_counter()
    for name, expected in EXPECTED.items():
        result = compact(run_skill_sandbox_v2(CONFIG_PATH, samples / name))
        result.update({"sample": name, "expected": expected, "passed": result["decision"] == expected})
        records.append(result)
    docker_cli = discover_docker_cli()
    residual_result = run_docker_cli(
        [*_docker_prefix(docker_cli), "container", "ls", "--all", "--filter", f"label=aegis.dynamic.backend={BACKEND_ID}", "--format", "{{.ID}}"],
        timeout_seconds=15,
    )
    residual_check_completed = residual_result.return_code == 0
    residual = [line.strip() for line in residual_result.stdout.splitlines() if line.strip()] if residual_check_completed else []
    result = {
        "schema_version": "1.0",
        "suite_id": "aegis-p0p1-real-docker-acceptance-v1",
        "cases": len(records),
        "passed": sum(item["passed"] for item in records),
        "all_container_security_gates": all(
            run_item["image_gates_all"] and run_item["inspect_gates_all"]
            for item in records for run_item in item["runs"]
        ),
        "all_three_rounds_attested": all(
            run_item["round_ids"] == ["typical", "edge", "adversarial"]
            for item in records for run_item in item["runs"]
        ),
        "all_cleanup_verified": all(
            run_item["cleanup"].get("removed") is True and run_item["cleanup"].get("residual") is False
            for item in records for run_item in item["runs"]
        ),
        "residual_check_completed": residual_check_completed,
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "records": records,
        "residual_containers": residual,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [
        "# P0/P1 真实 Docker 动态验收",
        "",
        f"- 用例：{result['passed']}/{result['cases']} 通过",
        f"- 镜像与容器安全门：{'PASS' if result['all_container_security_gates'] else 'FAIL'}",
        f"- 三轮输入证明：{'PASS' if result['all_three_rounds_attested'] else 'FAIL'}",
        f"- 容器清理：{'PASS' if result['all_cleanup_verified'] else 'FAIL'}",
        f"- 残留容器复查：{'PASS' if result['residual_check_completed'] and not residual else 'FAIL'}（{len(residual)} 个）",
        f"- 总耗时：{result['duration_ms']} ms",
        "",
        "| 样本 | 运行时 | 预期 | 实际 | 规则 | 结果 |",
        "|---|---|---|---|---|---|",
        *[
            f"| {item['sample']} | {','.join(item['entrypoint_plan'].get('runtimes') or [])} | {item['expected']} | {item['decision']} | {','.join(item['rule_ids']) or 'none'} | {'PASS' if item['passed'] else 'FAIL'} |"
            for item in records
        ],
        "",
        "> 语言级钩子和 Shell xtrace 是可解释行为证据，不是不可绕过的内核级检测；Docker 的断网、只读、非 root、能力删除和资源限制构成执行隔离边界。",
    ]
    (output / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = run(args.samples, args.output)
    summary = {key: result[key] for key in ("cases", "passed", "all_container_security_gates", "all_three_rounds_attested", "all_cleanup_verified", "residual_check_completed", "duration_ms")}
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if result["passed"] == result["cases"] and all(result[key] for key in ("all_container_security_gates", "all_three_rounds_attested", "all_cleanup_verified", "residual_check_completed")) and not result["residual_containers"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
