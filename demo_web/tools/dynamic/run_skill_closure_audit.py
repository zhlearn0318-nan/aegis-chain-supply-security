from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.dynamic_audit.docker_backend import DockerBackendError  # noqa: E402
from backend.dynamic_audit.skill_closure import (  # noqa: E402
    SKILL_CLOSURE_SCHEMA_VERSION,
    run_skill_closure_probe,
)


DEFAULT_RUN_ID = "2026-08-23-skill-runtime-closure-dev-v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / DEFAULT_RUN_ID
DEFAULT_CONFIG = DEMO_ROOT / "config" / "docker_skill_closure_backend.json"


def _sha256_file(path: Path) -> dict[str, str | int]:
    payload = path.read_bytes()
    return {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_text(path: Path, payload: str) -> None:
    path.write_text(payload.rstrip() + "\n", encoding="utf-8", newline="\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the controlled Docker Skill runtime-closure audit"
    )
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not args.run_id or len(args.run_id) > 128:
        raise ValueError("run-id must be a non-empty bounded value")
    output = args.output.resolve(strict=False)
    output.mkdir(parents=True, exist_ok=True)
    protected_outputs = (
        "skill_closure_evidence.json", "metrics.json", "evaluation_summary.json",
        "run_manifest.json", "artifact_manifest.json", "run.log", "bash.log",
        "summary.md",
    )
    existing = [name for name in protected_outputs if (output / name).exists()]
    if existing:
        raise ValueError(f"refusing to overwrite existing outputs: {existing}")

    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    evidence = run_skill_closure_probe(
        args.config,
        output / "fixture_workspaces",
    )
    elapsed_seconds = round(time.perf_counter() - started, 3)
    completed_at = datetime.now(timezone.utc)
    metrics = dict(evidence["metrics"])
    metrics.update({
        "run_id": args.run_id,
        "status": "completed" if evidence["success"] else "failed",
        "run_elapsed_seconds": elapsed_seconds,
    })
    evidence.update({
        "schema_version": SKILL_CLOSURE_SCHEMA_VERSION,
        "run_id": args.run_id,
        "status": metrics["status"],
    })
    _write_json(output / "skill_closure_evidence.json", evidence)
    _write_json(output / "metrics.json", metrics)

    success = evidence["success"] is True
    evaluation_summary = {
        "takeaway": (
            "受控 Skill 运行后新增的指令、脚本和配置被完整盘点，并由现有 Cisco + Aegis 静态链路找回运行时风险。"
            if success else "Skill 目录闭包、静态提升或 Docker 接受门至少一项未通过。"
        ),
        "claim_update": "strengthens" if success else "neutral",
        "baseline_relation": "extends_static_audit_with_controlled_runtime_content_lift",
        "comparability": "complementary",
        "failure_mode": "none" if success else (
            (evidence.get("error") or {}).get("code") or "evaluation"
        ),
        "next_action": "freeze_skill_closure_v1" if success else "repair_skill_closure_gate",
    }
    _write_json(output / "evaluation_summary.json", evaluation_summary)

    source_paths = (
        "config/docker_skill_closure_backend.json",
        "backend/skill_static_pipeline.py",
        "backend/dynamic_audit/skill_closure.py",
        "tools/dynamic/docker/fixtures/skill_runtime_closure.py",
        "tools/dynamic/run_skill_closure_audit.py",
        "backend/tests/test_skill_closure.py",
    )
    command = [sys.executable, *sys.argv]
    run_manifest = {
        "schema_version": SKILL_CLOSURE_SCHEMA_VERSION,
        "run_id": args.run_id,
        "status": metrics["status"],
        "experiment_tier": "auxiliary/dev",
        "research_question": (
            "受控 Skill 运行时新增内容能否被完整盘点，并由现有 Cisco + Aegis 静态链路"
            "找回初始目录中不可见的风险？"
        ),
        "research_type": "deterministic_runtime_directory_closure_validation",
        "research_objective": "将运行时生成的指令、脚本和配置提升回既有静态审计。",
        "experimental_setup": {
            "initial_files": 2,
            "materialized_files": 3,
            "materialized_categories": ["instruction", "script", "config"],
            "vendor_scanner": "Cisco Skill Scanner",
            "static_pipeline": "existing_cisco_plus_aegis_pipeline",
            "container_network": "none",
            "generated_content_executed": False,
        },
        "experimental_results": metrics,
        "experimental_analysis": evaluation_summary["takeaway"],
        "experimental_conclusions": (
            "supported_on_controlled_fixture" if success else "inconclusive"
        ),
        "null_hypothesis": "目录差分、哈希验证或静态提升任一失败，或新增负面指标非零。",
        "alternative_hypothesis": "3 个新增文件被完整提升且找回至少 1 条运行时独有风险。",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "baseline": {
            "static_run_id": "2026-08-22-static-audit-regression600-v1",
            "docker_run_id": "2026-08-22-docker-safety-backend-dev-v2",
            "telemetry_run_id": "2026-08-23-mcp-kernel-telemetry-dev-v1",
            "relation": "read_only_complementary_not_numerically_superior",
        },
        "dataset": {
            "external_dataset": None,
            "controlled_fixtures": 1,
            "third_party_samples_read": 0,
            "third_party_samples_executed": 0,
        },
        "environment": {
            "host_python": sys.version,
            "host_platform": platform.platform(),
            "docker_engine": evidence.get("engine"),
            "container_image": evidence.get("image"),
            "gpu_used": False,
            "cloud_used": False,
            "internet_used": False,
            "image_pull_used": False,
        },
        "sources": {path: _sha256_file(DEMO_ROOT / path) for path in source_paths},
        "metrics": metrics,
        "metric_contract": {
            "positive": {
                "materialized_files_observed": 3,
                "materialized_files_lifted": 3,
                "materialized_hashes_verified": 3,
                "instruction_files": 1,
                "script_files": 1,
                "config_files": 1,
                "closure_coverage_rate": 1.0,
                "runtime_only_risk_recovered": 1,
                "vendor_scans": 2,
            },
            "negative_zero": [
                "unsafe_paths", "symlinks", "oversized_files", "unsupported_files",
                "raw_content_leaks", "third_party_samples_executed", "internet_used",
                "image_pull_used", "gpu_used", "decision_changes", "container_residuals",
                "timeouts",
            ],
        },
        "safety_contract": {
            "execution_trust": "self_built_hash_locked_only",
            "accepts_user_code": False,
            "accepts_user_paths": False,
            "accepts_custom_commands": False,
            "generated_content_executed": False,
            "image_pull_policy": "never",
            "network_mode": "none",
            "read_only_rootfs": True,
            "non_root": True,
            "cap_drop_all": True,
            "no_new_privileges": True,
            "docker_socket_mounted": False,
            "raw_generated_content_retained": False,
            "policy_effect": "none",
            "static_decision_changes": 0,
            "not_a_third_party_skill_sandbox_proof": True,
        },
        "claim_boundary": evidence["claim_boundary"],
        "evaluation_summary": evaluation_summary,
    }
    _write_json(output / "run_manifest.json", run_manifest)
    _write_text(
        output / "run.log",
        "\n".join([
            f"run_id={args.run_id}",
            f"status={metrics['status']}",
            f"all_gates={metrics['all_gates_passed']}/{metrics['all_gates_total']}",
            f"materialized={metrics['materialized_files_observed']}/{metrics['materialized_files_expected']}",
            f"lifted={metrics['materialized_files_lifted']}",
            f"hashes_verified={metrics['materialized_hashes_verified']}",
            f"runtime_risk_findings={metrics['runtime_risk_findings']}",
            f"vendor_scans={metrics['vendor_scans']}",
            f"raw_content_leaks={metrics['raw_content_leaks']}",
            f"container_residuals={metrics['container_residuals']}",
            f"decision_changes={metrics['decision_changes']}",
            f"elapsed_seconds={elapsed_seconds}",
        ]),
    )
    _write_text(
        output / "bash.log",
        "\n".join([
            "execution_interface=exec_command",
            "required_bash_exec_artifact_interfaces=unavailable",
            f"command={json.dumps(command, ensure_ascii=False)}",
            f"docker_create_command={json.dumps(evidence['create_command'], ensure_ascii=False)}",
            f"status={metrics['status']}",
        ]),
    )
    _write_text(
        output / "summary.md",
        "\n".join([
            "# D3-C Skill 运行时目录闭包与静态提升结果",
            "",
            f"- 状态：`{metrics['status']}`",
            f"- 全部接受门：{metrics['all_gates_passed']}/{metrics['all_gates_total']}",
            f"- 运行前/运行后文件：{metrics['pre_files_total']}/{metrics['post_files_total']}",
            f"- 新增/提升/哈希验证：{metrics['materialized_files_observed']}/{metrics['materialized_files_lifted']}/{metrics['materialized_hashes_verified']}",
            f"- 指令/脚本/配置：{metrics['instruction_files']}/{metrics['script_files']}/{metrics['config_files']}",
            f"- 闭包覆盖率：{metrics['closure_coverage_rate']:.1%}",
            f"- Cisco 前后扫描次数：{metrics['vendor_scans']}",
            f"- 静态发现（前/后/新增）：{metrics['pre_static_findings']}/{metrics['post_static_findings']}/{metrics['new_static_findings']}",
            f"- 运行时风险发现：{metrics['runtime_risk_findings']}",
            f"- 原始内容泄漏：{metrics['raw_content_leaks']}",
            f"- 容器残留：{metrics['container_residuals']}",
            f"- 第三方样本执行：{metrics['third_party_samples_executed']}",
            f"- 静态最终决策变化：{metrics['decision_changes']}",
            "- 边界：只验证自建 fixture 的目录闭包与静态提升，不代表可安全执行任意第三方 Skill。",
        ]),
    )
    output_names = [
        "skill_closure_evidence.json", "metrics.json", "evaluation_summary.json",
        "run_manifest.json", "run.log", "bash.log", "summary.md", "PLAN.md",
        "CHECKLIST.md",
    ]
    artifact_manifest = {
        "schema_version": SKILL_CLOSURE_SCHEMA_VERSION,
        "run_id": args.run_id,
        "evidence_files": {
            name: _sha256_file(output / name)
            for name in output_names if (output / name).is_file()
        },
    }
    _write_json(output / "artifact_manifest.json", artifact_manifest)
    return {
        "run_id": args.run_id,
        "status": metrics["status"],
        "metrics": metrics,
        "output": str(output),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except (DockerBackendError, OSError, ValueError, KeyError) as exc:
        print(f"Skill closure audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
