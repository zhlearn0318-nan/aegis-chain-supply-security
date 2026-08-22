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

from backend.dynamic_audit.docker_backend import (  # noqa: E402
    DOCKER_BACKEND_SCHEMA_VERSION,
    DockerBackendError,
    run_docker_security_probe,
)


DEFAULT_RUN_ID = "2026-08-22-docker-safety-backend-dev-v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / DEFAULT_RUN_ID
DEFAULT_CONFIG = DEMO_ROOT / "config" / "docker_dynamic_backend.json"


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
        description="Run the Aegis Docker dynamic-backend safety gate"
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
        "docker_safety_evidence.json",
        "metrics.json",
        "evaluation_summary.json",
        "run_manifest.json",
        "artifact_manifest.json",
        "run.log",
        "bash.log",
        "summary.md",
    )
    existing = [name for name in protected_outputs if (output / name).exists()]
    if existing:
        raise ValueError(f"refusing to overwrite existing outputs: {existing}")

    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    evidence = run_docker_security_probe(args.config)
    elapsed_seconds = round(time.perf_counter() - started, 3)
    completed_at = datetime.now(timezone.utc)
    metrics = dict(evidence["metrics"])
    metrics.update({
        "run_id": args.run_id,
        "status": "completed" if evidence["success"] else "failed",
        "run_elapsed_seconds": elapsed_seconds,
    })
    evidence.update({
        "schema_version": DOCKER_BACKEND_SCHEMA_VERSION,
        "run_id": args.run_id,
        "status": metrics["status"],
    })
    _write_json(output / "docker_safety_evidence.json", evidence)
    _write_json(output / "metrics.json", metrics)

    success = evidence["success"] is True
    evaluation_summary = {
        "schema_version": DOCKER_BACKEND_SCHEMA_VERSION,
        "run_id": args.run_id,
        "outcome_summary": (
            "固定本地镜像和自建probe通过Docker配置、实际行为与清理安全门。"
            if success else "Docker安全后端未通过全部接受门。"
        ),
        "evaluation_summary": {
            "engine_ready": metrics["engine_ready"],
            "all_gates": f"{metrics['all_gates_passed']}/{metrics['all_gates_total']}",
            "fixture_completed": metrics["fixture_completed"],
            "policy_violations": metrics["policy_violations"],
            "container_residuals": metrics["container_residuals"],
            "decision_changes": metrics["decision_changes"],
        },
        "claim_update": "supported_on_controlled_fixture" if success else "inconclusive",
        "baseline_relation": "extends_dynamic_marker_v2_without_changing_static_baseline",
        "failure_mode": None if success else (
            (evidence.get("error") or {}).get("code") or "evaluation_pipeline_failure"
        ),
        "next_action": "controlled_mcp_protocol_fixture" if success else "docker_gate_repair",
    }
    _write_json(output / "evaluation_summary.json", evaluation_summary)

    source_paths = (
        "config/docker_dynamic_backend.json",
        "backend/dynamic_audit/docker_backend.py",
        "tools/dynamic/docker/fixtures/security_probe.py",
        "tools/dynamic/run_docker_safety_audit.py",
        "backend/tests/test_docker_backend.py",
    )
    command = [sys.executable, *sys.argv]
    run_manifest = {
        "schema_version": DOCKER_BACKEND_SCHEMA_VERSION,
        "run_id": args.run_id,
        "status": metrics["status"],
        "experiment_tier": "auxiliary/dev",
        "research_type": "deterministic_engineering_safety_gate_validation",
        "research_question": (
            "能否在不下载镜像、不执行第三方样本和不改变静态决策的条件下，"
            "建立可复核、失败闭锁的Docker动态执行后端？"
        ),
        "null_hypothesis": "任一镜像、配置、运行行为或清理安全门失败。",
        "alternative_hypothesis": "固定镜像和自建probe通过全部安全门，负面指标均为0。",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "baseline": {
            "dynamic_run_id": "2026-08-22-dynamic-marker-flow-dev-v2",
            "static_run_id": "2026-08-22-static-audit-regression600-v1",
            "relation": "read_only_complementary_not_numerically_comparable",
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
        "safety_contract": {
            "execution_trust": "self_built_hash_locked_only",
            "accepts_user_code": False,
            "accepts_user_paths": False,
            "accepts_custom_commands": False,
            "image_pull_policy": "never",
            "network_mode": "none",
            "read_only_rootfs": True,
            "non_root": True,
            "cap_drop_all": True,
            "no_new_privileges": True,
            "docker_socket_mounted": False,
            "policy_effect": "none",
            "static_decision_changes": 0,
            "not_a_container_escape_proof": True,
        },
        "claim_boundary": evidence["claim_boundary"],
        "next_action": evaluation_summary["next_action"],
    }
    _write_json(output / "run_manifest.json", run_manifest)
    _write_text(
        output / "run.log",
        "\n".join([
            f"run_id={args.run_id}",
            f"status={metrics['status']}",
            f"engine_ready={metrics['engine_ready']}",
            f"all_gates={metrics['all_gates_passed']}/{metrics['all_gates_total']}",
            f"fixture_completed={metrics['fixture_completed']}",
            f"policy_violations={metrics['policy_violations']}",
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
            "# D2 Docker 安全执行后端开发结果",
            "",
            f"- 状态：`{metrics['status']}`",
            f"- Engine 就绪：{metrics['engine_ready']}",
            f"- 全部安全门：{metrics['all_gates_passed']}/{metrics['all_gates_total']}",
            f"- fixture 完成：{metrics['fixture_completed']}/1",
            f"- 策略违规：{metrics['policy_violations']}",
            f"- 容器残留：{metrics['container_residuals']}",
            f"- 第三方样本执行：{metrics['third_party_samples_executed']}",
            f"- 静态最终决策变化：{metrics['decision_changes']}",
            "- 边界：只证明当前固定镜像和自建 probe 的配置/行为安全门，不证明容器逃逸不可发生。",
        ]),
    )
    output_names = [
        "docker_safety_evidence.json",
        "metrics.json",
        "evaluation_summary.json",
        "run_manifest.json",
        "run.log",
        "bash.log",
        "summary.md",
        "PLAN.md",
        "CHECKLIST.md",
    ]
    artifact_manifest = {
        "schema_version": DOCKER_BACKEND_SCHEMA_VERSION,
        "run_id": args.run_id,
        "evidence_files": {
            name: _sha256_file(output / name)
            for name in output_names
            if (output / name).is_file()
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
        print(f"Docker safety audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
