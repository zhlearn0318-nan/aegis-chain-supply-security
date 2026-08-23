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
from backend.dynamic_audit.mcp_protocol import (  # noqa: E402
    MCP_BACKEND_SCHEMA_VERSION,
    run_mcp_protocol_probe,
)


DEFAULT_RUN_ID = "2026-08-23-mcp-protocol-marker-dev-v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / DEFAULT_RUN_ID
DEFAULT_CONFIG = DEMO_ROOT / "config" / "docker_mcp_protocol_backend.json"


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
        description="Run the controlled Docker MCP protocol and marker-flow audit"
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
        "mcp_protocol_evidence.json",
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
    evidence = run_mcp_protocol_probe(args.config)
    elapsed_seconds = round(time.perf_counter() - started, 3)
    completed_at = datetime.now(timezone.utc)
    metrics = dict(evidence["metrics"])
    metrics.update({
        "run_id": args.run_id,
        "status": "completed" if evidence["success"] else "failed",
        "run_elapsed_seconds": elapsed_seconds,
    })
    evidence.update({
        "schema_version": MCP_BACKEND_SCHEMA_VERSION,
        "run_id": args.run_id,
        "status": metrics["status"],
    })
    _write_json(output / "mcp_protocol_evidence.json", evidence)
    _write_json(output / "metrics.json", metrics)

    success = evidence["success"] is True
    evaluation_summary = {
        "takeaway": (
            "受控 MCP stdio 服务在 Docker 安全边界内完成真实工具调用，并仅在调用后形成公文 Marker 证据。"
            if success else "MCP 协议、Marker 或 Docker 接受门至少一项未通过。"
        ),
        "claim_update": "strengthens" if success else "neutral",
        "baseline_relation": "extends_marker_v2_and_docker_v2_without_decision_change",
        "comparability": "high",
        "failure_mode": "none" if success else (
            (evidence.get("error") or {}).get("code") or "evaluation"
        ),
        "next_action": "add_syscall_and_filesystem_telemetry" if success else "repair_mcp_gate",
    }
    _write_json(output / "evaluation_summary.json", evaluation_summary)

    source_paths = (
        "config/docker_mcp_protocol_backend.json",
        "backend/dynamic_audit/mcp_protocol.py",
        "tools/dynamic/docker/fixtures/mcp_protocol_marker.py",
        "tools/dynamic/run_mcp_protocol_audit.py",
        "backend/tests/test_mcp_protocol.py",
    )
    command = [sys.executable, *sys.argv]
    run_manifest = {
        "schema_version": MCP_BACKEND_SCHEMA_VERSION,
        "run_id": args.run_id,
        "status": metrics["status"],
        "experiment_tier": "auxiliary/dev",
        "research_question": (
            "静态 Trigger Plan 能否引导受控 MCP 目标完成真实 stdio 协议调用，"
            "并仅在 tools/call 后形成政企公文 Marker 源到汇证据？"
        ),
        "research_type": "deterministic_protocol_and_evidence_mechanism_validation",
        "research_objective": "验证 MCP 协议、工具调用、Marker 与静动态关联的最小闭环。",
        "experimental_setup": {
            "protocol_version": "2025-06-18",
            "transport": "stdio_newline_delimited_jsonrpc",
            "sequence": [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call",
            ],
            "tool": "read_official_document",
            "marker_profile": "official_document",
            "container_network": "none",
        },
        "experimental_results": metrics,
        "experimental_analysis": evaluation_summary["takeaway"],
        "experimental_conclusions": (
            "supported_on_controlled_fixture" if success else "inconclusive"
        ),
        "null_hypothesis": "任一协议、Marker、Docker、脱敏或清理接受门失败。",
        "alternative_hypothesis": "调用前无 Marker，合法工具调用后形成一个脱敏 witness，且全部安全门通过。",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "baseline": {
            "docker_run_id": "2026-08-22-docker-safety-backend-dev-v2",
            "marker_run_id": "2026-08-22-dynamic-marker-flow-dev-v2",
            "static_run_id": "2026-08-22-static-audit-regression600-v1",
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
                "protocol_steps_passed": 4,
                "post_call_marker_witnesses": 1,
                "source_to_sink_witness_rate": 1.0,
                "correlation_confirmed": 1,
            },
            "negative_zero": [
                "pre_call_marker_witnesses",
                "protocol_errors",
                "timeouts",
                "raw_marker_leaks",
                "container_residuals",
                "third_party_samples_executed",
                "decision_changes",
            ],
        },
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
            "raw_marker_retained": False,
            "policy_effect": "none",
            "static_decision_changes": 0,
            "not_a_container_escape_proof": True,
        },
        "official_spec_references": [
            "https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle",
            "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports",
            "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
        ],
        "claim_boundary": evidence["claim_boundary"],
        "evaluation_summary": evaluation_summary,
    }
    _write_json(output / "run_manifest.json", run_manifest)
    _write_text(
        output / "run.log",
        "\n".join([
            f"run_id={args.run_id}",
            f"status={metrics['status']}",
            f"protocol_steps={metrics['protocol_steps_passed']}/{metrics['protocol_steps_total']}",
            f"all_gates={metrics['all_gates_passed']}/{metrics['all_gates_total']}",
            f"pre_call_marker_witnesses={metrics['pre_call_marker_witnesses']}",
            f"post_call_marker_witnesses={metrics['post_call_marker_witnesses']}",
            f"correlation_confirmed={metrics['correlation_confirmed']}",
            f"raw_marker_leaks={metrics['raw_marker_leaks']}",
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
            "# D3 MCP 协议调用与 Marker 证据闭环结果",
            "",
            f"- 状态：`{metrics['status']}`",
            f"- MCP 协议步骤：{metrics['protocol_steps_passed']}/{metrics['protocol_steps_total']}",
            f"- 全部接受门：{metrics['all_gates_passed']}/{metrics['all_gates_total']}",
            f"- 调用前 Marker witness：{metrics['pre_call_marker_witnesses']}",
            f"- 调用后 Marker witness：{metrics['post_call_marker_witnesses']}",
            f"- 静动态关联确认：{metrics['correlation_confirmed']}",
            f"- 原始 Marker 泄漏：{metrics['raw_marker_leaks']}",
            f"- 容器残留：{metrics['container_residuals']}",
            f"- 第三方样本执行：{metrics['third_party_samples_executed']}",
            f"- 静态最终决策变化：{metrics['decision_changes']}",
            "- 边界：仅证明受控自建 MCP fixture 的协议与 Marker 机制，不证明任意 MCP Server 安全。",
        ]),
    )
    output_names = [
        "mcp_protocol_evidence.json",
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
        "schema_version": MCP_BACKEND_SCHEMA_VERSION,
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
        print(f"MCP protocol audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
