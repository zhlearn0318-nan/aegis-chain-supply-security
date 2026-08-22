from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.dynamic_audit.planning import (  # noqa: E402
    build_trigger_plan,
    correlate_dynamic_evidence,
)
from backend.dynamic_audit.runner import (  # noqa: E402
    DYNAMIC_AUDIT_SCHEMA_VERSION,
    run_safe_marker_flow_fixture,
)


DEFAULT_RUN_ID = "2026-08-22-dynamic-marker-flow-dev-v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / DEFAULT_RUN_ID


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
        description="Run the controlled Aegis dynamic source-to-sink marker experiment"
    )
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not args.run_id or len(args.run_id) > 128:
        raise ValueError("run-id must be a non-empty bounded value")
    output = args.output.resolve(strict=False)
    output.mkdir(parents=True, exist_ok=True)
    protected_outputs = (
        "dynamic_evidence.json",
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
    static_findings = [{
        "id": "controlled-static-sensitive-flow",
        "rule_id": "AEGIS_SENSITIVE_DATA_TO_OUTBOUND_SINK",
        "category": "sensitive network credential flow",
        "title": "敏感数据可能进入网络汇点",
    }]
    plan = build_trigger_plan(
        target_id="self-built-marker-file-to-loopback",
        target_kind="skill",
        static_findings=static_findings,
        max_attempts=1,
    )
    with tempfile.TemporaryDirectory(prefix="fixture-workspaces-", dir=output) as temporary:
        fixture_result = run_safe_marker_flow_fixture(
            Path(temporary) / "run",
            seed=args.run_id,
        )
    event_types = [
        event["event_type"]
        for event in fixture_result["events"]
        if event.get("severity") == "INFO"
    ]
    correlation = correlate_dynamic_evidence(
        plan,
        execution_status=(
            "completed" if fixture_result["metrics"]["fixtures_completed"] == 1 else "failed"
        ),
        observed_event_types=event_types,
        marker_witnesses=fixture_result["marker_witnesses"],
    )
    elapsed_seconds = round(time.perf_counter() - started, 3)
    completed_at = datetime.now(timezone.utc)
    metrics = dict(fixture_result["metrics"])
    metrics.update({
        "run_id": args.run_id,
        "trigger_plan_steps": len(plan.steps),
        "correlation_status": correlation.status,
        "static_finding_ids": len(plan.static_finding_ids),
        "static_decision_changes": 0,
        "run_elapsed_seconds": elapsed_seconds,
    })
    success = (
        fixture_result["success"] is True
        and correlation.status == "confirmed"
        and metrics["marker_witnesses"] == 1
        and metrics["static_decision_changes"] == 0
    )
    evidence = {
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
        "run_id": args.run_id,
        "status": "completed" if success else "failed",
        "static_findings": static_findings,
        "trigger_plan": plan.to_dict(),
        "controlled_fixture": fixture_result,
        "correlation": correlation.to_dict(),
        "claim_boundary": (
            "Self-built hash-locked marker fixture mechanism evidence only; no third-party "
            "Skill execution and no untrusted-code sandbox claim."
        ),
    }
    _write_json(output / "dynamic_evidence.json", evidence)
    _write_json(output / "metrics.json", metrics)

    evaluation_summary = {
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
        "run_id": args.run_id,
        "outcome_summary": (
            "受控假公文标记经文件读取和Base64编码到达本机回环汇点，形成1条脱敏源到汇证据。"
            if success else "受控Marker源到汇机制未通过全部接受门。"
        ),
        "evaluation_summary": {
            "fixture_completion": f"{metrics['fixtures_completed']}/{metrics['fixtures_total']}",
            "marker_witnesses": metrics["marker_witnesses"],
            "source_to_sink_witness_rate": metrics["source_to_sink_witness_rate"],
            "correlation_status": metrics["correlation_status"],
            "raw_marker_leaks": metrics["raw_marker_leaks"],
            "static_decision_changes": metrics["static_decision_changes"],
        },
        "claim_update": "supported_on_controlled_fixture" if success else "inconclusive",
        "baseline_relation": "complements_read_only_static_regression_baseline",
        "failure_mode": None if success else "evaluation_pipeline_failure",
        "next_action": "docker_safety_backend_gate",
    }
    _write_json(output / "evaluation_summary.json", evaluation_summary)

    source_paths = (
        "backend/dynamic_audit/markers.py",
        "backend/dynamic_audit/planning.py",
        "backend/dynamic_audit/runner.py",
        "tools/dynamic/fixtures/marker_file_to_loopback.py",
        "tools/dynamic/run_marker_flow_audit.py",
        "backend/tests/test_dynamic_evidence.py",
    )
    command = [sys.executable, *sys.argv]
    run_manifest = {
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
        "run_id": args.run_id,
        "status": "completed" if success else "failed",
        "experiment_tier": "auxiliary/dev",
        "research_question": (
            "能否在不执行第三方样本、不连接互联网且不改变静态决策的条件下，"
            "形成政企诱饵文件到受控网络汇点的脱敏源到汇证据？"
        ),
        "null_hypothesis": "Marker不能形成完整证据，或发生原文泄露、越界行为或静态决策变化。",
        "alternative_hypothesis": "1/1受控fixture形成Base64源到汇witness，负面安全指标和决策变化均为0。",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "baseline": {
            "run_id": "2026-08-22-static-audit-regression600-v1",
            "relation": "read_only_complementary_not_numerically_comparable",
        },
        "dataset": {
            "external_dataset": None,
            "controlled_fixtures": 1,
            "protected_samples_read": 0,
            "protected_samples_executed": 0,
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "gpu_used": False,
            "docker_used": False,
            "cloud_used": False,
            "internet_used": False,
            "network_allowance": "127.0.0.1_ephemeral_only",
        },
        "sources": {
            path: _sha256_file(DEMO_ROOT / path)
            for path in source_paths
        },
        "metrics": metrics,
        "safety_contract": {
            "execution_trust": "self_built_hash_locked_only",
            "accepts_user_code": False,
            "accepts_user_paths": False,
            "accepts_custom_commands": False,
            "raw_marker_retained": False,
            "policy_effect": "none",
            "static_decision_changes": 0,
            "not_an_untrusted_code_sandbox": True,
        },
        "claim_boundary": evidence["claim_boundary"],
        "next_action": evaluation_summary["next_action"],
    }
    _write_json(output / "run_manifest.json", run_manifest)
    _write_text(
        output / "run.log",
        "\n".join([
            f"run_id={args.run_id}",
            f"status={run_manifest['status']}",
            f"fixture_completion={metrics['fixtures_completed']}/{metrics['fixtures_total']}",
            f"marker_witnesses={metrics['marker_witnesses']}",
            f"correlation_status={metrics['correlation_status']}",
            f"raw_marker_leaks={metrics['raw_marker_leaks']}",
            f"static_decision_changes={metrics['static_decision_changes']}",
            f"elapsed_seconds={elapsed_seconds}",
        ]),
    )
    _write_text(
        output / "bash.log",
        "\n".join([
            "execution_interface=exec_command",
            "required_bash_exec_artifact_interfaces=unavailable",
            f"command={json.dumps(command, ensure_ascii=False)}",
            f"status={run_manifest['status']}",
        ]),
    )
    _write_text(
        output / "summary.md",
        "\n".join([
            "# 动态 Marker 源到汇开发实验结果",
            "",
            f"- 状态：`{run_manifest['status']}`",
            f"- 受控 fixture：{metrics['fixtures_completed']}/{metrics['fixtures_total']}",
            f"- 源到汇 witness：{metrics['marker_witnesses']}，变换 `{', '.join(metrics['confirmed_transforms'])}`",
            f"- 静动态关联：`{metrics['correlation_status']}`",
            f"- 原始 marker 泄露：{metrics['raw_marker_leaks']}",
            f"- 静态最终决策变化：{metrics['static_decision_changes']}",
            "- 边界：只证明自建、哈希锁定 fixture 的机制，不证明第三方代码可安全执行。",
        ]),
    )
    output_names = [
        "dynamic_evidence.json",
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
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
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
        "status": run_manifest["status"],
        "metrics": metrics,
        "output": str(output),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Marker flow audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
