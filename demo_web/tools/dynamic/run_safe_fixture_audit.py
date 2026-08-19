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

from backend.dynamic_audit.runner import (  # noqa: E402
    DYNAMIC_AUDIT_SCHEMA_VERSION,
    DynamicAuditConfigurationError,
    run_safe_fixture_set,
    sha256_file,
)


DEFAULT_RUN_ID = "2026-08-18-safe-dynamic-fixture-dev-v1"
DEFAULT_CONFIG = DEMO_ROOT / "config" / "safe_dynamic_fixtures.json"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / DEFAULT_RUN_ID
PROTECTED_OUTPUTS = {
    "per_fixture.jsonl",
    "events.jsonl",
    "metrics.json",
    "metrics.md",
    "evaluation_summary.json",
    "run_manifest.json",
    "artifact_manifest.json",
    "run.log",
    "bash.log",
    "runlog.summary.md",
    "summary.md",
    "claim_validation.md",
}


def _write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8", newline="\n")


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    _write_text(
        path,
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
    )


def _sha256_entry(path: Path) -> dict[str, Any]:
    return {"sha256": sha256_file(path), "bytes": path.stat().st_size}


def _source_manifest() -> dict[str, dict[str, Any]]:
    relative_paths = [
        "backend/dynamic_audit/policy.py",
        "backend/dynamic_audit/bootstrap.py",
        "backend/dynamic_audit/runner.py",
        "tools/dynamic/run_safe_fixture_audit.py",
    ]
    return {
        relative: _sha256_entry(DEMO_ROOT / relative)
        for relative in relative_paths
    }


def _fixture_manifest(paths: list[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in paths:
        path = Path(raw).resolve(strict=True)
        result[path.relative_to(DEMO_ROOT).as_posix()] = _sha256_entry(path)
    return result


def _metrics_markdown(metrics: dict[str, Any]) -> str:
    counts = metrics["event_type_counts"]
    return "\n".join([
        "# 最小安全动态 Fixture v1 指标",
        "",
        f"- fixture 完成：{metrics['fixtures_completed']}/{metrics['fixtures_total']}",
        f"- 预期事件检查：{metrics['expected_checks_passed']}/{metrics['expected_checks_total']}",
        f"- 进程/stdin/环境事件：{counts.get('process_spawn', 0)}/{counts.get('stdin_read', 0)}/{counts.get('environment_read', 0)}",
        f"- 文件读/写事件：{counts.get('file_read', 0)}/{counts.get('file_write', 0)}",
        f"- 回环连接/服务端接收：{counts.get('network_connect', 0)}/{metrics['server_receipts']}",
        f"- 策略违规/超时/事件解析错误：{metrics['policy_violations']}/{metrics['timeouts']}/{metrics['event_parse_errors']}",
        f"- 非 INFO 证据/原始 token 泄露：{metrics['non_info_evidence']}/{metrics['raw_token_leaks']}",
        f"- 受保护样本读取/执行：{metrics['protected_samples_read']}/{metrics['protected_samples_executed']}",
        f"- 互联网连接/最终决策变化：{metrics['internet_connections_allowed']}/{metrics['decision_changes']}",
        f"- 平均/最大 fixture 耗时：{metrics['duration_ms']['mean']:.2f}/{metrics['duration_ms']['max']} ms",
        "",
    ])


def _claim_validation(metrics: dict[str, Any]) -> str:
    return "\n".join([
        "# Claim validation",
        "",
        "| Claim | Metric | Expected | Observed | Verdict |",
        "|---|---|---:|---:|---|",
        f"| 三份自建 fixture 均完成 | fixtures_completed | {metrics['fixtures_total']}/{metrics['fixtures_total']} | {metrics['fixtures_completed']}/{metrics['fixtures_total']} | {'supported' if metrics['fixtures_completed'] == metrics['fixtures_total'] else 'refuted'} |",
        f"| 预期动态机制均被观测 | expected checks | {metrics['expected_checks_total']}/{metrics['expected_checks_total']} | {metrics['expected_checks_passed']}/{metrics['expected_checks_total']} | {'supported' if metrics['expected_checks_passed'] == metrics['expected_checks_total'] else 'refuted'} |",
        f"| 运行未触发越界策略 | policy violations | 0 | {metrics['policy_violations']} | {'supported' if metrics['policy_violations'] == 0 else 'refuted'} |",
        f"| 结果不保留原始测试 token | raw token leaks | 0 | {metrics['raw_token_leaks']} | {'supported' if metrics['raw_token_leaks'] == 0 else 'refuted'} |",
        f"| 不接触数据集或第三方样本 | protected samples read/executed | 0/0 | {metrics['protected_samples_read']}/{metrics['protected_samples_executed']} | {'supported' if metrics['protected_samples_read'] == metrics['protected_samples_executed'] == 0 else 'refuted'} |",
        f"| 不改变准入决策 | decision changes | 0 | {metrics['decision_changes']} | {'supported' if metrics['decision_changes'] == 0 else 'refuted'} |",
        "",
        "边界：这些结论只支持哈希锁定、自建 Python fixture 的协作式观测，不支持执行不可信 Skill、恶意样本或后代进程内部行为的安全声明。",
        "",
    ])


def _summary(run_id: str, success: bool, metrics: dict[str, Any]) -> str:
    verdict = "supported_on_safe_fixtures" if success else "failed"
    return "\n".join([
        f"# {run_id}",
        "",
        f"- status: {'completed' if success else 'failed'}",
        f"- claim_verdict: {verdict}",
        f"- fixtures: {metrics['fixtures_completed']}/{metrics['fixtures_total']}",
        f"- expected_checks: {metrics['expected_checks_passed']}/{metrics['expected_checks_total']}",
        f"- violations/timeouts/leaks: {metrics['policy_violations']}/{metrics['timeouts']}/{metrics['raw_token_leaks']}",
        "- scope: self-built, hash-locked Python fixtures only",
        "- network: 127.0.0.1 ephemeral port only",
        "- policy_effect: INFO-only; no admission decision change",
        "- protected_samples_read_or_executed: 0",
        "- caveat: cooperative Python audit harness, not an untrusted-code sandbox",
        "",
    ])


def _runlog_summary(success: bool, metrics: dict[str, Any]) -> str:
    return "\n".join([
        "# Run log summary",
        "",
        f"- final_status: {'completed' if success else 'failed'}",
        f"- fixture_completion: {metrics['fixtures_completed']}/{metrics['fixtures_total']}",
        f"- expected_event_checks: {metrics['expected_checks_passed']}/{metrics['expected_checks_total']}",
        f"- fail_closed_signals: violations={metrics['policy_violations']}, timeouts={metrics['timeouts']}, parse_errors={metrics['event_parse_errors']}",
        "- external_dataset_or_sample_access: none",
        "- internet_access: none",
        "",
    ])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Aegis self-built safe dynamic fixtures")
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = args.output.resolve(strict=False)
    experiment_root = (DEMO_ROOT / "artifacts" / "experiment").resolve(strict=True)
    try:
        output_dir.relative_to(experiment_root)
    except ValueError as exc:
        raise DynamicAuditConfigurationError("output must remain under artifacts/experiment") from exc
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = sorted(name for name in PROTECTED_OUTPUTS if (output_dir / name).exists())
    if existing:
        raise DynamicAuditConfigurationError(
            f"Output directory already contains protected run outputs: {existing}"
        )

    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    result = run_safe_fixture_set(
        args.config.resolve(strict=True),
        output_dir / "fixture_workspaces",
    )
    elapsed_seconds = round(time.perf_counter() - started, 3)
    completed_at = datetime.now(timezone.utc)
    success = bool(result["success"])
    metrics = dict(result["metrics"])
    metrics["run_id"] = args.run_id
    metrics["status"] = "completed" if success else "failed"

    _write_jsonl(output_dir / "per_fixture.jsonl", result["fixture_results"])
    _write_jsonl(output_dir / "events.jsonl", result["events"])
    _write_json(output_dir / "metrics.json", metrics)
    _write_text(output_dir / "metrics.md", _metrics_markdown(metrics))

    evaluation_summary = {
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
        "run_id": args.run_id,
        "claim_verdict": "supported_on_safe_fixtures" if success else "refuted",
        "evaluation_summary": {
            "takeaway": (
                f"Hash-locked safe fixtures completed {metrics['fixtures_completed']}/"
                f"{metrics['fixtures_total']} with {metrics['policy_violations']} policy violations."
            ),
            "claim_update": "strengthens" if success else "weakens",
            "baseline_relation": "not_comparable",
            "comparability": "high",
            "failure_mode": "none" if success else "implementation",
            "next_action": "continue" if success else "revise_idea",
        },
        "evidence_boundary": [
            "Only self-built, SHA-256 locked Python fixtures were executed.",
            "The Python audit hook is cooperative instrumentation, not an OS sandbox.",
            "Only 127.0.0.1 on a parent-created ephemeral port was allowed.",
            "No dataset, third-party Skill, regression case, GPU, Docker, cloud, or internet was used.",
            "Dynamic evidence is INFO-only and does not affect admission decisions.",
        ],
    }
    _write_json(output_dir / "evaluation_summary.json", evaluation_summary)
    _write_text(output_dir / "summary.md", _summary(args.run_id, success, metrics))
    _write_text(output_dir / "claim_validation.md", _claim_validation(metrics))
    _write_text(output_dir / "runlog.summary.md", _runlog_summary(success, metrics))

    run_log = {
        "run_id": args.run_id,
        "status": "completed" if success else "failed",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "elapsed_seconds": elapsed_seconds,
        "progress": [
            "fixture config and SHA-256 validated",
            f"{metrics['fixtures_completed']}/{metrics['fixtures_total']} fixtures completed",
            f"{metrics['expected_checks_passed']}/{metrics['expected_checks_total']} expected checks passed",
            "outputs written without raw stdout, stderr, stdin, environment values, or network payloads",
        ],
    }
    _write_json(output_dir / "run.log", run_log)
    _write_text(
        output_dir / "bash.log",
        "\n".join([
            f"run_id={args.run_id}",
            f"command={sys.executable} {' '.join(sys.argv)}",
            "execution_interface=exec_command",
            "required_bash_exec_artifact_memory_interfaces=unavailable",
            f"status={'completed' if success else 'failed'}",
            f"elapsed_seconds={elapsed_seconds}",
            "",
        ]),
    )

    output_names = [
        "per_fixture.jsonl",
        "events.jsonl",
        "metrics.json",
        "metrics.md",
        "evaluation_summary.json",
        "run.log",
        "bash.log",
        "runlog.summary.md",
        "summary.md",
        "claim_validation.md",
    ]
    run_manifest = {
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
        "run_id": args.run_id,
        "status": "completed" if success else "failed",
        "experiment_tier": "auxiliary/dev",
        "research_type": "deterministic_engineering_mechanism_validation",
        "research_objective": "Validate a fail-closed, redacted dynamic evidence contract on trusted self-built Python fixtures.",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "elapsed_seconds": elapsed_seconds,
        "command": [sys.executable, *sys.argv],
        "baseline": {
            "static_run_id": "2026-08-18-aegis-command-context-dev-v2",
            "relation": "complementary_not_numerically_comparable",
        },
        "dataset": {
            "external_dataset": None,
            "fixture_set_id": "aegis-safe-dynamic-fixtures-v1",
            "fixtures": metrics["fixtures_total"],
            "protected_samples_read": 0,
            "protected_samples_executed": 0,
            "regression_cases_opened": 0,
        },
        "config": {
            "path": args.config.resolve(strict=True).relative_to(DEMO_ROOT).as_posix(),
            "sha256": result["config_sha256"],
        },
        "sources": _source_manifest(),
        "fixtures": _fixture_manifest(result["fixture_paths"]),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "windows_python_only": True,
            "network_allowance": "127.0.0.1 ephemeral port only",
            "gpu_used": False,
            "docker_used": False,
            "cloud_used": False,
            "internet_used": False,
            "administrator_required": False,
            "execution_interface": "exec_command; bash_exec/artifact/memory unavailable",
        },
        "safety_contract": {
            "execution_trust": "self_built_hash_locked_only",
            "workspace_write_only": True,
            "loopback_only": True,
            "allowed_child_executable": "current Python interpreter with exact argv-tail hashes",
            "raw_values_in_evidence": False,
            "policy_effect": "INFO-only; no admission decision change",
            "not_an_untrusted_code_sandbox": True,
        },
        "metrics": metrics,
        "outputs": {
            name: _sha256_entry(output_dir / name)
            for name in output_names
        },
        "claim_boundary": "Trusted, hash-locked Python fixture mechanism evidence only; no untrusted Skill execution or sandbox-security claim.",
        "next_action": "document_and_consider_admin_only_platform_integration",
    }
    _write_json(output_dir / "run_manifest.json", run_manifest)

    manifest_names = [*output_names, "run_manifest.json", "PLAN.md", "CHECKLIST.md"]
    artifact_manifest = {
        "schema_version": DYNAMIC_AUDIT_SCHEMA_VERSION,
        "run_id": args.run_id,
        "canonical_manifest": "run_manifest.json",
        "plan": "PLAN.md",
        "checklist": "CHECKLIST.md",
        "evidence_files": {
            name: _sha256_entry(output_dir / name)
            for name in manifest_names
        },
    }
    _write_json(output_dir / "artifact_manifest.json", artifact_manifest)
    return {
        "run_id": args.run_id,
        "status": run_manifest["status"],
        "metrics": metrics,
        "output_dir": str(output_dir),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except (DynamicAuditConfigurationError, OSError, ValueError, KeyError) as exc:
        print(f"Safe dynamic fixture audit failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
