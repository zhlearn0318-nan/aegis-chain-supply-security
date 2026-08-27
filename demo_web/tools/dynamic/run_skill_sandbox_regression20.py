from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.dynamic_audit.docker_backend import (  # noqa: E402
    DockerBackendError,
    _docker_prefix,
    _require_success,
    discover_docker_cli,
    run_docker_cli,
)
from backend.dynamic_audit.skill_sandbox_docker import (  # noqa: E402
    BACKEND_ID,
    load_skill_sandbox_config,
    run_python_skill_entrypoint,
)


RUN_ID = "2026-08-27-skill-dynamic-regression20-v2"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
DEFAULT_SANDBOX_CONFIG = DEMO_ROOT / "config" / "skill_dynamic_sandbox.json"
DEFAULT_SUITE_CONFIG = DEMO_ROOT / "config" / "skill_dynamic_regression20.json"
FIXTURE_ROOT = DEMO_ROOT / "tools" / "dynamic" / "fixtures" / "skill_sandbox_regression20"
EXPECTED_CASE_IDS = {
    "benign_noop", "benign_compute", "benign_workspace_write", "benign_loopback_request",
    "process_shell", "process_transfer_tool", "process_child_python", "process_os_system",
    "network_external_ip", "network_dns", "network_encoded_host", "decoy_read",
    "decoy_raw_exfil", "decoy_base64_exfil", "decoy_hex_exfil", "sensitive_passwd",
    "sensitive_ssh", "native_load_none", "native_load_libc", "resource_timeout",
}
EXPECTED_FAMILIES = {
    "benign_control", "process_execution", "external_network", "encoding_obfuscation",
    "sensitive_data", "sensitive_path", "dynamic_loading", "resource_abuse",
}
CASE_FIELDS = {
    "id", "family", "risk_class", "timeout_seconds", "expected_decision", "expected_rules", "files",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _file_record(path: Path) -> dict[str, str | int]:
    return {"sha256": _sha256(path), "bytes": path.stat().st_size}


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_text(path: Path, payload: str) -> None:
    path.write_text(payload.rstrip() + "\n", encoding="utf-8", newline="\n")


def load_regression_suite(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if set(payload) != {"schema_version", "suite_id", "seed", "repeats", "cases"}:
        raise ValueError("suite top-level fields changed")
    if payload["schema_version"] != "1.0" or payload["suite_id"] != "aegis-skill-dynamic-regression20-v2":
        raise ValueError("suite identity changed")
    if payload["seed"] != 20260827 or payload["repeats"] != 3:
        raise ValueError("suite seed or repeat count changed")
    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != 20:
        raise ValueError("suite must contain exactly 20 cases")
    ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != CASE_FIELDS:
            raise ValueError("case fields changed")
        case_id = case.get("id")
        if not isinstance(case_id, str) or case_id in ids:
            raise ValueError("case id invalid or duplicated")
        ids.add(case_id)
        if case.get("family") not in EXPECTED_FAMILIES:
            raise ValueError(f"case family invalid: {case_id}")
        if case.get("risk_class") not in {"benign", "review", "dangerous"}:
            raise ValueError(f"case risk class invalid: {case_id}")
        if case.get("expected_decision") not in {"ALLOW", "REVIEW", "BLOCK"}:
            raise ValueError(f"case expected decision invalid: {case_id}")
        if case.get("risk_class") == "benign" and case.get("expected_decision") != "ALLOW":
            raise ValueError(f"benign case must expect ALLOW: {case_id}")
        if case.get("risk_class") == "dangerous" and case.get("expected_decision") != "BLOCK":
            raise ValueError(f"dangerous case must expect BLOCK: {case_id}")
        if not isinstance(case.get("timeout_seconds"), (int, float)) or not 1 <= case["timeout_seconds"] <= 8:
            raise ValueError(f"case timeout invalid: {case_id}")
        if not isinstance(case.get("expected_rules"), list) or not all(
            isinstance(rule, str) and rule.startswith("AEGIS_DYNAMIC_") for rule in case["expected_rules"]
        ):
            raise ValueError(f"case expected rules invalid: {case_id}")
        if set(case.get("files") or {}) != {"SKILL.md", "run.py"}:
            raise ValueError(f"case file set invalid: {case_id}")
        if not all(
            isinstance(value, str) and len(value) == 64
            for value in case["files"].values()
        ):
            raise ValueError(f"case file hash invalid: {case_id}")
    if ids != EXPECTED_CASE_IDS:
        raise ValueError("suite case identity set changed")
    return payload


def verify_fixtures(suite: dict[str, Any]) -> list[tuple[dict[str, Any], Path]]:
    fixture_root = FIXTURE_ROOT.resolve(strict=True)
    actual_dirs = {path.name for path in fixture_root.iterdir() if path.is_dir()}
    if actual_dirs != EXPECTED_CASE_IDS:
        raise ValueError("fixture directory set changed")
    verified: list[tuple[dict[str, Any], Path]] = []
    for case in suite["cases"]:
        root = (fixture_root / case["id"]).resolve(strict=True)
        root.relative_to(fixture_root)
        if root.is_symlink():
            raise ValueError(f"fixture root link denied: {case['id']}")
        actual_files = {path.name for path in root.iterdir() if path.is_file()}
        if actual_files != set(case["files"]):
            raise ValueError(f"fixture file set changed: {case['id']}")
        for name, expected_hash in case["files"].items():
            candidate = (root / name).resolve(strict=True)
            candidate.relative_to(root)
            if candidate.is_symlink() or _sha256(candidate) != expected_hash:
                raise ValueError(f"fixture hash mismatch: {case['id']}/{name}")
        verified.append((case, root))
    return verified


def _summarize_case(case: dict[str, Any], raw: dict[str, Any], replicate: int) -> dict[str, Any]:
    runner = raw.get("runner") or {}
    evaluation = raw.get("evaluation") or {}
    findings = evaluation.get("findings") or []
    rules = sorted({str(item.get("rule_id")) for item in findings if isinstance(item, dict)})
    expected_rules = sorted(set(case["expected_rules"]))
    inspect_gates = raw.get("inspect_gates") or {}
    decision_correct = evaluation.get("decision") == case["expected_decision"]
    required_rules_present = set(expected_rules).issubset(rules)
    infrastructure_passed = (
        raw.get("success") is True
        and bool(inspect_gates)
        and all(inspect_gates.values())
        and (raw.get("cleanup") or {}).get("removed") is True
        and (raw.get("cleanup") or {}).get("residual") is False
        and runner.get("telemetry_complete") is True
    )
    return {
        "case_id": case["id"],
        "family": case["family"],
        "risk_class": case["risk_class"],
        "replicate": replicate,
        "expected_decision": case["expected_decision"],
        "observed_decision": evaluation.get("decision"),
        "decision_correct": decision_correct,
        "expected_rules": expected_rules,
        "observed_rules": rules,
        "required_rules_present": required_rules_present,
        "execution_status": runner.get("execution_status"),
        "highest_severity": evaluation.get("highest_severity"),
        "telemetry_complete": runner.get("telemetry_complete"),
        "event_type_counts": dict(sorted(Counter(
            str(item.get("type") or "unknown")
            for item in runner.get("events") or []
            if isinstance(item, dict)
        ).items())),
        "inspect_gates": {"passed": sum(value is True for value in inspect_gates.values()), "total": len(inspect_gates)},
        "cleanup": raw.get("cleanup"),
        "duration_ms": raw.get("duration_ms"),
        "error": raw.get("error"),
        "passed": bool(decision_correct and required_rules_present and infrastructure_passed),
    }


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * fraction))))
    return round(float(ordered[index]), 3)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the fixed 20-case real Docker Skill regression")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--sandbox-config", type=Path, default=DEFAULT_SANDBOX_CONFIG)
    parser.add_argument("--suite-config", type=Path, default=DEFAULT_SUITE_CONFIG)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    output = args.output.resolve(strict=False)
    output.mkdir(parents=True, exist_ok=True)
    protected = {
        "results.json", "metrics.json", "evaluation_summary.json", "run_manifest.json", "run.log", "bash.log",
    }
    existing = sorted(name for name in protected if (output / name).exists())
    if existing:
        raise ValueError(f"refusing to overwrite existing outputs: {existing}")

    suite = load_regression_suite(args.suite_config)
    verified = verify_fixtures(suite)
    sandbox_config = load_skill_sandbox_config(args.sandbox_config)
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    cases: list[dict[str, Any]] = []
    engine: dict[str, Any] = {}
    image: dict[str, Any] = {}
    for replicate in range(1, suite["repeats"] + 1):
        for case, root in verified:
            raw = run_python_skill_entrypoint(
                sandbox_config,
                root,
                "run.py",
                timeout_seconds=float(case["timeout_seconds"]),
            )
            engine = raw.get("engine") or engine
            image = raw.get("image") or image
            cases.append(_summarize_case(case, raw, replicate))

    docker_cli = discover_docker_cli()
    residual = run_docker_cli(
        [*_docker_prefix(docker_cli), "container", "ls", "--all", "--filter",
         f"label=aegis.dynamic.backend={BACKEND_ID}", "--format", "{{.ID}}"],
        timeout_seconds=15,
    )
    residual_ids = [line.strip() for line in _require_success(residual, "residual_container_query").splitlines() if line.strip()]
    elapsed_seconds = round(time.perf_counter() - started, 3)

    signatures: dict[str, set[tuple[str, tuple[str, ...]]]] = defaultdict(set)
    for case in cases:
        signatures[case["case_id"]].add((str(case["observed_decision"]), tuple(case["observed_rules"])))
    unstable_cases = sorted(case_id for case_id, values in signatures.items() if len(values) != 1)
    durations = [float(case["duration_ms"]) for case in cases if isinstance(case.get("duration_ms"), (int, float))]
    family_metrics: dict[str, dict[str, int]] = {}
    for family in sorted(EXPECTED_FAMILIES):
        subset = [case for case in cases if case["family"] == family]
        family_metrics[family] = {
            "executions": len(subset),
            "passed": sum(case["passed"] for case in subset),
            "decision_correct": sum(case["decision_correct"] for case in subset),
            "required_rules_present": sum(case["required_rules_present"] for case in subset),
        }
    metrics: dict[str, Any] = {
        "unique_scenarios": len(verified),
        "behavior_families": len(EXPECTED_FAMILIES),
        "repeats": suite["repeats"],
        "total_executions": len(cases),
        "passed_executions": sum(case["passed"] for case in cases),
        "decision_correct": sum(case["decision_correct"] for case in cases),
        "required_rule_checks_passed": sum(case["required_rules_present"] for case in cases),
        "dynamic_allows": sum(case["observed_decision"] == "ALLOW" for case in cases),
        "dynamic_reviews": sum(case["observed_decision"] == "REVIEW" for case in cases),
        "dynamic_blocks": sum(case["observed_decision"] == "BLOCK" for case in cases),
        "benign_false_positives": sum(case["risk_class"] == "benign" and case["observed_decision"] != "ALLOW" for case in cases),
        "dangerous_false_negatives": sum(case["risk_class"] == "dangerous" and case["observed_decision"] != "BLOCK" for case in cases),
        "review_mismatches": sum(case["risk_class"] == "review" and case["observed_decision"] != "REVIEW" for case in cases),
        "unstable_case_count": len(unstable_cases),
        "unstable_cases": unstable_cases,
        "telemetry_incomplete": sum(case["telemetry_complete"] is not True for case in cases),
        "cleanup_failures": sum((case.get("cleanup") or {}).get("removed") is not True for case in cases),
        "container_residuals": len(residual_ids),
        "duration_ms_median": round(statistics.median(durations), 3) if durations else 0.0,
        "duration_ms_p95": _percentile(durations, 0.95),
        "duration_ms_max": round(max(durations), 3) if durations else 0.0,
        "elapsed_seconds": elapsed_seconds,
        "family_metrics": family_metrics,
        "third_party_samples_executed": 0,
        "gpu_used": False,
        "cloud_used": False,
        "internet_used": False,
    }
    accepted = (
        metrics["total_executions"] == 60
        and metrics["passed_executions"] == 60
        and metrics["decision_correct"] == 60
        and metrics["required_rule_checks_passed"] == 60
        and metrics["benign_false_positives"] == 0
        and metrics["dangerous_false_negatives"] == 0
        and metrics["review_mismatches"] == 0
        and metrics["unstable_case_count"] == 0
        and metrics["telemetry_incomplete"] == 0
        and metrics["cleanup_failures"] == 0
        and metrics["container_residuals"] == 0
    )
    results = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "accepted" if accepted else "failed",
        "cases": cases,
        "residual_container_ids": residual_ids,
    }
    evaluation = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "outcome_summary": (
            "20 个自建 Skill 动态场景在真实 Docker 中连续 3 轮全部符合预期。"
            if accepted else "20 样本稳定性回归至少有一项接受门未通过。"
        ),
        "evaluation_summary": {
            "status": results["status"],
            "executions": metrics["total_executions"],
            "passed": metrics["passed_executions"],
            "behavior_families": metrics["behavior_families"],
        },
        "claim_update": "supported_on_controlled_20_case_regression" if accepted else "refuted_or_inconclusive",
        "baseline_relation": "repairs_v1_os_system_semantic_label_and_extends_5_case_baseline" if accepted else "does_not_meet_corrected_v2_gate",
        "failure_mode": None if accepted else {
            "failed_cases": [f"{case['case_id']}#r{case['replicate']}" for case in cases if not case["passed"]],
            "unstable_cases": unstable_cases,
            "container_residual_ids": residual_ids,
        },
        "next_action": "analyze_rule_gaps_and_add_third_party_safe_corpus" if accepted else "repair_failed_cases_without_relaxing_sandbox",
        "limits": [
            "全部样本均为项目自建受控 fixture，不能据此声称现实第三方 Skill 的泛化检测率。",
            "Python audit hook 是行为证据采集层，不是不可绕过的内核安全边界。",
            "尚未形成 Falco/eBPF 内核级交叉证据。",
            "Docker Desktop/WSL2 不等同于专用恶意代码分析虚拟机。",
        ],
    }
    _write_json(output / "results.json", results)
    _write_json(output / "metrics.json", metrics)
    _write_json(output / "evaluation_summary.json", evaluation)

    fixture_sources = {
        f"tools/dynamic/fixtures/skill_sandbox_regression20/{case['id']}/{name}": _file_record(root / name)
        for case, root in verified for name in case["files"]
    }
    source_names = (
        "backend/dynamic_audit/skill_sandbox.py",
        "backend/dynamic_audit/skill_sandbox_docker.py",
        "config/skill_dynamic_sandbox.json",
        "config/skill_dynamic_regression20.json",
        "tools/dynamic/docker/skill_sandbox/runner.py",
        "tools/dynamic/docker/skill_sandbox/sitecustomize.py",
        "tools/dynamic/run_skill_sandbox_regression20.py",
    )
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": results["status"],
        "experiment_tier": "auxiliary/dev-regression",
        "seed": suite["seed"],
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "command": [sys.executable, *sys.argv],
        "environment": {
            "host_python": sys.version,
            "host_platform": platform.platform(),
            "docker_engine": engine,
            "container_image": image,
            "gpu_used": False,
            "cloud_used": False,
            "internet_used": False,
            "image_pull_used": False,
            "execution_interface": "Codex exec_command (bash_exec/artifact tools unavailable in this environment)",
        },
        "dataset": {
            "self_built_fixtures": len(verified),
            "behavior_families": len(EXPECTED_FAMILIES),
            "repeats": suite["repeats"],
            "total_executions": len(cases),
            "third_party_samples_executed": 0,
        },
        "sources": {**{name: _file_record(DEMO_ROOT / name) for name in source_names}, **fixture_sources},
        "metrics": metrics,
        "claim_boundary": evaluation["limits"],
    }
    _write_json(output / "run_manifest.json", manifest)
    _write_text(output / "bash.log", "execution_interface=Codex exec_command\nbash_exec_available=false\nartifact_tool_available=false")
    _write_text(output / "run.log", "\n".join([
        f"run_id={RUN_ID}",
        f"status={results['status']}",
        *(f"case={case['case_id']} replicate={case['replicate']} expected={case['expected_decision']} observed={case['observed_decision']} passed={case['passed']} duration_ms={case['duration_ms']}" for case in cases),
        f"unstable_cases={','.join(unstable_cases)}",
        f"container_residuals={len(residual_ids)}",
        f"elapsed_seconds={elapsed_seconds}",
    ]))
    return {"status": results["status"], "metrics": metrics, "output": str(output)}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except (DockerBackendError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Skill regression failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "accepted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
