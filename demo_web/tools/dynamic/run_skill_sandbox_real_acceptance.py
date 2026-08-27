from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from collections import Counter
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


RUN_ID = "2026-08-27-skill-dynamic-sandbox-real-v2"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
DEFAULT_CONFIG = DEMO_ROOT / "config" / "skill_dynamic_sandbox.json"
FIXTURE_ROOT = DEMO_ROOT / "tools" / "dynamic" / "fixtures" / "skill_sandbox_samples"
FIXTURES: tuple[dict[str, Any], ...] = (
    {
        "id": "safe_skill",
        "timeout_seconds": 8.0,
        "expected_decision": "ALLOW",
        "expected_rules": (),
        "files": {
            "SKILL.md": "65dbb2a015f37edd0e638ad0c7682ca08372a180b8666741f859cd19f2649ed0",
            "run.py": "801a926578d7c96b4f518043af6474dce6afa49047abd03936251828add65ba3",
        },
    },
    {
        "id": "external_network_skill",
        "timeout_seconds": 8.0,
        "expected_decision": "BLOCK",
        "expected_rules": ("AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT",),
        "files": {
            "SKILL.md": "0816593c6fa959dc1e767301374b53a0f0e0f4f5dfc815b7aa7cf897d9397430",
            "run.py": "1769026f6185a2823f2956d9dcd0f2c8d9ce92af7eb60a27fa7e27cfbd7d4049",
        },
    },
    {
        "id": "decoy_exfiltration_skill",
        "timeout_seconds": 8.0,
        "expected_decision": "BLOCK",
        "expected_rules": (
            "AEGIS_DYNAMIC_DECOY_ACCESS",
            "AEGIS_DYNAMIC_DECOY_EXFILTRATION",
        ),
        "files": {
            "SKILL.md": "6b5d3c9d82b8dc85b7bac0f182c7cc552dfd217a4c4b2da03dc7731b5bc35075",
            "run.py": "8b43f25bcb9b0d2dacc197a6df2af372f6f4c901943c0b4895adfea65dc3596a",
        },
    },
    {
        "id": "shell_spawn_skill",
        "timeout_seconds": 8.0,
        "expected_decision": "BLOCK",
        "expected_rules": ("AEGIS_DYNAMIC_SHELL_SPAWN",),
        "files": {
            "SKILL.md": "1d4e8b51770910aaa320001f209e47d2a740795b640bf17d1d3bceb0ef4ecabb",
            "run.py": "b9e887e2f5aec3a144c60b311131e4bb64c02e2b622f3f40b7b505f100faa53d",
        },
    },
    {
        "id": "timeout_skill",
        "timeout_seconds": 2.0,
        "expected_decision": "REVIEW",
        "expected_rules": (
            "AEGIS_DYNAMIC_RESOURCE_OR_TIMEOUT",
            "AEGIS_DYNAMIC_EXECUTION_INCONCLUSIVE",
        ),
        "files": {
            "SKILL.md": "a3fc8dfe379437d3a932943a8239e1fd0103e94b5bca2d77c4378116012eca27",
            "run.py": "125fd5d43355a1c49366b8c85fa762fa630bcd5ee9bd1136fb212728d6c76d82",
        },
    },
)


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


def _verify_fixture(fixture: dict[str, Any]) -> Path:
    root = (FIXTURE_ROOT / fixture["id"]).resolve(strict=True)
    root.relative_to(FIXTURE_ROOT.resolve(strict=True))
    actual_names = {path.name for path in root.iterdir() if path.is_file()}
    if actual_names != set(fixture["files"]):
        raise ValueError(f"fixture file set changed: {fixture['id']}")
    for name, expected in fixture["files"].items():
        candidate = (root / name).resolve(strict=True)
        candidate.relative_to(root)
        if candidate.is_symlink() or _sha256(candidate) != expected:
            raise ValueError(f"fixture hash mismatch: {fixture['id']}/{name}")
    return root


def _summarize_case(
    fixture: dict[str, Any], raw: dict[str, Any], *, replicate: int
) -> dict[str, Any]:
    runner = raw.get("runner") or {}
    evaluation = raw.get("evaluation") or {}
    findings = evaluation.get("findings") or []
    rules = sorted({str(item.get("rule_id")) for item in findings if isinstance(item, dict)})
    expected_rules = set(fixture["expected_rules"])
    event_counts = Counter(
        str(item.get("type") or "unknown")
        for item in runner.get("events") or []
        if isinstance(item, dict)
    )
    inspect_gates = raw.get("inspect_gates") or {}
    passed = (
        raw.get("success") is True
        and evaluation.get("decision") == fixture["expected_decision"]
        and expected_rules.issubset(rules)
        and inspect_gates
        and all(inspect_gates.values())
        and (raw.get("cleanup") or {}).get("removed") is True
        and (raw.get("cleanup") or {}).get("residual") is False
        and runner.get("telemetry_complete") is True
    )
    return {
        "case_id": fixture["id"],
        "replicate": replicate,
        "expected_decision": fixture["expected_decision"],
        "observed_decision": evaluation.get("decision"),
        "expected_rules": sorted(expected_rules),
        "observed_rules": rules,
        "execution_status": runner.get("execution_status"),
        "highest_severity": evaluation.get("highest_severity"),
        "telemetry_complete": runner.get("telemetry_complete"),
        "event_type_counts": dict(sorted(event_counts.items())),
        "inspect_gates": {
            "passed": sum(value is True for value in inspect_gates.values()),
            "total": len(inspect_gates),
        },
        "cleanup": raw.get("cleanup"),
        "duration_ms": raw.get("duration_ms"),
        "error": raw.get("error"),
        "passed": passed,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run real Docker acceptance for the Skill sandbox")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--repeats", type=int, default=3)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not 1 <= args.repeats <= 5:
        raise ValueError("repeats must be between 1 and 5")
    output = args.output.resolve(strict=False)
    output.mkdir(parents=True, exist_ok=True)
    protected = ("results.json", "metrics.json", "evaluation_summary.json", "run_manifest.json", "run.log")
    existing = [name for name in protected if (output / name).exists()]
    if existing:
        raise ValueError(f"refusing to overwrite existing outputs: {existing}")

    config = load_skill_sandbox_config(args.config)
    verified = [(fixture, _verify_fixture(fixture)) for fixture in FIXTURES]
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    cases: list[dict[str, Any]] = []
    engine: dict[str, Any] = {}
    image: dict[str, Any] = {}
    for replicate in range(1, args.repeats + 1):
        for fixture, root in verified:
            raw = run_python_skill_entrypoint(
                config,
                root,
                "run.py",
                timeout_seconds=float(fixture["timeout_seconds"]),
            )
            engine = raw.get("engine") or engine
            image = raw.get("image") or image
            cases.append(_summarize_case(fixture, raw, replicate=replicate))

    docker_cli = discover_docker_cli()
    residual_result = run_docker_cli(
        [
            *_docker_prefix(docker_cli),
            "container",
            "ls",
            "--all",
            "--filter",
            f"label=aegis.dynamic.backend={BACKEND_ID}",
            "--format",
            "{{.ID}}",
        ],
        timeout_seconds=15,
    )
    residual_output = _require_success(residual_result, "residual_container_query")
    residual_ids = [line.strip() for line in residual_output.splitlines() if line.strip()]
    elapsed_seconds = round(time.perf_counter() - started, 3)
    completed_at = datetime.now(timezone.utc)
    metrics = {
        "unique_scenarios": len(FIXTURES),
        "repeats": args.repeats,
        "total_executions": len(cases),
        "passed_executions": sum(case["passed"] for case in cases),
        "decision_correct": sum(case["expected_decision"] == case["observed_decision"] for case in cases),
        "dynamic_blocks": sum(case["observed_decision"] == "BLOCK" for case in cases),
        "dynamic_reviews": sum(case["observed_decision"] == "REVIEW" for case in cases),
        "safe_false_positives": sum(
            case["case_id"] == "safe_skill" and case["observed_decision"] != "ALLOW" for case in cases
        ),
        "dangerous_false_negatives": sum(
            case["expected_decision"] == "BLOCK" and case["observed_decision"] != "BLOCK" for case in cases
        ),
        "telemetry_incomplete": sum(case["telemetry_complete"] is not True for case in cases),
        "cleanup_failures": sum((case.get("cleanup") or {}).get("removed") is not True for case in cases),
        "container_residuals": len(residual_ids),
        "third_party_samples_executed": 0,
        "gpu_used": False,
        "elapsed_seconds": elapsed_seconds,
    }
    accepted = (
        metrics["passed_executions"] == metrics["total_executions"]
        and metrics["safe_false_positives"] == 0
        and metrics["dangerous_false_negatives"] == 0
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
        "claim_update": "supported_on_self_built_real_docker_fixtures" if accepted else "refuted_or_inconclusive",
        "outcome_summary": (
            "真实 Docker 容器已正确区分 5 类自建 Skill 行为，且观测完整、清理无残留。"
            if accepted
            else "至少一个真实 Docker 接受门未通过，不能声明动态沙箱已闭环。"
        ),
        "limits": [
            "仅覆盖自建 Python fixture，尚未执行第三方 Skill。",
            "Python audit hook 是行为证据采集层，不是容器安全边界。",
            "尚未形成 Falco/eBPF 内核级交叉证据。",
            "Docker Desktop/WSL2 不等同于恶意代码专用虚拟机。",
        ],
        "next_action": "expand_regression_and_optional_falco_preflight" if accepted else "repair_failed_acceptance_gate",
    }
    _write_json(output / "results.json", results)
    _write_json(output / "metrics.json", metrics)
    _write_json(output / "evaluation_summary.json", evaluation)

    fixture_sources = {
        f"tools/dynamic/fixtures/skill_sandbox_samples/{fixture['id']}/{name}": _file_record(root / name)
        for fixture, root in verified
        for name in fixture["files"]
    }
    source_names = (
        "backend/dynamic_audit/skill_sandbox.py",
        "backend/dynamic_audit/skill_sandbox_docker.py",
        "config/skill_dynamic_sandbox.json",
        "tools/dynamic/docker/skill_sandbox/runner.py",
        "tools/dynamic/docker/skill_sandbox/sitecustomize.py",
        "tools/dynamic/run_skill_sandbox_real_acceptance.py",
    )
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": results["status"],
        "experiment_tier": "auxiliary/dev-real-runtime",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "command": [sys.executable, *sys.argv],
        "environment": {
            "host_python": sys.version,
            "host_platform": platform.platform(),
            "docker_engine": engine,
            "container_image": image,
            "gpu_used": False,
            "cloud_used": False,
            "image_pull_used": False,
        },
        "dataset": {
            "self_built_fixtures": len(FIXTURES),
            "repeats": args.repeats,
            "total_executions": len(cases),
            "third_party_samples_executed": 0,
        },
        "sources": {
            **{name: _file_record(DEMO_ROOT / name) for name in source_names},
            **fixture_sources,
        },
        "metrics": metrics,
        "claim_boundary": evaluation["limits"],
    }
    _write_json(output / "run_manifest.json", manifest)
    _write_text(
        output / "run.log",
        "\n".join(
            [
                f"run_id={RUN_ID}",
                f"status={results['status']}",
                *(f"case={case['case_id']} replicate={case['replicate']} expected={case['expected_decision']} observed={case['observed_decision']} passed={case['passed']} duration_ms={case['duration_ms']}" for case in cases),
                f"container_residuals={metrics['container_residuals']}",
                f"elapsed_seconds={elapsed_seconds}",
            ]
        ),
    )
    return {"status": results["status"], "metrics": metrics, "output": str(output)}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except (DockerBackendError, OSError, ValueError, KeyError) as exc:
        print(f"Skill sandbox acceptance failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "accepted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
