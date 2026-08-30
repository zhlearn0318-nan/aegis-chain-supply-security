from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.dynamic_audit.docker_backend import (  # noqa: E402
    _docker_prefix,
    _require_success,
    discover_docker_cli,
    probe_docker_engine,
    run_docker_cli,
)
from backend.dynamic_audit.skill_sandbox_docker import BACKEND_ID  # noqa: E402
from backend.install_policy_audit import (  # noqa: E402
    read_recent_install_policy_audits,
    verify_install_policy_audit,
)
from backend.openclaw_install_policy import (  # noqa: E402
    evaluate_install_request,
    hash_source_tree,
)


RUN_ID = "2026-08-27-openclaw-skill-dynamic-e2e-v2"
EXPECTED_OPENCLAW_VERSION = "2026.7.1-2"
EXPECTED_OPENCLAW_COMMIT = "0790d9f"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
DEFAULT_RUNTIME = DEMO_ROOT / "data" / RUN_ID
FIXTURE_ROOT = DEMO_ROOT / "tools" / "dynamic" / "fixtures" / "skill_sandbox_samples"
POLICY_SCRIPT = DEMO_ROOT / "tools" / "openclaw_install_policy.py"
PYTHON_RUNTIME = REPOSITORY_ROOT / ".runtime_mcp313" / "Scripts" / "python.exe"
TEST_SLUGS = {
    "safe": "aegis-dyn-safe",
    "shell": "aegis-dyn-shell-block",
    "invalid": "aegis-dyn-config-block",
}
FIXTURES: dict[str, dict[str, str]] = {
    "safe_skill": {
        "SKILL.md": "65dbb2a015f37edd0e638ad0c7682ca08372a180b8666741f859cd19f2649ed0",
        "run.py": "801a926578d7c96b4f518043af6474dce6afa49047abd03936251828add65ba3",
    },
    "shell_spawn_skill": {
        "SKILL.md": "1d4e8b51770910aaa320001f209e47d2a740795b640bf17d1d3bceb0ef4ecabb",
        "run.py": "b9e887e2f5aec3a144c60b311131e4bb64c02e2b622f3f40b7b505f100faa53d",
    },
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


def _redact(value: str, runtime_root: Path) -> str:
    replacements = [
        (str(runtime_root), "<RUNTIME>"),
        (str(REPOSITORY_ROOT), "<REPOSITORY>"),
        (str(Path.home()), "<USER_HOME>"),
    ]
    text = value
    for raw, replacement in replacements:
        text = text.replace(raw, replacement).replace(raw.replace("\\", "/"), replacement)
    return text[-8_000:]


def _verify_fixture(name: str) -> Path:
    root = (FIXTURE_ROOT / name).resolve(strict=True)
    root.relative_to(FIXTURE_ROOT.resolve(strict=True))
    expected = FIXTURES[name]
    actual_names = {item.name for item in root.iterdir() if item.is_file()}
    if actual_names != set(expected):
        raise ValueError(f"fixture file set changed: {name}")
    for relative, expected_hash in expected.items():
        candidate = (root / relative).resolve(strict=True)
        candidate.relative_to(root)
        if candidate.is_symlink() or _sha256(candidate) != expected_hash:
            raise ValueError(f"fixture hash mismatch: {name}/{relative}")
    return root


def _discover_openclaw() -> tuple[Path, Path, Path]:
    app_data = os.environ.get("APPDATA", "").strip()
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files").strip()
    candidates = [
        Path(app_data) / "npm" / "node_modules" / "openclaw" / "openclaw.mjs"
        if app_data
        else Path("__missing__"),
    ]
    entrypoint = next((path.resolve(strict=True) for path in candidates if path.is_file()), None)
    if entrypoint is None or entrypoint.name != "openclaw.mjs":
        raise ValueError("trusted OpenClaw entrypoint not found")
    node_candidates = [
        Path(program_files) / "nodejs" / "node.exe",
        Path(shutil.which("node.exe") or shutil.which("node") or "__missing__"),
    ]
    node = next((path.resolve(strict=True) for path in node_candidates if path.is_file()), None)
    if node is None or node.name.casefold() != "node.exe":
        raise ValueError("trusted Node.js runtime not found")
    wrapper = entrypoint.parents[2] / "openclaw.cmd"
    if not wrapper.is_file():
        raise ValueError("OpenClaw command wrapper not found")
    return node, entrypoint, wrapper.resolve(strict=True)


def _run_command(
    command: list[str], env: dict[str, str], *, timeout_seconds: float
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        timeout=timeout_seconds,
        check=False,
        creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
    )


def _base_environment(
    runtime_root: Path, config_path: Path, state_dir: Path, node: Path
) -> dict[str, str]:
    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    profile = runtime_root / "profile"
    temp = runtime_root / "temp"
    roaming = profile / "AppData" / "Roaming"
    local = profile / "AppData" / "Local"
    for path in (profile, temp, roaming, local, state_dir):
        path.mkdir(parents=True, exist_ok=True)
    path_entries = [node.parent, Path(system_root) / "System32", Path(system_root)]
    return {
        "SYSTEMROOT": system_root,
        "WINDIR": system_root,
        "COMSPEC": str(Path(system_root) / "System32" / "cmd.exe"),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "PATH": os.pathsep.join(str(path) for path in path_entries),
        "TEMP": str(temp),
        "TMP": str(temp),
        "USERPROFILE": str(profile),
        "HOME": str(profile),
        "APPDATA": str(roaming),
        "LOCALAPPDATA": str(local),
        "OPENCLAW_CONFIG_PATH": str(config_path),
        "OPENCLAW_STATE_DIR": str(state_dir),
        "CI": "1",
        "NO_COLOR": "1",
    }


def _policy_config(
    workspace: Path, audit_db: Path, *, dynamic_mode: str
) -> dict[str, Any]:
    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    docker_bin = (
        Path(local_app_data) / "Programs" / "DockerDesktop" / "resources" / "bin"
        if local_app_data
        else Path(program_files) / "Docker" / "Docker" / "resources" / "bin"
    )
    docker_config = (Path.home() / ".docker").resolve(strict=True)
    if not docker_config.is_dir():
        raise ValueError("Docker CLI config directory is unavailable")
    policy_path = os.pathsep.join(
        [str(docker_bin), str(Path(system_root) / "System32"), system_root]
    )
    return {
        "agents": {"defaults": {"workspace": str(workspace)}},
        "security": {
            "installPolicy": {
                "enabled": True,
                "targets": ["skill"],
                "exec": {
                    "source": "exec",
                    "command": str(PYTHON_RUNTIME.resolve(strict=True)),
                    "args": [str(POLICY_SCRIPT.resolve(strict=True))],
                    "timeoutMs": 135000,
                    "noOutputTimeoutMs": 135000,
                    "maxOutputBytes": 1048576,
                    "passEnv": [],
                    "env": {
                        "AEGIS_OPENCLAW_SCAN_TIMEOUT_SECONDS": "60",
                        "AEGIS_OPENCLAW_REVIEW_MODE": "block",
                        "AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY": dynamic_mode,
                        "AEGIS_OPENCLAW_AUDIT_DB": str(audit_db),
                        "PYTHONUTF8": "1",
                        "PYTHONIOENCODING": "utf-8",
                        "SYSTEMROOT": system_root,
                        "WINDIR": system_root,
                        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                        "LOCALAPPDATA": local_app_data,
                        "ProgramFiles": program_files,
                        "DOCKER_CONFIG": str(docker_config),
                        "PATH": policy_path,
                    },
                    "trustedDirs": [
                        str(PYTHON_RUNTIME.resolve(strict=True).parent),
                        str(POLICY_SCRIPT.resolve(strict=True).parent),
                    ],
                    "allowInsecurePath": True,
                },
            }
        },
    }


@contextmanager
def _temporary_environment(updates: dict[str, str]) -> Iterator[None]:
    previous = {name: os.environ.get(name) for name in updates}
    try:
        os.environ.update(updates)
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _static_control(name: str, root: Path) -> dict[str, Any]:
    payload = {
        "protocolVersion": 1,
        "openclawVersion": EXPECTED_OPENCLAW_VERSION,
        "targetType": "skill",
        "targetName": name,
        "sourcePath": str(root),
        "sourcePathKind": "directory",
    }
    with _temporary_environment(
        {
            "AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY": "disabled",
            "AEGIS_OPENCLAW_REVIEW_MODE": "block",
        }
    ):
        return evaluate_install_request(payload)


def _install_case(
    *,
    node: Path,
    entrypoint: Path,
    env: dict[str, str],
    source: Path,
    slug: str,
    workspace: Path,
    expected_success: bool,
    runtime_root: Path,
) -> dict[str, Any]:
    destination = workspace / "skills" / slug
    if destination.exists():
        raise ValueError(f"refusing to overwrite existing destination: {slug}")
    started = time.perf_counter()
    completed = _run_command(
        [str(node), str(entrypoint), "skills", "install", str(source), "--as", slug],
        env,
        timeout_seconds=150,
    )
    exists = destination.is_dir()
    passed = (completed.returncode == 0 and exists) if expected_success else (
        completed.returncode != 0 and not exists
    )
    return {
        "slug": slug,
        "expected_success": expected_success,
        "exit_code": completed.returncode,
        "destination_exists": exists,
        "passed": passed,
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "stdout": _redact(completed.stdout, runtime_root),
        "stderr": _redact(completed.stderr, runtime_root),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run real OpenClaw required dynamic Skill admission E2E")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    output = args.output.resolve(strict=False)
    runtime_root = args.runtime_root.resolve(strict=False)
    protected = (
        "results.json",
        "metrics.json",
        "evaluation_summary.json",
        "run_manifest.json",
        "run.log",
        "artifact_manifest.json",
    )
    output.mkdir(parents=True, exist_ok=True)
    existing_outputs = [name for name in protected if (output / name).exists()]
    if existing_outputs:
        raise ValueError(f"refusing to overwrite existing outputs: {existing_outputs}")
    if runtime_root.exists():
        raise ValueError(f"refusing to reuse runtime root: {runtime_root}")
    runtime_root.mkdir(parents=True)

    node, openclaw_entrypoint, openclaw_wrapper = _discover_openclaw()
    version_result = _run_command(
        [str(node), str(openclaw_entrypoint), "--version"],
        _base_environment(runtime_root, runtime_root / "version.json", runtime_root / "version-state", node),
        timeout_seconds=30,
    )
    version_text = (version_result.stdout + "\n" + version_result.stderr).strip()
    if (
        version_result.returncode != 0
        or EXPECTED_OPENCLAW_VERSION not in version_text
        or EXPECTED_OPENCLAW_COMMIT not in version_text
    ):
        raise ValueError("unexpected OpenClaw version")

    safe_root = _verify_fixture("safe_skill")
    shell_root = _verify_fixture("shell_spawn_skill")
    source_hashes_before = {
        "safe_skill": hash_source_tree(safe_root),
        "shell_spawn_skill": hash_source_tree(shell_root),
    }
    static_controls = {
        "safe_skill": _static_control("safe_skill", safe_root),
        "shell_spawn_skill": _static_control("shell_spawn_skill", shell_root),
    }

    state_dir = runtime_root / "state"
    workspace = runtime_root / "workspace"
    audit_db = runtime_root / "admission_audit.db"
    required_config = runtime_root / "openclaw-required.json"
    invalid_config = runtime_root / "openclaw-invalid.json"
    workspace.mkdir(parents=True)
    _write_json(required_config, _policy_config(workspace, audit_db, dynamic_mode="required"))
    _write_json(invalid_config, _policy_config(workspace, audit_db, dynamic_mode="unexpected"))
    required_env = _base_environment(runtime_root, required_config, state_dir, node)
    invalid_env = _base_environment(runtime_root, invalid_config, state_dir, node)

    required_validate = _run_command(
        [str(node), str(openclaw_entrypoint), "config", "validate", "--json"],
        required_env,
        timeout_seconds=30,
    )
    invalid_validate = _run_command(
        [str(node), str(openclaw_entrypoint), "config", "validate", "--json"],
        invalid_env,
        timeout_seconds=30,
    )
    config_validation = {
        "required_exit_code": required_validate.returncode,
        "invalid_mode_schema_exit_code": invalid_validate.returncode,
        "passed": required_validate.returncode == 0 and invalid_validate.returncode == 0,
    }

    default_workspace = Path.home() / ".openclaw" / "workspace" / "skills"
    default_before = {
        slug: (default_workspace / slug).exists() for slug in TEST_SLUGS.values()
    }
    cases = [
        _install_case(
            node=node,
            entrypoint=openclaw_entrypoint,
            env=required_env,
            source=safe_root,
            slug=TEST_SLUGS["safe"],
            workspace=workspace,
            expected_success=True,
            runtime_root=runtime_root,
        ),
        _install_case(
            node=node,
            entrypoint=openclaw_entrypoint,
            env=required_env,
            source=shell_root,
            slug=TEST_SLUGS["shell"],
            workspace=workspace,
            expected_success=False,
            runtime_root=runtime_root,
        ),
        _install_case(
            node=node,
            entrypoint=openclaw_entrypoint,
            env=invalid_env,
            source=safe_root,
            slug=TEST_SLUGS["invalid"],
            workspace=workspace,
            expected_success=False,
            runtime_root=runtime_root,
        ),
    ]
    default_after = {
        slug: (default_workspace / slug).exists() for slug in TEST_SLUGS.values()
    }

    source_hashes_after = {
        "safe_skill": hash_source_tree(safe_root),
        "shell_spawn_skill": hash_source_tree(shell_root),
    }
    audit_verification = verify_install_policy_audit(audit_db)
    audits = list(reversed(read_recent_install_policy_audits(audit_db, limit=20)))
    safe_hash = source_hashes_before["safe_skill"]
    shell_hash = source_hashes_before["shell_spawn_skill"]
    audit_gates = {
        "safe_allow": any(
            row.get("source_tree_sha256") == safe_hash and row.get("decision") == "allow"
            for row in audits
        ),
        "dynamic_shell_block": any(
            row.get("source_tree_sha256") == shell_hash
            and row.get("decision") == "block"
            and "AEGIS_DYNAMIC_SHELL_SPAWN" in row.get("finding_rule_ids", [])
            for row in audits
        ),
        "invalid_mode_block": any(
            row.get("source_tree_sha256") == safe_hash
            and row.get("decision") == "block"
            and "AEGIS_DYNAMIC_POLICY_CONFIG_INVALID" in row.get("finding_rule_ids", [])
            for row in audits
        ),
    }

    docker_cli = discover_docker_cli()
    engine = probe_docker_engine(docker_cli)
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
    unexpected_isolated = [
        path.name
        for path in (workspace / "skills").iterdir()
        if path.name != TEST_SLUGS["safe"]
    ] if (workspace / "skills").is_dir() else []

    metrics = {
        "cases_total": len(cases),
        "cases_passed": sum(case["passed"] for case in cases),
        "static_allow_controls": sum(
            response.get("decision") == "allow" for response in static_controls.values()
        ),
        "audit_rows": audit_verification.get("rows", 0),
        "audit_chain_valid": audit_verification.get("valid") is True,
        "audit_gates_passed": sum(audit_gates.values()),
        "audit_gates_total": len(audit_gates),
        "source_hash_changes": sum(
            source_hashes_before[name] != source_hashes_after[name]
            for name in source_hashes_before
        ),
        "blocked_install_residuals": sum(
            (workspace / "skills" / TEST_SLUGS[name]).exists()
            for name in ("shell", "invalid")
        ),
        "unexpected_isolated_workspace_entries": len(unexpected_isolated),
        "default_workspace_test_residuals": sum(default_after.values()),
        "default_workspace_preexisting_test_slugs": sum(default_before.values()),
        "docker_container_residuals": len(residual_ids),
        "docker_config_explicit": True,
        "third_party_samples_executed": 0,
        "gpu_used": False,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }
    accepted = (
        config_validation["passed"]
        and metrics["cases_passed"] == metrics["cases_total"]
        and metrics["static_allow_controls"] == 2
        and metrics["audit_chain_valid"]
        and metrics["audit_gates_passed"] == metrics["audit_gates_total"]
        and metrics["source_hash_changes"] == 0
        and metrics["blocked_install_residuals"] == 0
        and metrics["unexpected_isolated_workspace_entries"] == 0
        and metrics["default_workspace_preexisting_test_slugs"] == 0
        and metrics["default_workspace_test_residuals"] == 0
        and metrics["docker_container_residuals"] == 0
    )
    results = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "accepted" if accepted else "failed",
        "openclaw": {
            "version": EXPECTED_OPENCLAW_VERSION,
            "commit": EXPECTED_OPENCLAW_COMMIT,
            "node": str(node),
            "entrypoint_sha256": _sha256(openclaw_entrypoint),
            "wrapper_sha256": _sha256(openclaw_wrapper),
        },
        "config_validation": config_validation,
        "static_controls": static_controls,
        "cases": cases,
        "audit_verification": audit_verification,
        "audit_gates": audit_gates,
        "audits": audits,
        "source_hashes_before": source_hashes_before,
        "source_hashes_after": source_hashes_after,
        "unexpected_isolated_workspace_entries": unexpected_isolated,
        "docker_residual_ids": residual_ids,
        "docker_context_policy": "explicit_trusted_cli_config_not_mounted_to_target",
    }
    _write_json(output / "results.json", results)
    _write_json(output / "metrics.json", metrics)
    evaluation = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "claim_update": "supported_real_openclaw_required_dynamic_admission" if accepted else "refuted_or_inconclusive",
        "outcome_summary": (
            "真实 OpenClaw 已完成安全安装、静态 ALLOW 到动态 BLOCK、配置异常失败关闭三条安装前闭环。"
            if accepted
            else "至少一个 OpenClaw required 动态准入接受门未通过。"
        ),
        "limits": [
            "仅执行哈希锁定的自建 Python Skill fixture。",
            "当前 OpenClaw 稳定版将 REVIEW 兼容映射为 block。",
            "Docker Desktop/WSL2 不等同于恶意代码专用虚拟机。",
            "Falco/eBPF 与第三方 Skill 尚未验收。",
        ],
        "next_action": "expand_dynamic_regression_before_third_party_trial" if accepted else "repair_failed_e2e_gate",
    }
    _write_json(output / "evaluation_summary.json", evaluation)

    source_names = (
        "backend/openclaw_install_policy.py",
        "backend/install_policy_audit.py",
        "backend/dynamic_audit/skill_sandbox.py",
        "backend/dynamic_audit/skill_sandbox_docker.py",
        "config/skill_dynamic_sandbox.json",
        "tools/openclaw_install_policy.py",
        "tools/dynamic/run_openclaw_skill_dynamic_e2e.py",
    )
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": results["status"],
        "experiment_tier": "auxiliary/dev-real-platform-e2e",
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "host_platform": platform.platform(),
            "host_python": sys.version,
            "openclaw_version": EXPECTED_OPENCLAW_VERSION,
            "openclaw_commit": EXPECTED_OPENCLAW_COMMIT,
            "docker_engine": engine,
            "gpu_used": False,
            "third_party_samples_executed": 0,
        },
        "sources": {
            **{name: _file_record(DEMO_ROOT / name) for name in source_names},
            **{
                f"tools/dynamic/fixtures/skill_sandbox_samples/{fixture}/{relative}":
                    _file_record(FIXTURE_ROOT / fixture / relative)
                for fixture, files in FIXTURES.items()
                for relative in files
            },
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
                f"openclaw={EXPECTED_OPENCLAW_VERSION} ({EXPECTED_OPENCLAW_COMMIT})",
                *(f"case={case['slug']} exit={case['exit_code']} destination={case['destination_exists']} passed={case['passed']} duration_ms={case['duration_ms']}" for case in cases),
                f"audit_chain_valid={metrics['audit_chain_valid']}",
                f"audit_gates={metrics['audit_gates_passed']}/{metrics['audit_gates_total']}",
                f"blocked_install_residuals={metrics['blocked_install_residuals']}",
                f"default_workspace_test_residuals={metrics['default_workspace_test_residuals']}",
                f"docker_container_residuals={metrics['docker_container_residuals']}",
            ]
        ),
    )
    return {"status": results["status"], "metrics": metrics, "output": str(output)}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"OpenClaw dynamic E2E failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "accepted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
