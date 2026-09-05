from __future__ import annotations

import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .docker_backend import (
    DockerBackendError,
    DockerCommandResult,
    _cleanup_container,
    _docker_prefix,
    _parse_json_object,
    _require_success,
    discover_docker_cli,
    inspect_image_identity,
    probe_docker_engine,
    run_docker_cli,
    sha256_file,
)
from .skill_sandbox import (
    DynamicEvaluation,
    EntrypointPlan,
    discover_python_entrypoints,
    evaluate_dynamic_result,
    serialize_dynamic_evaluation,
)


DEMO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_SCHEMA_VERSION = "1.0"
BACKEND_ID = "aegis-python-skill-sandbox-v1"
DOCKER_CONTEXT = "desktop-linux"
IMAGE_REFERENCE = (
    "public.ecr.aws/docker/library/python@"
    "sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65"
)
IMAGE_ID = "sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65"
TOOL_RELATIVE_ROOT = "tools/dynamic/docker/skill_sandbox"
TOOL_CONTAINER_ROOT = "/aegis_tool"
EXPECTED_TOOL_HASHES = {
    "runner.py": "cf3a1aaf1ec4963440b88229b59516c9ebd6f6ec1aae2ee3b127d6732c9117bd",
    "sitecustomize.py": "70f6e29cf83feaaf78595697b4cf98585db23da17e32400dac0f606b0fa90d32",
}
EXPECTED_SECURITY: dict[str, Any] = {
    "network_mode": "none",
    "read_only_rootfs": True,
    "user": "65532:65532",
    "cap_drop": ["ALL"],
    "no_new_privileges": True,
    "privileged": False,
    "pid_mode": "",
    "ipc_mode": "none",
    "pids_limit": 64,
    "memory_bytes": 268435456,
    "nano_cpus": 500000000,
    "init": True,
    "log_driver": "none",
    "tmpfs": {
        "/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777",
        "/workspace": "rw,noexec,nosuid,nodev,size=67108864,mode=1777",
    },
}
CONTAINER_NAME = re.compile(r"^aegis-skill-[0-9a-f]{16}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class SkillSandboxConfig:
    config_path: Path
    config_sha256: str
    tool_root: Path
    tool_hashes: dict[str, str]
    timeout_seconds: float
    max_entrypoints: int
    security: dict[str, Any]


@dataclass(frozen=True)
class _ImageConfig:
    image_reference: str = IMAGE_REFERENCE
    image_id: str = IMAGE_ID


def _mapping(value: Any, operation: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DockerBackendError("CONFIG_TYPE_INVALID", operation)
    return value


def load_skill_sandbox_config(path: Path) -> SkillSandboxConfig:
    try:
        resolved = path.resolve(strict=True)
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DockerBackendError("CONFIG_READ_FAILED", "skill_sandbox_config") from exc
    if not isinstance(payload, dict):
        raise DockerBackendError("CONFIG_TYPE_INVALID", "skill_sandbox_config")
    expected_top = {
        "schema_version", "backend_id", "docker_context", "pull_policy",
        "image", "tool", "execution", "security",
    }
    if set(payload) != expected_top:
        raise DockerBackendError("CONFIG_FIELDS_DENIED", "skill_sandbox_config")
    if payload.get("schema_version") != CONFIG_SCHEMA_VERSION or payload.get("backend_id") != BACKEND_ID:
        raise DockerBackendError("CONFIG_IDENTITY_DENIED", "skill_sandbox_config")
    if payload.get("docker_context") != DOCKER_CONTEXT or payload.get("pull_policy") != "never":
        raise DockerBackendError("CONFIG_DOCKER_POLICY_DENIED", "skill_sandbox_config")
    if _mapping(payload.get("image"), "image") != {
        "reference": IMAGE_REFERENCE,
        "id": IMAGE_ID,
        "os": "linux",
        "architecture": "amd64",
    }:
        raise DockerBackendError("CONFIG_IMAGE_IDENTITY_DENIED", "skill_sandbox_config")
    tool = _mapping(payload.get("tool"), "tool")
    if tool != {
        "root": TOOL_RELATIVE_ROOT,
        "container_root": TOOL_CONTAINER_ROOT,
        "files": EXPECTED_TOOL_HASHES,
    }:
        raise DockerBackendError("CONFIG_TOOL_IDENTITY_DENIED", "skill_sandbox_config")
    tool_root = (DEMO_ROOT / TOOL_RELATIVE_ROOT).resolve(strict=True)
    for relative, expected_hash in EXPECTED_TOOL_HASHES.items():
        candidate = (tool_root / relative).resolve(strict=True)
        try:
            candidate.relative_to(tool_root)
        except ValueError as exc:
            raise DockerBackendError("CONFIG_TOOL_PATH_DENIED", "skill_sandbox_config") from exc
        if candidate.is_symlink() or sha256_file(candidate) != expected_hash:
            raise DockerBackendError("CONFIG_TOOL_HASH_MISMATCH", relative)
    execution = _mapping(payload.get("execution"), "execution")
    if set(execution) != {"total_timeout_seconds", "max_entrypoints"}:
        raise DockerBackendError("CONFIG_EXECUTION_FIELDS_DENIED", "skill_sandbox_config")
    timeout = execution.get("total_timeout_seconds")
    entrypoints = execution.get("max_entrypoints")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 60 <= timeout <= 120:
        raise DockerBackendError("CONFIG_TIMEOUT_DENIED", "skill_sandbox_config")
    if entrypoints != 3:
        raise DockerBackendError("CONFIG_ENTRYPOINT_LIMIT_DENIED", "skill_sandbox_config")
    security = _mapping(payload.get("security"), "security")
    if security != EXPECTED_SECURITY:
        raise DockerBackendError("CONFIG_SECURITY_RELAXATION_DENIED", "skill_sandbox_config")
    return SkillSandboxConfig(
        config_path=resolved,
        config_sha256=sha256_file(resolved),
        tool_root=tool_root,
        tool_hashes=dict(EXPECTED_TOOL_HASHES),
        timeout_seconds=float(timeout),
        max_entrypoints=int(entrypoints),
        security=security,
    )


def _safe_mount_source(path: Path, operation: str) -> str:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DockerBackendError("MOUNT_SOURCE_INVALID", operation) from exc
    text = str(resolved)
    if any(character in text for character in [",", "\r", "\n"]):
        raise DockerBackendError("MOUNT_SOURCE_DENIED", operation)
    return text


def build_skill_container_command(
    docker_cli: Path,
    config: SkillSandboxConfig,
    *,
    skill_root: Path,
    entrypoint: str,
    container_name: str,
    timeout_seconds: float,
) -> list[str]:
    if not CONTAINER_NAME.fullmatch(container_name):
        raise DockerBackendError("CONTAINER_NAME_DENIED", "skill_command_plan")
    if entrypoint.startswith("/") or "\\" in entrypoint or ".." in entrypoint.split("/"):
        raise DockerBackendError("ENTRYPOINT_PATH_DENIED", "skill_command_plan")
    if not entrypoint.lower().endswith(".py"):
        raise DockerBackendError("ENTRYPOINT_TYPE_DENIED", "skill_command_plan")
    if not 1 <= timeout_seconds <= config.timeout_seconds:
        raise DockerBackendError("ENTRYPOINT_TIMEOUT_DENIED", "skill_command_plan")
    skill_source = _safe_mount_source(skill_root, "skill_mount")
    tool_source = _safe_mount_source(config.tool_root, "tool_mount")
    security = config.security
    command = [
        str(docker_cli), "--context", DOCKER_CONTEXT, "create",
        "--name", container_name,
        "--label", f"aegis.dynamic.backend={BACKEND_ID}",
        "--label", f"aegis.dynamic.run={container_name}",
        "--pull", "never",
        "--network", "none",
        "--read-only",
        "--user", security["user"],
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true",
        "--pids-limit", str(security["pids_limit"]),
        "--memory", str(security["memory_bytes"]),
        "--cpus", "0.5",
        "--init",
        "--ipc", "none",
        "--log-driver", "none",
        "--stop-timeout", "1",
        "--hostname", "aegis-skill-sandbox",
        "--workdir", "/workspace",
    ]
    for destination, options in sorted(security["tmpfs"].items()):
        command.extend(["--tmpfs", f"{destination}:{options}"])
    command.extend(
        [
            "--mount", f"type=bind,source={skill_source},target=/skill,readonly",
            "--mount", f"type=bind,source={tool_source},target={TOOL_CONTAINER_ROOT},readonly",
            "--entrypoint", "/usr/local/bin/python",
            IMAGE_REFERENCE,
            "-B", "/aegis_tool/runner.py",
            "--skill-root", "/skill",
            "--entry", entrypoint,
            "--timeout-seconds", f"{timeout_seconds:g}",
        ]
    )
    return command


def validate_skill_container_inspect(
    payload: dict[str, Any],
    config: SkillSandboxConfig,
    *,
    skill_root: Path,
    entrypoint: str,
    container_name: str,
    timeout_seconds: float,
) -> dict[str, bool]:
    container_config = _mapping(payload.get("Config"), "inspect.Config")
    host = _mapping(payload.get("HostConfig"), "inspect.HostConfig")
    labels = container_config.get("Labels") or {}
    mounts = payload.get("Mounts") if isinstance(payload.get("Mounts"), list) else []
    bind_mounts = [item for item in mounts if isinstance(item, dict) and item.get("Type") == "bind"]
    expected_sources = {
        "/skill": os.path.normcase(str(skill_root.resolve(strict=True))),
        TOOL_CONTAINER_ROOT: os.path.normcase(str(config.tool_root.resolve(strict=True))),
    }
    mount_gates: list[bool] = []
    for destination, expected_source in expected_sources.items():
        matches = [item for item in bind_mounts if item.get("Destination") == destination]
        mount_gates.append(
            len(matches) == 1
            and matches[0].get("RW") is False
            and os.path.normcase(str(Path(str(matches[0].get("Source") or "")).resolve(strict=False))) == expected_source
        )
    cap_drop = {str(item).upper() for item in host.get("CapDrop") or []}
    security_opt = {str(item).lower() for item in host.get("SecurityOpt") or []}
    expected_cmd = [
        "-B", "/aegis_tool/runner.py", "--skill-root", "/skill",
        "--entry", entrypoint, "--timeout-seconds", f"{timeout_seconds:g}",
    ]
    mount_text = json.dumps(mounts, ensure_ascii=False).casefold()
    return {
        "backend_label_exact": labels.get("aegis.dynamic.backend") == BACKEND_ID,
        "run_label_exact": labels.get("aegis.dynamic.run") == container_name,
        "image_reference_immutable": container_config.get("Image") == IMAGE_REFERENCE,
        "entrypoint_fixed": container_config.get("Entrypoint") == ["/usr/local/bin/python"],
        "command_exact": container_config.get("Cmd") == expected_cmd,
        "workdir_fixed": container_config.get("WorkingDir") == "/workspace",
        "non_root_user": container_config.get("User") == EXPECTED_SECURITY["user"],
        "network_none": host.get("NetworkMode") == "none",
        "read_only_rootfs": host.get("ReadonlyRootfs") is True,
        "privileged_false": host.get("Privileged") is False,
        "private_pid_namespace": str(host.get("PidMode") or "") == "",
        "ipc_none": host.get("IpcMode") == "none",
        "cap_drop_all": "ALL" in cap_drop and not host.get("CapAdd"),
        "no_new_privileges": "no-new-privileges=true" in security_opt,
        "pids_limited": host.get("PidsLimit") == EXPECTED_SECURITY["pids_limit"],
        "memory_limited": host.get("Memory") == EXPECTED_SECURITY["memory_bytes"],
        "cpu_limited": host.get("NanoCpus") == EXPECTED_SECURITY["nano_cpus"],
        "init_enabled": host.get("Init") is True,
        "log_driver_none": (host.get("LogConfig") or {}).get("Type") == "none",
        "tmpfs_exact": host.get("Tmpfs") == EXPECTED_SECURITY["tmpfs"],
        "two_read_only_binds_exact": len(bind_mounts) == 2 and all(mount_gates),
        "no_docker_socket_or_host_root_mount": "docker.sock" not in mount_text and '"destination": "/"' not in mount_text,
        "restart_disabled": (host.get("RestartPolicy") or {}).get("Name") == "no",
    }


def _parse_runner_payload(stdout: str, entrypoint: str) -> dict[str, Any]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise DockerBackendError("SKILL_RUNNER_OUTPUT_INVALID", "container_start") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        raise DockerBackendError("SKILL_RUNNER_SCHEMA_INVALID", "container_start")
    if payload.get("collector") != "aegis-python-skill-runner-v1":
        raise DockerBackendError("SKILL_RUNNER_IDENTITY_INVALID", "container_start")
    if payload.get("entrypoint") not in {None, entrypoint}:
        raise DockerBackendError("SKILL_RUNNER_ENTRYPOINT_MISMATCH", "container_start")
    events = payload.get("events")
    if not isinstance(events, list) or len(events) > 5_000 or not all(isinstance(item, dict) for item in events):
        raise DockerBackendError("SKILL_RUNNER_EVENTS_INVALID", "container_start")
    if payload.get("internet_used") is not False:
        raise DockerBackendError("SKILL_RUNNER_NETWORK_CONTRACT_FAILED", "container_start")
    return payload


def run_python_skill_entrypoint(
    config: SkillSandboxConfig,
    skill_root: Path,
    entrypoint: str,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    started = time.perf_counter()
    docker_cli = discover_docker_cli()
    container_name = f"aegis-skill-{secrets.token_hex(8)}"
    container_id = ""
    error: dict[str, str] | None = None
    engine: dict[str, Any] = {}
    image: dict[str, Any] = {}
    image_gates: dict[str, bool] = {}
    inspect_gates: dict[str, bool] = {}
    runner_payload: dict[str, Any] = {}
    cleanup: dict[str, Any] = {"attempted": False, "removed": False, "residual": False}
    command = build_skill_container_command(
        docker_cli, config, skill_root=skill_root, entrypoint=entrypoint,
        container_name=container_name, timeout_seconds=timeout_seconds,
    )
    evaluation: DynamicEvaluation | None = None
    try:
        engine = probe_docker_engine(docker_cli)
        image, image_gates = inspect_image_identity(docker_cli, _ImageConfig())
        if not all(image_gates.values()):
            raise DockerBackendError("DOCKER_IMAGE_GATE_FAILED", "image_inspect")
        created = run_docker_cli(command, timeout_seconds=20)
        container_id = _require_success(created, "container_create")
        if not CONTAINER_ID.fullmatch(container_id):
            raise DockerBackendError("CONTAINER_ID_INVALID", "container_create")
        inspected = run_docker_cli(
            [*_docker_prefix(docker_cli), "container", "inspect", container_id, "--format", "{{json .}}"],
            timeout_seconds=15,
        )
        inspect_payload = _parse_json_object(
            _require_success(inspected, "container_inspect"),
            "CONTAINER_INSPECT_PARSE_FAILED", "container_inspect",
        )
        inspect_gates = validate_skill_container_inspect(
            inspect_payload, config, skill_root=skill_root, entrypoint=entrypoint,
            container_name=container_name, timeout_seconds=timeout_seconds,
        )
        if not all(inspect_gates.values()):
            raise DockerBackendError("CONTAINER_INSPECT_GATE_FAILED", "container_inspect")
        result = run_docker_cli(
            [*_docker_prefix(docker_cli), "container", "start", "--attach", container_id],
            timeout_seconds=timeout_seconds + 15,
        )
        if result.return_code not in {0, 1}:
            raise DockerBackendError("SKILL_RUNNER_FAILED", "container_start")
        runner_payload = _parse_runner_payload(result.stdout, entrypoint)
        evaluation = evaluate_dynamic_result(
            runner_payload["events"],
            execution_status=str(runner_payload.get("execution_status") or "failed"),
            telemetry_complete=runner_payload.get("telemetry_complete") is True,
        )
    except DockerBackendError as exc:
        error = {"code": exc.code, "operation": exc.operation}
        evaluation = evaluate_dynamic_result(
            [], execution_status="infrastructure_failed", telemetry_complete=False
        )
    finally:
        if container_id:
            try:
                cleanup = _cleanup_container(docker_cli, container_id)
            except DockerBackendError as exc:
                cleanup = {"attempted": True, "removed": False, "residual": True, "error_code": exc.code}
    if cleanup.get("residual") is True and evaluation is not None:
        evaluation = evaluate_dynamic_result(
            [*runner_payload.get("events", []), {"type": "telemetry.tamper", "reason": "container_residual"}],
            execution_status="cleanup_failed",
            telemetry_complete=False,
        )
    return {
        "success": error is None and cleanup.get("removed") is True and cleanup.get("residual") is False,
        "error": error,
        "engine": engine,
        "image": image,
        "image_gates": image_gates,
        "inspect_gates": inspect_gates,
        "entrypoint": entrypoint,
        "runner": runner_payload,
        "evaluation": serialize_dynamic_evaluation(evaluation),
        "cleanup": cleanup,
        "duration_ms": round((time.perf_counter() - started) * 1000),
    }


def run_python_skill_sandbox(config_path: Path, skill_root: Path) -> dict[str, Any]:
    started = time.perf_counter()
    config = load_skill_sandbox_config(config_path)
    plan: EntrypointPlan = discover_python_entrypoints(
        skill_root, max_entrypoints=config.max_entrypoints
    )
    per_entry_timeout = max(1.0, config.timeout_seconds / len(plan.entrypoints))
    runs = [
        run_python_skill_entrypoint(
            config, skill_root, entrypoint, timeout_seconds=per_entry_timeout
        )
        for entrypoint in plan.entrypoints
    ]
    decisions = [str((run.get("evaluation") or {}).get("decision") or "BLOCK") for run in runs]
    final = "BLOCK" if "BLOCK" in decisions else ("REVIEW" if "REVIEW" in decisions else "ALLOW")
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str]] = set()
    for run in runs:
        for finding in (run.get("evaluation") or {}).get("findings") or []:
            if not isinstance(finding, dict):
                continue
            identity = (str(finding.get("rule_id") or ""), str(finding.get("evidence") or ""))
            if identity in seen_findings:
                continue
            seen_findings.add(identity)
            findings.append(finding)
    status = "malicious" if final == "BLOCK" else ("suspicious" if final == "REVIEW" else "clean")
    return {
        "schema_version": "1.0",
        "backend_id": BACKEND_ID,
        "config_sha256": config.config_sha256,
        "entrypoint_plan": {
            "entrypoints": list(plan.entrypoints),
            "discovery": plan.discovery,
            "files_seen": plan.files_seen,
            "total_bytes": plan.total_bytes,
        },
        "runs": runs,
        "decision": final,
        "status": status,
        "findings": findings,
        "reason": (
            "隔离试运行观察到高危行为，已升级为阻断。"
            if final == "BLOCK"
            else "隔离试运行需要人工复核。"
            if final == "REVIEW"
            else "隔离试运行完成，未观察到影响准入的动态风险。"
        ),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "claim_boundary": "Python 审计钩子是可解释行为证据，不是不可绕过的内核安全边界。",
    }
