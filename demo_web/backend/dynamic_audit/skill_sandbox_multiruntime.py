from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..analyzers.skill_semantic import analyze_skill_semantics
from ..models import Decision
from ..semantic_model import configured_semantic_provider
from .docker_backend import (
    DockerBackendError,
    _cleanup_container,
    _docker_prefix,
    _parse_json_object,
    _require_success,
    discover_docker_cli,
    probe_docker_engine,
    run_docker_cli,
    sha256_file,
)
from .skill_sandbox import (
    EntrypointPlan,
    classify_dynamic_events,
    discover_skill_entrypoints,
    evaluate_dynamic_result,
    serialize_dynamic_evaluation,
)


BACKEND_ID = "aegis-multiruntime-skill-sandbox-v2"
DOCKER_CONTEXT = "desktop-linux"
DEMO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = DEMO_ROOT / "config" / "skill_dynamic_sandbox_v2.json"
CONTAINER_NAME = re.compile(r"^aegis-skill-v2-[0-9a-f]{16}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
MAX_ENTRYPOINT_ARGV = 16
MAX_ENTRYPOINT_ARG_LENGTH = 512
MAX_ENTRYPOINT_ARGV_BYTES = 4096


@dataclass(frozen=True)
class RuntimeImage:
    reference: str
    image_id: str


@dataclass(frozen=True)
class MultiRuntimeConfig:
    path: Path
    sha256: str
    tool_root: Path
    images: dict[str, RuntimeImage]
    security: dict[str, Any]
    timeout_seconds: float
    max_entrypoints: int


def load_multiruntime_config(path: Path = CONFIG_PATH) -> MultiRuntimeConfig:
    resolved = path.resolve(strict=True)
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "2.0" or payload.get("backend_id") != BACKEND_ID:
        raise DockerBackendError("MULTIRUNTIME_CONFIG_IDENTITY_DENIED", "config")
    if payload.get("docker_context") != DOCKER_CONTEXT or payload.get("pull_policy") != "never":
        raise DockerBackendError("MULTIRUNTIME_DOCKER_POLICY_DENIED", "config")
    images = payload.get("images")
    if not isinstance(images, dict) or set(images) != {"python", "node", "shell"}:
        raise DockerBackendError("MULTIRUNTIME_IMAGES_INVALID", "config")
    parsed_images: dict[str, RuntimeImage] = {}
    for runtime, item in images.items():
        if not isinstance(item, dict) or set(item) != {"reference", "id"}:
            raise DockerBackendError("MULTIRUNTIME_IMAGE_INVALID", runtime)
        reference, image_id = str(item["reference"]), str(item["id"])
        if "@sha256:" not in reference or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise DockerBackendError("MULTIRUNTIME_IMAGE_NOT_IMMUTABLE", runtime)
        parsed_images[runtime] = RuntimeImage(reference, image_id)
    tool = payload.get("tool")
    if not isinstance(tool, dict) or tool.get("root") != "tools/dynamic/docker/skill_sandbox" or tool.get("container_root") != "/aegis_tool":
        raise DockerBackendError("MULTIRUNTIME_TOOL_INVALID", "config")
    tool_root = (DEMO_ROOT / str(tool["root"])).resolve(strict=True)
    hashes = tool.get("files")
    if not isinstance(hashes, dict) or not hashes:
        raise DockerBackendError("MULTIRUNTIME_TOOL_HASHES_INVALID", "config")
    for relative, expected in hashes.items():
        candidate = (tool_root / str(relative)).resolve(strict=True)
        candidate.relative_to(tool_root)
        if candidate.is_symlink() or sha256_file(candidate) != expected:
            raise DockerBackendError("MULTIRUNTIME_TOOL_HASH_MISMATCH", str(relative))
    execution = payload.get("execution")
    if not isinstance(execution, dict) or execution.get("rounds") != ["typical", "edge", "adversarial"]:
        raise DockerBackendError("MULTIRUNTIME_ROUNDS_INVALID", "config")
    timeout = execution.get("total_timeout_seconds")
    maximum = execution.get("max_entrypoints")
    if not isinstance(timeout, (int, float)) or not 60 <= timeout <= 120 or maximum != 3:
        raise DockerBackendError("MULTIRUNTIME_LIMITS_INVALID", "config")
    security = payload.get("security")
    required = {
        "network_mode": "none", "read_only_rootfs": True, "user": "65532:65532",
        "cap_drop": ["ALL"], "no_new_privileges": True, "privileged": False,
        "pid_mode": "", "ipc_mode": "none", "pids_limit": 64,
        "memory_bytes": 268435456, "nano_cpus": 500000000,
        "init": True, "log_driver": "none",
        "tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777", "/workspace": "rw,noexec,nosuid,nodev,size=67108864,mode=1777"},
    }
    if security != required:
        raise DockerBackendError("MULTIRUNTIME_SECURITY_RELAXATION_DENIED", "config")
    return MultiRuntimeConfig(resolved, sha256_file(resolved), tool_root, parsed_images, security, float(timeout), int(maximum))


def _runner(runtime: str) -> tuple[str, str, list[str]]:
    if runtime == "node":
        return "/usr/local/bin/node", "/aegis_tool/runner_node.cjs", []
    if runtime == "shell":
        return "/usr/local/bin/python", "/aegis_tool/runner_shell.py", ["-B"]
    if runtime == "python":
        return "/usr/local/bin/python", "/aegis_tool/runner_python_rounds.py", ["-B"]
    raise DockerBackendError("RUNTIME_DENIED", "command_plan")


def _safe_mount_source(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    text = str(resolved)
    if any(character in text for character in (",", "\r", "\n", "\x00")):
        raise DockerBackendError("MOUNT_SOURCE_DENIED", "command_plan")
    return resolved


def _canonical_mount_source(value: object) -> str:
    text = str(value or "").replace("\\", "/").rstrip("/").casefold()
    match = re.match(r"^/(?:run/desktop/mnt/host|host_mnt)/([a-z])(?:/(.*))?$", text)
    if match:
        suffix = f"/{match.group(2)}" if match.group(2) else ""
        return f"{match.group(1)}:{suffix}"
    return text


def _normalize_entrypoint_argv(argv: tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    values = tuple(argv or ())
    if len(values) > MAX_ENTRYPOINT_ARGV:
        raise DockerBackendError("ENTRYPOINT_ARGV_LIMIT_EXCEEDED", "command_plan")
    if any(
        not isinstance(value, str)
        or len(value) > MAX_ENTRYPOINT_ARG_LENGTH
        or any(character in value for character in ("\x00", "\r", "\n"))
        for value in values
    ):
        raise DockerBackendError("ENTRYPOINT_ARGV_DENIED", "command_plan")
    encoded = json.dumps(list(values), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_ENTRYPOINT_ARGV_BYTES:
        raise DockerBackendError("ENTRYPOINT_ARGV_LIMIT_EXCEEDED", "command_plan")
    return values


def _argv_json(argv: tuple[str, ...]) -> str:
    return json.dumps(list(argv), ensure_ascii=False, separators=(",", ":"))


def _argv_sha256(argv: tuple[str, ...]) -> str:
    return hashlib.sha256(_argv_json(argv).encode("utf-8")).hexdigest()


def build_multiruntime_command(
    docker_cli: Path,
    config: MultiRuntimeConfig,
    skill_root: Path,
    entrypoint: str,
    runtime: str,
    container_name: str,
    timeout_seconds: float,
    argv: tuple[str, ...] | list[str] | None = None,
) -> list[str]:
    if not CONTAINER_NAME.fullmatch(container_name) or runtime not in config.images:
        raise DockerBackendError("MULTIRUNTIME_COMMAND_DENIED", "command_plan")
    if entrypoint.startswith("/") or "\\" in entrypoint or ".." in entrypoint.split("/"):
        raise DockerBackendError("ENTRYPOINT_PATH_DENIED", "command_plan")
    normalized_argv = _normalize_entrypoint_argv(argv)
    executable, runner, prefix = _runner(runtime)
    skill_mount = _safe_mount_source(skill_root)
    tool_mount = _safe_mount_source(config.tool_root)
    image = config.images[runtime]
    security = config.security
    command = [
        str(docker_cli), "--context", DOCKER_CONTEXT, "create", "--name", container_name,
        "--label", f"aegis.dynamic.backend={BACKEND_ID}", "--label", f"aegis.dynamic.run={container_name}",
        "--label", f"aegis.dynamic.runtime={runtime}", "--pull", "never", "--network", "none",
        "--read-only", "--user", security["user"], "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true", "--pids-limit", "64", "--memory", "268435456",
        "--cpus", "0.5", "--init", "--ipc", "none", "--log-driver", "none", "--stop-timeout", "1",
        "--hostname", "aegis-skill-sandbox", "--workdir", "/workspace",
    ]
    for destination, options in sorted(security["tmpfs"].items()):
        command.extend(["--tmpfs", f"{destination}:{options}"])
    command.extend([
        "--mount", f"type=bind,source={skill_mount},target=/skill,readonly",
        "--mount", f"type=bind,source={tool_mount},target=/aegis_tool,readonly",
        "--entrypoint", executable, image.reference, *prefix, runner,
        "--skill-root", "/skill", "--entry", entrypoint, "--timeout-seconds", f"{timeout_seconds:g}",
    ])
    if normalized_argv:
        command.extend(["--argv-json", _argv_json(normalized_argv)])
    return command


def _inspect_gates(
    payload: dict[str, Any],
    config: MultiRuntimeConfig,
    runtime: str,
    name: str,
    skill_root: Path,
    entrypoint: str,
    timeout_seconds: float,
    argv: tuple[str, ...] | list[str] | None = None,
) -> dict[str, bool]:
    host = payload.get("HostConfig") if isinstance(payload.get("HostConfig"), dict) else {}
    container = payload.get("Config") if isinstance(payload.get("Config"), dict) else {}
    labels = container.get("Labels") or {}
    mounts = payload.get("Mounts") if isinstance(payload.get("Mounts"), list) else []
    mount_text = json.dumps(mounts, ensure_ascii=False).casefold()
    executable, runner, prefix = _runner(runtime)
    expected_cmd = [*prefix, runner, "--skill-root", "/skill", "--entry", entrypoint, "--timeout-seconds", f"{timeout_seconds:g}"]
    normalized_argv = _normalize_entrypoint_argv(argv)
    if normalized_argv:
        expected_cmd.extend(["--argv-json", _argv_json(normalized_argv)])
    bind_mounts = {str(item.get("Destination") or ""): item for item in mounts if isinstance(item, dict) and item.get("Type") == "bind"}
    skill_mount = bind_mounts.get("/skill") or {}
    tool_mount = bind_mounts.get("/aegis_tool") or {}
    return {
        "backend_label": labels.get("aegis.dynamic.backend") == BACKEND_ID,
        "run_label": labels.get("aegis.dynamic.run") == name,
        "runtime_label": labels.get("aegis.dynamic.runtime") == runtime,
        "image_immutable": container.get("Image") == config.images[runtime].reference,
        "network_none": host.get("NetworkMode") == "none",
        "read_only": host.get("ReadonlyRootfs") is True,
        "non_root": container.get("User") == "65532:65532",
        "not_privileged": host.get("Privileged") is False,
        "private_pid": str(host.get("PidMode") or "") == "",
        "ipc_none": host.get("IpcMode") == "none",
        "cap_drop_all": "ALL" in {str(item).upper() for item in host.get("CapDrop") or []} and not host.get("CapAdd"),
        "no_new_privileges": "no-new-privileges=true" in {str(item).lower() for item in host.get("SecurityOpt") or []},
        "pids_limited": host.get("PidsLimit") == 64,
        "memory_limited": host.get("Memory") == 268435456,
        "cpu_limited": host.get("NanoCpus") == 500000000,
        "tmpfs_exact": host.get("Tmpfs") == config.security["tmpfs"],
        "mounts_exact": len(mounts) == 2 and len(bind_mounts) == 2,
        "skill_mount_exact": skill_mount.get("RW") is False and _canonical_mount_source(skill_mount.get("Source")) == _canonical_mount_source(skill_root.resolve(strict=True)),
        "tool_mount_exact": tool_mount.get("RW") is False and _canonical_mount_source(tool_mount.get("Source")) == _canonical_mount_source(config.tool_root.resolve(strict=True)),
        "entrypoint_exact": container.get("Entrypoint") == [executable],
        "command_exact": container.get("Cmd") == expected_cmd,
        "workdir_exact": container.get("WorkingDir") == "/workspace",
        "init_enabled": host.get("Init") is True,
        "log_driver_none": (host.get("LogConfig") or {}).get("Type") == "none",
        "no_host_control_mount": "docker.sock" not in mount_text and '"destination": "/"' not in mount_text,
        "restart_disabled": (host.get("RestartPolicy") or {}).get("Name") == "no",
    }


def _image_gates(docker_cli: Path, image: RuntimeImage) -> tuple[dict[str, Any], dict[str, bool]]:
    result = run_docker_cli([*_docker_prefix(docker_cli), "image", "inspect", image.reference, "--format", "{{json .}}"], timeout_seconds=15)
    payload = _parse_json_object(_require_success(result, "image_inspect"), "IMAGE_PARSE_FAILED", "image_inspect")
    repo_digests = payload.get("RepoDigests") if isinstance(payload.get("RepoDigests"), list) else []
    expected_digest = image.reference.rsplit("@", 1)[-1]
    gates = {
        "id_exact": payload.get("Id") == image.image_id,
        "reference_present": any(str(item).endswith(f"@{expected_digest}") for item in repo_digests),
        "linux": payload.get("Os") == "linux",
        "amd64": payload.get("Architecture") == "amd64",
    }
    return {"id": payload.get("Id"), "repo_digests": repo_digests, "os": payload.get("Os"), "architecture": payload.get("Architecture")}, gates


def _parse_runner(
    stdout: str,
    entrypoint: str,
    runtime: str,
    argv: tuple[str, ...] | list[str] | None = None,
) -> dict[str, Any]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise DockerBackendError("MULTIRUNTIME_OUTPUT_INVALID", "container_start") from exc
    expected = {"python": "aegis-python-skill-runner-v2", "node": "aegis-node-skill-runner-v1", "shell": "aegis-shell-skill-runner-v1"}[runtime]
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0" or payload.get("collector") != expected:
        raise DockerBackendError("MULTIRUNTIME_RUNNER_IDENTITY_INVALID", "container_start")
    if payload.get("entrypoint") != entrypoint or payload.get("internet_used") is not False:
        raise DockerBackendError("MULTIRUNTIME_RUNNER_CONTRACT_FAILED", "container_start")
    normalized_argv = _normalize_entrypoint_argv(argv)
    if payload.get("argv_count") != len(normalized_argv) or payload.get("argv_sha256") != _argv_sha256(normalized_argv):
        raise DockerBackendError("MULTIRUNTIME_ARGV_ATTESTATION_INVALID", "container_start")
    rounds = payload.get("rounds")
    if not isinstance(rounds, list) or [item.get("id") for item in rounds if isinstance(item, dict)] != ["typical", "edge", "adversarial"]:
        raise DockerBackendError("MULTIRUNTIME_ROUND_ATTESTATION_INVALID", "container_start")
    events = payload.get("events")
    if not isinstance(events, list) or len(events) > 5000 or not all(isinstance(item, dict) for item in events):
        raise DockerBackendError("MULTIRUNTIME_EVENTS_INVALID", "container_start")
    return payload


def run_multiruntime_entrypoint(
    config: MultiRuntimeConfig,
    skill_root: Path,
    entrypoint: str,
    runtime: str,
    timeout_seconds: float,
    argv: tuple[str, ...] | list[str] | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    docker_cli = discover_docker_cli()
    name = f"aegis-skill-v2-{secrets.token_hex(8)}"
    container_id = ""
    runner_payload: dict[str, Any] = {}
    cleanup: dict[str, Any] = {"attempted": False, "removed": False, "residual": False}
    error: dict[str, str] | None = None
    image_payload: dict[str, Any] = {}
    image_gates: dict[str, bool] = {}
    inspect_gates: dict[str, bool] = {}
    try:
        probe_docker_engine(docker_cli)
        image_payload, image_gates = _image_gates(docker_cli, config.images[runtime])
        if not all(image_gates.values()):
            raise DockerBackendError("MULTIRUNTIME_IMAGE_GATE_FAILED", "image_inspect")
        normalized_argv = _normalize_entrypoint_argv(argv)
        command = build_multiruntime_command(docker_cli, config, skill_root, entrypoint, runtime, name, timeout_seconds, normalized_argv)
        container_id = _require_success(run_docker_cli(command, timeout_seconds=20), "container_create")
        if not CONTAINER_ID.fullmatch(container_id):
            raise DockerBackendError("CONTAINER_ID_INVALID", "container_create")
        inspected = run_docker_cli([*_docker_prefix(docker_cli), "container", "inspect", container_id, "--format", "{{json .}}"], timeout_seconds=15)
        payload = _parse_json_object(_require_success(inspected, "container_inspect"), "CONTAINER_INSPECT_PARSE_FAILED", "container_inspect")
        inspect_gates = _inspect_gates(payload, config, runtime, name, skill_root, entrypoint, timeout_seconds, normalized_argv)
        if not all(inspect_gates.values()):
            raise DockerBackendError("MULTIRUNTIME_INSPECT_GATE_FAILED", "container_inspect")
        result = run_docker_cli([*_docker_prefix(docker_cli), "container", "start", "--attach", container_id], timeout_seconds=timeout_seconds + 20)
        if result.return_code not in {0, 1}:
            raise DockerBackendError("MULTIRUNTIME_RUNNER_FAILED", "container_start")
        runner_payload = _parse_runner(result.stdout, entrypoint, runtime, normalized_argv)
        evaluation = evaluate_dynamic_result(runner_payload["events"], execution_status=str(runner_payload.get("execution_status") or "failed"), telemetry_complete=runner_payload.get("telemetry_complete") is True)
    except DockerBackendError as exc:
        error = {"code": exc.code, "operation": exc.operation}
        evaluation = evaluate_dynamic_result([], execution_status="infrastructure_failed", telemetry_complete=False)
    finally:
        if container_id:
            try:
                cleanup = _cleanup_container(docker_cli, container_id)
            except DockerBackendError as exc:
                cleanup = {"attempted": True, "removed": False, "residual": True, "error_code": exc.code}
    return {
        "success": error is None and cleanup.get("removed") is True and cleanup.get("residual") is False,
        "error": error, "runtime": runtime, "entrypoint": entrypoint,
        "argv_attestation": {
            "count": len(_normalize_entrypoint_argv(argv)),
            "sha256": _argv_sha256(_normalize_entrypoint_argv(argv)),
            "raw_values_retained": False,
        },
        "image": image_payload, "image_gates": image_gates, "inspect_gates": inspect_gates,
        "runner": runner_payload, "evaluation": serialize_dynamic_evaluation(evaluation), "cleanup": cleanup,
        "duration_ms": round((time.perf_counter() - started) * 1000),
    }


_DEFAULT_SEMANTIC_PROVIDER = object()


def _instruction_audit(
    skill_root: Path,
    plan: EntrypointPlan,
    semantic_provider: Any = _DEFAULT_SEMANTIC_PROVIDER,
) -> dict[str, Any]:
    provider = semantic_provider
    if semantic_provider is _DEFAULT_SEMANTIC_PROVIDER:
        provider = None
        try:
            provider = configured_semantic_provider()
        except Exception:
            provider = None
    findings, _ = analyze_skill_semantics(skill_root, provider=provider)
    severities = {str(item.get("severity") or "UNKNOWN").upper() for item in findings}
    decision = "BLOCK" if severities & {"HIGH", "CRITICAL", "UNKNOWN"} else ("REVIEW" if "MEDIUM" in severities else "ALLOW")
    return {
        "schema_version": "2.0", "backend_id": BACKEND_ID, "execution_kind": "pure_instruction",
        "entrypoint_plan": {"entrypoints": [], "runtimes": [], "discovery": plan.discovery, "files_seen": plan.files_seen, "total_bytes": plan.total_bytes},
        "runs": [], "decision": decision,
        "status": "malicious" if decision == "BLOCK" else ("suspicious" if decision == "REVIEW" else "clean"),
        "findings": findings,
        "reason": "纯指令 Skill 已完成三类语义场景准入检查。",
        "instruction_attestation": {"scenarios": ["typical", "edge", "adversarial"], "raw_content_retained": False, "model_may_block_alone": False},
        "claim_boundary": "纯指令 Skill 不执行代码；结果来自确定性语义规则与可选模型复核。",
    }


def run_skill_sandbox_v2(
    config_path: Path,
    skill_root: Path,
    *,
    semantic_provider: Any = _DEFAULT_SEMANTIC_PROVIDER,
) -> dict[str, Any]:
    started = time.perf_counter()
    config = load_multiruntime_config(config_path)
    plan = discover_skill_entrypoints(skill_root, max_entrypoints=config.max_entrypoints)
    if not plan.entrypoints:
        result = _instruction_audit(skill_root, plan, semantic_provider)
        result["config_sha256"] = config.sha256
        result["duration_ms"] = round((time.perf_counter() - started) * 1000)
        return result
    per_entry = max(1, config.timeout_seconds / len(plan.entrypoints))
    runs = [run_multiruntime_entrypoint(config, skill_root, entry, runtime, per_entry) for entry, runtime in zip(plan.entrypoints, plan.runtimes)]
    decisions = [str((item.get("evaluation") or {}).get("decision") or "BLOCK") for item in runs]
    decision = "BLOCK" if "BLOCK" in decisions else ("REVIEW" if "REVIEW" in decisions else "ALLOW")
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for run in runs:
        for finding in (run.get("evaluation") or {}).get("findings") or []:
            key = (str(finding.get("rule_id") or ""), str(finding.get("evidence") or ""))
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    return {
        "schema_version": "2.0", "backend_id": BACKEND_ID, "config_sha256": config.sha256,
        "execution_kind": "container_scripts",
        "entrypoint_plan": {"entrypoints": list(plan.entrypoints), "runtimes": list(plan.runtimes), "discovery": plan.discovery, "files_seen": plan.files_seen, "total_bytes": plan.total_bytes},
        "runs": runs, "decision": decision,
        "status": "malicious" if decision == "BLOCK" else ("suspicious" if decision == "REVIEW" else "clean"),
        "findings": findings,
        "reason": "隔离试运行观察到高危行为，已升级为阻断。" if decision == "BLOCK" else ("隔离试运行需要人工复核。" if decision == "REVIEW" else "三轮隔离试运行完成，未观察到影响准入的动态风险。"),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "claim_boundary": "语言级钩子与 Shell 跟踪是可解释证据；Docker 安全门是执行隔离边界，不等同于内核级完整检测。",
    }
