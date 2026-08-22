from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
DOCKER_BACKEND_SCHEMA_VERSION = "1.0"
DOCKER_BACKEND_ID = "aegis-docker-safety-v1"
DOCKER_CONTEXT = "desktop-linux"
IMAGE_REFERENCE = (
    "public.ecr.aws/docker/library/python@"
    "sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65"
)
IMAGE_ID = "sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65"
FIXTURE_RELATIVE_PATH = "tools/dynamic/docker/fixtures/security_probe.py"
FIXTURE_CONTAINER_PATH = "/aegis_fixture.py"
FIXTURE_ID = "docker_security_probe"
EXPECTED_FIXTURE_SHA256 = "1a2335f575e2d7270f970531c1c603155a9b8fbd4991e6c0711b4433391dbca4"
CONTAINER_NAME_PATTERN = re.compile(r"^aegis-dyn-[0-9a-f]{16}$")
CONTAINER_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
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
ALLOWED_CONTAINER_ENV_KEYS = {
    "PATH",
    "LANG",
    "GPG_KEY",
    "PYTHON_VERSION",
    "PYTHON_SHA256",
    "PYTHONUNBUFFERED",
}


class DockerBackendError(RuntimeError):
    def __init__(self, code: str, operation: str) -> None:
        super().__init__(f"{code}: {operation}")
        self.code = code
        self.operation = operation


@dataclass(frozen=True)
class DockerBackendConfig:
    config_path: Path
    config_sha256: str
    image_reference: str
    image_id: str
    fixture_path: Path
    fixture_sha256: str
    fixture_timeout_seconds: float
    security: dict[str, Any]


@dataclass(frozen=True)
class DockerCommandResult:
    return_code: int
    stdout: str
    stderr: str
    duration_ms: int


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DockerBackendError("CONFIG_TYPE_INVALID", label)
    return value


def load_docker_backend_config(config_path: Path) -> DockerBackendConfig:
    config_path = config_path.resolve(strict=True)
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DockerBackendError("CONFIG_READ_FAILED", "config_load") from exc
    payload = _require_mapping(payload, "config")
    if payload.get("schema_version") != DOCKER_BACKEND_SCHEMA_VERSION:
        raise DockerBackendError("CONFIG_SCHEMA_DENIED", "config_load")
    if payload.get("backend_id") != DOCKER_BACKEND_ID:
        raise DockerBackendError("CONFIG_BACKEND_ID_DENIED", "config_load")
    if payload.get("docker_context") != DOCKER_CONTEXT:
        raise DockerBackendError("CONFIG_DOCKER_CONTEXT_DENIED", "config_load")
    if payload.get("pull_policy") != "never":
        raise DockerBackendError("CONFIG_PULL_POLICY_DENIED", "config_load")

    image = _require_mapping(payload.get("image"), "image")
    if image != {
        "reference": IMAGE_REFERENCE,
        "id": IMAGE_ID,
        "os": "linux",
        "architecture": "amd64",
    }:
        raise DockerBackendError("CONFIG_IMAGE_IDENTITY_DENIED", "config_load")
    if "@sha256:" not in IMAGE_REFERENCE or not SHA256_PATTERN.fullmatch(
        IMAGE_REFERENCE.rsplit("@sha256:", 1)[1]
    ):
        raise DockerBackendError("CONFIG_IMAGE_NOT_IMMUTABLE", "config_load")

    fixture = _require_mapping(payload.get("fixture"), "fixture")
    expected_fixture_keys = {
        "id",
        "path",
        "sha256",
        "container_path",
        "timeout_seconds",
    }
    if set(fixture) != expected_fixture_keys:
        raise DockerBackendError("CONFIG_FIXTURE_FIELDS_DENIED", "config_load")
    if (
        fixture.get("id") != FIXTURE_ID
        or fixture.get("path") != FIXTURE_RELATIVE_PATH
        or fixture.get("container_path") != FIXTURE_CONTAINER_PATH
        or fixture.get("sha256") != EXPECTED_FIXTURE_SHA256
        or fixture.get("timeout_seconds") != 10
    ):
        raise DockerBackendError("CONFIG_FIXTURE_IDENTITY_DENIED", "config_load")
    fixture_path = (DEMO_ROOT / FIXTURE_RELATIVE_PATH).resolve(strict=True)
    fixture_root = (DEMO_ROOT / "tools" / "dynamic" / "docker" / "fixtures").resolve(
        strict=True
    )
    try:
        fixture_path.relative_to(fixture_root)
    except ValueError as exc:
        raise DockerBackendError("CONFIG_FIXTURE_PATH_DENIED", "config_load") from exc
    if fixture_path.is_symlink() or sha256_file(fixture_path) != EXPECTED_FIXTURE_SHA256:
        raise DockerBackendError("CONFIG_FIXTURE_HASH_MISMATCH", "config_load")

    security = _require_mapping(payload.get("security"), "security")
    if security != EXPECTED_SECURITY:
        raise DockerBackendError("CONFIG_SECURITY_RELAXATION_DENIED", "config_load")
    return DockerBackendConfig(
        config_path=config_path,
        config_sha256=sha256_file(config_path),
        image_reference=IMAGE_REFERENCE,
        image_id=IMAGE_ID,
        fixture_path=fixture_path,
        fixture_sha256=EXPECTED_FIXTURE_SHA256,
        fixture_timeout_seconds=10.0,
        security=security,
    )


def discover_docker_cli() -> Path:
    candidates: list[Path] = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(
            Path(local_app_data)
            / "Programs"
            / "DockerDesktop"
            / "resources"
            / "bin"
            / "docker.exe"
        )
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(
            Path(program_files) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe"
        )
    discovered = shutil.which("docker.exe") or shutil.which("docker")
    if discovered:
        candidates.append(Path(discovered))
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file() and resolved.name.lower() in {"docker.exe", "docker"}:
            return resolved
    raise DockerBackendError("DOCKER_CLI_NOT_FOUND", "docker_discovery")


def _creation_flags() -> int:
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


def run_docker_cli(
    command: list[str],
    *,
    timeout_seconds: float,
) -> DockerCommandResult:
    if not command or Path(command[0]).name.lower() not in {"docker.exe", "docker"}:
        raise DockerBackendError("DOCKER_COMMAND_INVALID", "docker_cli")
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout_seconds,
            shell=False,
            creationflags=_creation_flags(),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DockerBackendError("DOCKER_COMMAND_TIMEOUT", "docker_cli") from exc
    return DockerCommandResult(
        return_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_ms=round((time.perf_counter() - started) * 1000),
    )


def _require_success(result: DockerCommandResult, operation: str) -> str:
    if result.return_code != 0:
        raise DockerBackendError("DOCKER_COMMAND_FAILED", operation)
    return result.stdout.strip()


def _docker_prefix(docker_cli: Path) -> list[str]:
    return [str(docker_cli), "--context", DOCKER_CONTEXT]


def probe_docker_engine(docker_cli: Path) -> dict[str, Any]:
    version_result = run_docker_cli(
        [*_docker_prefix(docker_cli), "version", "--format", "{{json .Server}}"],
        timeout_seconds=15.0,
    )
    try:
        server = json.loads(_require_success(version_result, "engine_version"))
    except json.JSONDecodeError as exc:
        raise DockerBackendError("DOCKER_VERSION_PARSE_FAILED", "engine_version") from exc
    if not isinstance(server, dict) or not server.get("Version"):
        raise DockerBackendError("DOCKER_ENGINE_NOT_READY", "engine_version")
    return {
        "engine_version": str(server.get("Version")),
        "api_version": str(server.get("ApiVersion") or server.get("APIVersion")),
        "os": str(server.get("Os")),
        "architecture": str(server.get("Arch")),
        "duration_ms": version_result.duration_ms,
    }


def inspect_image_identity(
    docker_cli: Path,
    config: DockerBackendConfig,
) -> tuple[dict[str, Any], dict[str, bool]]:
    result = run_docker_cli(
        [
            *_docker_prefix(docker_cli),
            "image",
            "inspect",
            config.image_reference,
            "--format",
            "{{json .}}",
        ],
        timeout_seconds=15.0,
    )
    try:
        image = json.loads(_require_success(result, "image_inspect"))
    except json.JSONDecodeError as exc:
        raise DockerBackendError("DOCKER_IMAGE_PARSE_FAILED", "image_inspect") from exc
    if not isinstance(image, dict):
        raise DockerBackendError("DOCKER_IMAGE_PARSE_FAILED", "image_inspect")
    repo_digests = [str(value) for value in image.get("RepoDigests") or []]
    gates = {
        "image_id_matches": image.get("Id") == config.image_id,
        "repo_digest_matches": config.image_reference in repo_digests,
        "image_os_linux": image.get("Os") == "linux",
        "image_arch_amd64": image.get("Architecture") == "amd64",
    }
    return ({
        "id": str(image.get("Id") or ""),
        "repo_digest_matched": gates["repo_digest_matches"],
        "os": str(image.get("Os") or ""),
        "architecture": str(image.get("Architecture") or ""),
        "duration_ms": result.duration_ms,
    }, gates)


def build_create_command(
    docker_cli: Path,
    config: DockerBackendConfig,
    container_name: str,
) -> list[str]:
    if not CONTAINER_NAME_PATTERN.fullmatch(container_name):
        raise DockerBackendError("CONTAINER_NAME_DENIED", "command_plan")
    source = str(config.fixture_path)
    if "," in source or "\r" in source or "\n" in source:
        raise DockerBackendError("FIXTURE_MOUNT_PATH_DENIED", "command_plan")
    security = config.security
    command = [
        *_docker_prefix(docker_cli),
        "create",
        "--name",
        container_name,
        "--label",
        f"aegis.dynamic.backend={DOCKER_BACKEND_ID}",
        "--label",
        f"aegis.dynamic.run={container_name}",
        "--pull",
        "never",
        "--network",
        security["network_mode"],
        "--read-only",
        "--user",
        security["user"],
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        str(security["pids_limit"]),
        "--memory",
        str(security["memory_bytes"]),
        "--cpus",
        "0.5",
        "--init",
        "--ipc",
        security["ipc_mode"],
        "--log-driver",
        security["log_driver"],
        "--stop-timeout",
        "1",
        "--hostname",
        "aegis-sandbox",
        "--workdir",
        "/workspace",
        "--env",
        "PYTHONUNBUFFERED=1",
        "--entrypoint",
        "/usr/local/bin/python",
    ]
    for destination, options in sorted(security["tmpfs"].items()):
        command.extend(["--tmpfs", f"{destination}:{options}"])
    command.extend([
        "--mount",
        f"type=bind,source={source},target={FIXTURE_CONTAINER_PATH},readonly",
        config.image_reference,
        "-B",
        FIXTURE_CONTAINER_PATH,
    ])
    return command


def redact_docker_command(command: Iterable[str]) -> list[str]:
    redacted: list[str] = []
    for index, value in enumerate(command):
        if index == 0:
            redacted.append("<DOCKER_CLI>")
        elif value.startswith("type=bind,source="):
            redacted.append(
                f"type=bind,source=<HASH_LOCKED_FIXTURE>,target={FIXTURE_CONTAINER_PATH},readonly"
            )
        elif CONTAINER_ID_PATTERN.fullmatch(value):
            redacted.append("<CONTAINER_ID>")
        else:
            redacted.append(value)
    return redacted


def validate_container_inspect(
    inspect_payload: dict[str, Any],
    config: DockerBackendConfig,
    *,
    container_name: str,
) -> dict[str, bool]:
    container_config = _require_mapping(inspect_payload.get("Config"), "inspect.Config")
    host_config = _require_mapping(inspect_payload.get("HostConfig"), "inspect.HostConfig")
    labels = container_config.get("Labels") or {}
    env_keys = {
        str(entry).split("=", 1)[0]
        for entry in container_config.get("Env") or []
        if isinstance(entry, str) and "=" in entry
    }
    mounts = inspect_payload.get("Mounts") or []
    if not isinstance(mounts, list):
        mounts = []
    bind_mounts = [mount for mount in mounts if mount.get("Type") == "bind"]
    forbidden_mount_text = json.dumps(mounts, ensure_ascii=False).lower()
    source_matches = False
    if len(bind_mounts) == 1:
        source_value = Path(str(bind_mounts[0].get("Source") or "")).resolve(strict=False)
        source_matches = os.path.normcase(str(source_value)) == os.path.normcase(
            str(config.fixture_path.resolve(strict=True))
        )
    cap_drop = {str(value).upper() for value in host_config.get("CapDrop") or []}
    security_opt = {str(value).lower() for value in host_config.get("SecurityOpt") or []}
    tmpfs = host_config.get("Tmpfs") or {}
    return {
        "label_backend_exact": labels.get("aegis.dynamic.backend") == DOCKER_BACKEND_ID,
        "label_run_exact": labels.get("aegis.dynamic.run") == container_name,
        "image_reference_immutable": container_config.get("Image") == config.image_reference,
        "entrypoint_fixed": container_config.get("Entrypoint") == ["/usr/local/bin/python"],
        "command_fixed": container_config.get("Cmd") == ["-B", FIXTURE_CONTAINER_PATH],
        "workdir_fixed": container_config.get("WorkingDir") == "/workspace",
        "non_root_user": container_config.get("User") == EXPECTED_SECURITY["user"],
        "container_env_allowlisted": env_keys <= ALLOWED_CONTAINER_ENV_KEYS,
        "network_none": host_config.get("NetworkMode") == "none",
        "read_only_rootfs": host_config.get("ReadonlyRootfs") is True,
        "privileged_false": host_config.get("Privileged") is False,
        "pid_mode_private": str(host_config.get("PidMode") or "") == "",
        "ipc_none": host_config.get("IpcMode") == "none",
        "cap_drop_all": "ALL" in cap_drop and not host_config.get("CapAdd"),
        "no_new_privileges": "no-new-privileges=true" in security_opt,
        "pids_limited": host_config.get("PidsLimit") == EXPECTED_SECURITY["pids_limit"],
        "memory_limited": host_config.get("Memory") == EXPECTED_SECURITY["memory_bytes"],
        "cpu_limited": host_config.get("NanoCpus") == EXPECTED_SECURITY["nano_cpus"],
        "init_enabled": host_config.get("Init") is True,
        "log_driver_none": (host_config.get("LogConfig") or {}).get("Type") == "none",
        "tmpfs_exact": tmpfs == EXPECTED_SECURITY["tmpfs"],
        "single_read_only_fixture_bind": (
            len(bind_mounts) == 1
            and bind_mounts[0].get("Destination") == FIXTURE_CONTAINER_PATH
            and bind_mounts[0].get("RW") is False
            and source_matches
        ),
        "no_docker_socket_or_host_root_mount": (
            "docker.sock" not in forbidden_mount_text
            and '"destination": "/"' not in forbidden_mount_text
            and len(bind_mounts) == 1
        ),
        "restart_disabled": (host_config.get("RestartPolicy") or {}).get("Name") == "no",
    }


def validate_runtime_probe(payload: dict[str, Any]) -> dict[str, bool]:
    rootfs_write = payload.get("rootfs_write") or {}
    input_write = payload.get("input_write") or {}
    workspace_write = payload.get("workspace_write") or {}
    temp_write = payload.get("temp_write") or {}
    return {
        "probe_identity": payload.get("probe_id") == "aegis-docker-security-probe-v1",
        "uid_non_root_exact": payload.get("uid") == 65532,
        "gid_non_root_exact": payload.get("gid") == 65532,
        "effective_capabilities_zero": payload.get("cap_eff") == "0000000000000000",
        "no_new_privileges_active": payload.get("no_new_privs") == "1",
        "seccomp_filter_active": payload.get("seccomp") == "2",
        "rootfs_write_denied": rootfs_write.get("succeeded") is False,
        "input_mount_write_denied": input_write.get("succeeded") is False,
        "workspace_tmpfs_write_allowed": (
            workspace_write.get("succeeded") is True
            and workspace_write.get("content_matched") is True
        ),
        "temp_tmpfs_write_allowed": (
            temp_write.get("succeeded") is True
            and temp_write.get("content_matched") is True
        ),
        "network_namespace_loopback_only": payload.get("network_interfaces") == ["lo"],
        "working_directory_bounded": payload.get("cwd") == "/workspace",
    }


def _parse_json_object(value: str, code: str, operation: str) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise DockerBackendError(code, operation) from exc
    if not isinstance(payload, dict):
        raise DockerBackendError(code, operation)
    return payload


def _cleanup_container(
    docker_cli: Path,
    container_id: str,
) -> dict[str, Any]:
    if not CONTAINER_ID_PATTERN.fullmatch(container_id):
        return {"attempted": False, "removed": False, "residual": True}
    remove = run_docker_cli(
        [*_docker_prefix(docker_cli), "container", "rm", "--force", container_id],
        timeout_seconds=15.0,
    )
    verify = run_docker_cli(
        [*_docker_prefix(docker_cli), "container", "inspect", container_id],
        timeout_seconds=10.0,
    )
    return {
        "attempted": True,
        "removed": remove.return_code == 0,
        "residual": verify.return_code == 0,
        "remove_duration_ms": remove.duration_ms,
    }


def run_docker_security_probe(config_path: Path) -> dict[str, Any]:
    started = time.perf_counter()
    config = load_docker_backend_config(config_path)
    docker_cli = discover_docker_cli()
    container_name = f"aegis-dyn-{secrets.token_hex(8)}"
    container_id = ""
    error: dict[str, str] | None = None
    engine: dict[str, Any] = {}
    image: dict[str, Any] = {}
    image_gates: dict[str, bool] = {}
    inspect_gates: dict[str, bool] = {}
    runtime_gates: dict[str, bool] = {}
    runtime_payload: dict[str, Any] = {}
    start_result: DockerCommandResult | None = None
    command_plan = build_create_command(docker_cli, config, container_name)
    cleanup = {"attempted": False, "removed": False, "residual": False}
    try:
        engine = probe_docker_engine(docker_cli)
        image, image_gates = inspect_image_identity(docker_cli, config)
        if not all(image_gates.values()):
            raise DockerBackendError("DOCKER_IMAGE_GATE_FAILED", "image_inspect")
        create_result = run_docker_cli(command_plan, timeout_seconds=20.0)
        container_id = _require_success(create_result, "container_create")
        if not CONTAINER_ID_PATTERN.fullmatch(container_id):
            raise DockerBackendError("CONTAINER_ID_INVALID", "container_create")

        inspect_result = run_docker_cli(
            [
                *_docker_prefix(docker_cli),
                "container",
                "inspect",
                container_id,
                "--format",
                "{{json .}}",
            ],
            timeout_seconds=15.0,
        )
        inspect_payload = _parse_json_object(
            _require_success(inspect_result, "container_inspect"),
            "CONTAINER_INSPECT_PARSE_FAILED",
            "container_inspect",
        )
        inspect_gates = validate_container_inspect(
            inspect_payload,
            config,
            container_name=container_name,
        )
        if not all(inspect_gates.values()):
            raise DockerBackendError("CONTAINER_INSPECT_GATE_FAILED", "container_inspect")

        start_result = run_docker_cli(
            [*_docker_prefix(docker_cli), "container", "start", "--attach", container_id],
            timeout_seconds=config.fixture_timeout_seconds,
        )
        runtime_payload = _parse_json_object(
            _require_success(start_result, "container_start"),
            "RUNTIME_PROBE_PARSE_FAILED",
            "container_start",
        )
        runtime_gates = validate_runtime_probe(runtime_payload)
        if not all(runtime_gates.values()):
            raise DockerBackendError("RUNTIME_PROBE_GATE_FAILED", "container_start")
    except DockerBackendError as exc:
        error = {"code": exc.code, "operation": exc.operation}
    finally:
        if container_id:
            try:
                cleanup = _cleanup_container(docker_cli, container_id)
            except DockerBackendError as exc:
                cleanup = {
                    "attempted": True,
                    "removed": False,
                    "residual": True,
                    "error_code": exc.code,
                }

    all_gates = {**image_gates, **inspect_gates, **runtime_gates}
    success = (
        error is None
        and bool(all_gates)
        and all(all_gates.values())
        and cleanup.get("removed") is True
        and cleanup.get("residual") is False
    )
    metrics = {
        "schema_version": DOCKER_BACKEND_SCHEMA_VERSION,
        "backend_id": DOCKER_BACKEND_ID,
        "engine_ready": bool(engine.get("engine_version")),
        "image_gates_total": len(image_gates),
        "image_gates_passed": sum(image_gates.values()),
        "inspect_gates_total": len(inspect_gates),
        "inspect_gates_passed": sum(inspect_gates.values()),
        "runtime_gates_total": len(runtime_gates),
        "runtime_gates_passed": sum(runtime_gates.values()),
        "all_gates_total": len(all_gates),
        "all_gates_passed": sum(all_gates.values()),
        "fixture_completed": int(bool(runtime_payload)),
        "policy_violations": int(any(not value for value in all_gates.values())),
        "timeouts": int(bool(error and error.get("code") == "DOCKER_COMMAND_TIMEOUT")),
        "container_residuals": int(cleanup.get("residual") is True),
        "third_party_samples_read": 0,
        "third_party_samples_executed": 0,
        "internet_connections_allowed": 0,
        "image_pulls_allowed": 0,
        "gpu_used": False,
        "decision_changes": 0,
        "duration_ms": round((time.perf_counter() - started) * 1000),
    }
    public_runtime = {
        "probe_id": runtime_payload.get("probe_id"),
        "uid": runtime_payload.get("uid"),
        "gid": runtime_payload.get("gid"),
        "cap_eff": runtime_payload.get("cap_eff"),
        "no_new_privs": runtime_payload.get("no_new_privs"),
        "seccomp": runtime_payload.get("seccomp"),
        "rootfs_write_succeeded": (runtime_payload.get("rootfs_write") or {}).get(
            "succeeded"
        ),
        "input_write_succeeded": (runtime_payload.get("input_write") or {}).get(
            "succeeded"
        ),
        "workspace_write_succeeded": (
            runtime_payload.get("workspace_write") or {}
        ).get("succeeded"),
        "temp_write_succeeded": (runtime_payload.get("temp_write") or {}).get(
            "succeeded"
        ),
        "network_interfaces": runtime_payload.get("network_interfaces"),
        "cwd": runtime_payload.get("cwd"),
    }
    return {
        "success": success,
        "error": error,
        "config": {
            "schema_version": DOCKER_BACKEND_SCHEMA_VERSION,
            "backend_id": DOCKER_BACKEND_ID,
            "config_sha256": config.config_sha256,
            "fixture_id": FIXTURE_ID,
            "fixture_sha256": config.fixture_sha256,
            "image_reference": config.image_reference,
            "image_id": config.image_id,
            "pull_policy": "never",
        },
        "engine": engine,
        "image": image,
        "create_command": redact_docker_command(command_plan),
        "image_gates": image_gates,
        "inspect_gates": inspect_gates,
        "runtime_gates": runtime_gates,
        "runtime_probe": public_runtime,
        "container_identity_sha256": sha256_bytes(container_id.encode("ascii"))
        if container_id
        else None,
        "start_output": {
            "stdout_bytes": len(start_result.stdout.encode("utf-8")) if start_result else 0,
            "stdout_sha256": sha256_bytes(start_result.stdout.encode("utf-8"))
            if start_result
            else None,
            "stderr_bytes": len(start_result.stderr.encode("utf-8")) if start_result else 0,
            "stderr_sha256": sha256_bytes(start_result.stderr.encode("utf-8"))
            if start_result
            else None,
            "duration_ms": start_result.duration_ms if start_result else None,
            "raw_output_retained": False,
        },
        "cleanup": cleanup,
        "metrics": metrics,
        "claim_boundary": (
            "Docker configuration and self-built probe evidence only; no third-party code "
            "execution and no container-escape resistance claim."
        ),
    }
