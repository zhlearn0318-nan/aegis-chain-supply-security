from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.dynamic_audit import docker_backend
from backend.dynamic_audit.docker_backend import (
    DEMO_ROOT,
    DOCKER_BACKEND_ID,
    EXPECTED_SECURITY,
    FIXTURE_CONTAINER_PATH,
    IMAGE_REFERENCE,
    DockerCommandResult,
    DockerBackendError,
    _cleanup_container,
    build_create_command,
    load_docker_backend_config,
    probe_docker_engine,
    redact_docker_command,
    run_docker_cli,
    validate_container_inspect,
    validate_runtime_probe,
)


CONFIG_PATH = DEMO_ROOT / "config" / "docker_dynamic_backend.json"
CONTAINER_NAME = "aegis-dyn-0123456789abcdef"


def write_mutated_config(tmp_path: Path, mutate) -> Path:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    mutate(payload)
    path = tmp_path / "docker-config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def safe_inspect_payload(config) -> dict:
    return {
        "Config": {
            "Labels": {
                "aegis.dynamic.backend": DOCKER_BACKEND_ID,
                "aegis.dynamic.run": CONTAINER_NAME,
            },
            "Image": IMAGE_REFERENCE,
            "Entrypoint": ["/usr/local/bin/python"],
            "Cmd": ["-B", FIXTURE_CONTAINER_PATH],
            "WorkingDir": "/workspace",
            "User": "65532:65532",
            "Env": [
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "LANG=C.UTF-8",
                "PYTHON_VERSION=3.12.14",
                "PYTHONUNBUFFERED=1",
            ],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "PidMode": "",
            "IpcMode": "none",
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges=true"],
            "PidsLimit": 64,
            "Memory": 268435456,
            "NanoCpus": 500000000,
            "Init": True,
            "LogConfig": {"Type": "none"},
            "Tmpfs": dict(EXPECTED_SECURITY["tmpfs"]),
            "RestartPolicy": {"Name": "no"},
        },
        "Mounts": [{
            "Type": "bind",
            "Source": str(config.fixture_path),
            "Destination": FIXTURE_CONTAINER_PATH,
            "RW": False,
        }],
    }


def safe_runtime_payload() -> dict:
    return {
        "probe_id": "aegis-docker-security-probe-v1",
        "uid": 65532,
        "gid": 65532,
        "cap_eff": "0000000000000000",
        "no_new_privs": "1",
        "seccomp": "2",
        "rootfs_write": {"succeeded": False, "error_type": "OSError"},
        "input_write": {"succeeded": False, "error_type": "OSError"},
        "workspace_write": {"succeeded": True, "content_matched": True},
        "temp_write": {"succeeded": True, "content_matched": True},
        "network_interfaces": ["lo"],
        "cwd": "/workspace",
    }


def test_docker_config_locks_image_fixture_and_security_contract() -> None:
    config = load_docker_backend_config(CONFIG_PATH)

    assert config.image_reference == IMAGE_REFERENCE
    assert config.fixture_path.name == "security_probe.py"
    assert config.fixture_sha256 == "1a2335f575e2d7270f970531c1c603155a9b8fbd4991e6c0711b4433391dbca4"
    assert config.security == EXPECTED_SECURITY


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update({"pull_policy": "always"}),
        lambda payload: payload["image"].update({"reference": "python:latest"}),
        lambda payload: payload["fixture"].update({"sha256": "0" * 64}),
        lambda payload: payload["security"].update({"network_mode": "bridge"}),
        lambda payload: payload["security"].update({"privileged": True}),
        lambda payload: payload["security"].update({"pid_mode": "host"}),
        lambda payload: payload["security"].update({"read_only_rootfs": False}),
        lambda payload: payload["security"].update({"cap_drop": []}),
    ],
)
def test_config_rejects_supply_chain_or_isolation_relaxation(
    tmp_path: Path,
    mutate,
) -> None:
    path = write_mutated_config(tmp_path, mutate)
    with pytest.raises(DockerBackendError):
        load_docker_backend_config(path)


def test_create_command_is_fixed_and_mounts_only_hash_locked_file() -> None:
    config = load_docker_backend_config(CONFIG_PATH)
    docker_cli = Path("C:/trusted/docker.exe")
    command = build_create_command(docker_cli, config, CONTAINER_NAME)
    rendered = " ".join(command)

    assert command[0] == str(docker_cli)
    assert "--pull never" in rendered
    assert "--network none" in rendered
    assert "--read-only" in command
    assert "--user 65532:65532" in rendered
    assert "--cap-drop ALL" in rendered
    assert "--security-opt no-new-privileges=true" in rendered
    assert "--pids-limit 64" in rendered
    assert "--memory 268435456" in rendered
    assert "--cpus 0.5" in rendered
    assert "--privileged" not in command
    assert "host" not in command
    mount = command[command.index("--mount") + 1]
    assert mount.endswith(
        f",target={FIXTURE_CONTAINER_PATH},readonly"
    )
    assert str(config.fixture_path) in mount
    assert "docker.sock" not in mount.lower()

    redacted = " ".join(redact_docker_command(command))
    assert str(config.fixture_path) not in redacted
    assert "<HASH_LOCKED_FIXTURE>" in redacted


def test_command_builder_rejects_unbounded_container_name() -> None:
    config = load_docker_backend_config(CONFIG_PATH)
    with pytest.raises(DockerBackendError, match="CONTAINER_NAME_DENIED"):
        build_create_command(Path("docker.exe"), config, "user-controlled-name")


def test_docker_cli_wrapper_rejects_non_docker_executable_without_spawning() -> None:
    with pytest.raises(DockerBackendError, match="DOCKER_COMMAND_INVALID"):
        run_docker_cli(["powershell.exe", "whoami"], timeout_seconds=1)


def test_engine_probe_records_canonical_api_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        docker_backend,
        "run_docker_cli",
        lambda *_args, **_kwargs: DockerCommandResult(
            return_code=0,
            stdout=json.dumps({
                "Version": "29.7.2",
                "ApiVersion": "1.55",
                "Os": "linux",
                "Arch": "amd64",
            }),
            stderr="",
            duration_ms=1,
        ),
    )
    engine = probe_docker_engine(Path("docker.exe"))
    assert engine["api_version"] == "1.55"


def test_inspect_gate_accepts_only_complete_safe_configuration() -> None:
    config = load_docker_backend_config(CONFIG_PATH)
    gates = validate_container_inspect(
        safe_inspect_payload(config),
        config,
        container_name=CONTAINER_NAME,
    )

    assert len(gates) >= 20
    assert all(gates.values())


@pytest.mark.parametrize(
    ("mutate", "failed_gate"),
    [
        (lambda payload: payload["HostConfig"].update({"NetworkMode": "bridge"}), "network_none"),
        (lambda payload: payload["HostConfig"].update({"ReadonlyRootfs": False}), "read_only_rootfs"),
        (lambda payload: payload["HostConfig"].update({"Privileged": True}), "privileged_false"),
        (lambda payload: payload["HostConfig"].update({"PidMode": "host"}), "pid_mode_private"),
        (lambda payload: payload["HostConfig"].update({"CapDrop": []}), "cap_drop_all"),
        (lambda payload: payload["HostConfig"].update({"SecurityOpt": []}), "no_new_privileges"),
        (lambda payload: payload["HostConfig"].update({"PidsLimit": 0}), "pids_limited"),
        (lambda payload: payload["Config"].update({"User": "0:0"}), "non_root_user"),
    ],
)
def test_inspect_gate_rejects_runtime_security_relaxation(
    mutate,
    failed_gate: str,
) -> None:
    config = load_docker_backend_config(CONFIG_PATH)
    payload = safe_inspect_payload(config)
    mutate(payload)
    gates = validate_container_inspect(payload, config, container_name=CONTAINER_NAME)

    assert gates[failed_gate] is False


def test_inspect_gate_rejects_docker_socket_and_extra_bind() -> None:
    config = load_docker_backend_config(CONFIG_PATH)
    payload = safe_inspect_payload(config)
    payload["Mounts"].append({
        "Type": "bind",
        "Source": "/var/run/docker.sock",
        "Destination": "/var/run/docker.sock",
        "RW": True,
    })
    gates = validate_container_inspect(payload, config, container_name=CONTAINER_NAME)

    assert gates["single_read_only_fixture_bind"] is False
    assert gates["no_docker_socket_or_host_root_mount"] is False


def test_runtime_probe_requires_behavioral_security_evidence() -> None:
    gates = validate_runtime_probe(safe_runtime_payload())
    assert all(gates.values())

    relaxed = safe_runtime_payload()
    relaxed["rootfs_write"] = {"succeeded": True}
    relaxed["cap_eff"] = "0000000000000001"
    relaxed["network_interfaces"] = ["eth0", "lo"]
    failed = validate_runtime_probe(relaxed)
    assert failed["rootfs_write_denied"] is False
    assert failed["effective_capabilities_zero"] is False
    assert failed["network_namespace_loopback_only"] is False


def test_cleanup_uses_only_exact_created_container_id_and_verifies_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container_id = "a" * 64
    calls: list[list[str]] = []

    def fake_run(command: list[str], *, timeout_seconds: float) -> DockerCommandResult:
        calls.append(command)
        is_remove = "rm" in command
        return DockerCommandResult(
            return_code=0 if is_remove else 1,
            stdout=container_id if is_remove else "",
            stderr="",
            duration_ms=1,
        )

    monkeypatch.setattr(docker_backend, "run_docker_cli", fake_run)
    cleanup = _cleanup_container(Path("docker.exe"), container_id)

    assert cleanup["removed"] is True
    assert cleanup["residual"] is False
    assert all(container_id in command for command in calls)
    assert _cleanup_container(Path("docker.exe"), "not-an-id")["attempted"] is False


def test_start_timeout_still_cleans_exact_created_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_docker_backend_config(CONFIG_PATH)
    container_id = "b" * 64
    inspect_payload = safe_inspect_payload(config)
    calls: list[list[str]] = []

    monkeypatch.setattr(docker_backend, "discover_docker_cli", lambda: Path("docker.exe"))
    monkeypatch.setattr(docker_backend.secrets, "token_hex", lambda _size: "0123456789abcdef")
    monkeypatch.setattr(
        docker_backend,
        "probe_docker_engine",
        lambda _docker: {
            "engine_version": "29.7.2",
            "api_version": "1.55",
            "os": "linux",
            "architecture": "amd64",
        },
    )
    monkeypatch.setattr(
        docker_backend,
        "inspect_image_identity",
        lambda _docker, _config: (
            {"id": _config.image_id, "repo_digest_matched": True},
            {
                "image_id_matches": True,
                "repo_digest_matches": True,
                "image_os_linux": True,
                "image_arch_amd64": True,
            },
        ),
    )

    def fake_run(command: list[str], *, timeout_seconds: float) -> DockerCommandResult:
        calls.append(command)
        if "create" in command:
            return DockerCommandResult(0, container_id, "", 1)
        if "start" in command:
            raise DockerBackendError("DOCKER_COMMAND_TIMEOUT", "docker_cli")
        if "inspect" in command and "--format" in command:
            return DockerCommandResult(0, json.dumps(inspect_payload), "", 1)
        if "rm" in command:
            return DockerCommandResult(0, container_id, "", 1)
        if "inspect" in command:
            return DockerCommandResult(1, "", "not found", 1)
        raise AssertionError(command)

    monkeypatch.setattr(docker_backend, "run_docker_cli", fake_run)
    result = docker_backend.run_docker_security_probe(CONFIG_PATH)

    assert result["success"] is False
    assert result["error"]["code"] == "DOCKER_COMMAND_TIMEOUT"
    assert result["metrics"]["timeouts"] == 1
    assert result["cleanup"]["removed"] is True
    assert result["cleanup"]["residual"] is False
    assert any("rm" in command for command in calls)
