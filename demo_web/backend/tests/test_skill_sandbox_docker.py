from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.dynamic_audit.docker_backend import DockerBackendError
from backend.dynamic_audit.skill_sandbox_docker import (
    BACKEND_ID,
    EXPECTED_SECURITY,
    IMAGE_REFERENCE,
    build_skill_container_command,
    load_skill_sandbox_config,
    validate_skill_container_inspect,
)


DEMO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = DEMO_ROOT / "config" / "skill_dynamic_sandbox.json"


def make_skill(root: Path) -> Path:
    root.mkdir()
    (root / "SKILL.md").write_text("Run scripts/main.py\n", encoding="utf-8")
    scripts = root / "scripts"
    scripts.mkdir()
    (scripts / "main.py").write_text("print('ok')\n", encoding="utf-8")
    return root


def test_loads_hash_locked_skill_sandbox_config() -> None:
    config = load_skill_sandbox_config(CONFIG)
    assert config.timeout_seconds == 90
    assert config.max_entrypoints == 3
    assert config.security == EXPECTED_SECURITY


def test_rejects_relaxed_config(tmp_path: Path) -> None:
    payload = json.loads(CONFIG.read_text(encoding="utf-8"))
    payload["security"]["privileged"] = True
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DockerBackendError, match="CONFIG_SECURITY_RELAXATION_DENIED"):
        load_skill_sandbox_config(changed)


def test_command_never_grants_target_container_privilege(tmp_path: Path) -> None:
    config = load_skill_sandbox_config(CONFIG)
    skill = make_skill(tmp_path / "skill")
    command = build_skill_container_command(
        Path("C:/Docker/docker.exe"), config, skill_root=skill,
        entrypoint="scripts/main.py", container_name="aegis-skill-0123456789abcdef",
        timeout_seconds=30,
    )
    joined = " ".join(command).casefold()
    assert "--privileged" not in command
    assert "--pid=host" not in joined
    assert "docker.sock" not in joined
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges=true" in command
    assert command.count("--mount") == 2


def inspect_payload(config, skill: Path, entrypoint: str = "scripts/main.py") -> dict:
    return {
        "Config": {
            "Labels": {
                "aegis.dynamic.backend": BACKEND_ID,
                "aegis.dynamic.run": "aegis-skill-0123456789abcdef",
            },
            "Image": IMAGE_REFERENCE,
            "Entrypoint": ["/usr/local/bin/python"],
            "Cmd": [
                "-B", "/aegis_tool/runner.py", "--skill-root", "/skill",
                "--entry", entrypoint, "--timeout-seconds", "30",
            ],
            "WorkingDir": "/workspace",
            "User": "65532:65532",
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
            "Tmpfs": EXPECTED_SECURITY["tmpfs"],
            "RestartPolicy": {"Name": "no"},
        },
        "Mounts": [
            {"Type": "bind", "Source": str(skill.resolve()), "Destination": "/skill", "RW": False},
            {"Type": "bind", "Source": str(config.tool_root.resolve()), "Destination": "/aegis_tool", "RW": False},
        ],
    }


def test_post_create_inspect_requires_all_security_gates(tmp_path: Path) -> None:
    config = load_skill_sandbox_config(CONFIG)
    skill = make_skill(tmp_path / "skill")
    payload = inspect_payload(config, skill)
    gates = validate_skill_container_inspect(
        payload, config, skill_root=skill, entrypoint="scripts/main.py",
        container_name="aegis-skill-0123456789abcdef", timeout_seconds=30,
    )
    assert len(gates) >= 20
    assert all(gates.values())
    payload["HostConfig"]["Privileged"] = True
    assert not validate_skill_container_inspect(
        payload, config, skill_root=skill, entrypoint="scripts/main.py",
        container_name="aegis-skill-0123456789abcdef", timeout_seconds=30,
    )["privileged_false"]
