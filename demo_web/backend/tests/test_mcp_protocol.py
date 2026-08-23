from __future__ import annotations

import base64
import io
import json
from pathlib import Path

import pytest

from backend.dynamic_audit import mcp_protocol
from backend.dynamic_audit.docker_backend import (
    EXPECTED_SECURITY,
    IMAGE_REFERENCE,
    DockerBackendError,
    DockerCommandResult,
)
from backend.dynamic_audit.mcp_protocol import (
    DEMO_ROOT,
    EXPECTED_CLIENT_METHODS,
    MCP_FIXTURE_SHA256,
    MCP_PROTOCOL_VERSION,
    MCP_TOOL_NAME,
    evaluate_mcp_protocol_payload,
    load_mcp_protocol_config,
)
from tools.dynamic.docker.fixtures import mcp_protocol_marker as fixture


CONFIG_PATH = DEMO_ROOT / "config" / "docker_mcp_protocol_backend.json"


def write_mutated_config(tmp_path: Path, mutate) -> Path:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    mutate(payload)
    path = tmp_path / "mcp-config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def protocol_exchange(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "workspace" / fixture.MARKER_SOURCE_REF
    monkeypatch.setattr(fixture, "MARKER_SOURCE_PATH", source)
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": fixture.PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": fixture.TOOL_NAME,
                "arguments": {"action": "summarize"},
            },
        },
    ]
    stdin = io.StringIO("".join(fixture.compact_json(row) + "\n" for row in messages))
    stdout = io.StringIO()
    assert fixture.run_server(stdin, stdout) == 0
    raw_rows = stdout.getvalue().splitlines()
    rows = [json.loads(row) for row in raw_rows]
    marker_id, token, token_sha256 = fixture.marker_identity()
    payload = {
        "fixture_id": fixture.FIXTURE_ID,
        "protocol_version": fixture.PROTOCOL_VERSION,
        "transport": "stdio_newline_delimited_jsonrpc",
        "server_subprocess_started": True,
        "server_exit_code": 0,
        "server_stderr_bytes": 0,
        "initialize_success": True,
        "initialized_notification_sent": True,
        "tools_list_success": True,
        "listed_tool_names": [fixture.TOOL_NAME],
        "listed_tool_schemas": [fixture.tool_definition()["inputSchema"]],
        "schema_valid_calls": 1,
        "tool_call_success": True,
        "protocol_errors": 0,
        "marker_identity": {
            "marker_id": marker_id,
            "profile": fixture.MARKER_PROFILE,
            "source_kind": fixture.MARKER_SOURCE_KIND,
            "source_ref": fixture.MARKER_SOURCE_REF,
            "token_sha256": token_sha256,
            "source_sha256": token_sha256,
        },
        "transcript": [
            {"direction": "client_to_server", "kind": "request", "method": method}
            for method in EXPECTED_CLIENT_METHODS
        ],
        "pre_call_capture_b64": base64.b64encode(
            (raw_rows[0] + "\n" + raw_rows[1]).encode("utf-8")
        ).decode("ascii"),
        "post_call_capture_b64": base64.b64encode(raw_rows[2].encode("utf-8")).decode(
            "ascii"
        ),
        "probe_id": "aegis-docker-security-probe-v1",
        "uid": 65532,
        "gid": 65532,
        "cap_eff": "0000000000000000",
        "no_new_privs": "1",
        "seccomp": "2",
        "rootfs_write": {"succeeded": False},
        "input_write": {"succeeded": False},
        "workspace_write": {"succeeded": True, "content_matched": True},
        "temp_write": {"succeeded": True, "content_matched": True},
        "network_interfaces": ["lo"],
        "cwd": "/workspace",
    }
    return payload, token, rows, stdout.getvalue()


def test_config_locks_mcp_fixture_marker_image_and_security() -> None:
    config = load_mcp_protocol_config(CONFIG_PATH)

    assert config.docker.image_reference == IMAGE_REFERENCE
    assert config.docker.fixture_sha256 == MCP_FIXTURE_SHA256
    assert config.docker.fixture_path.name == "mcp_protocol_marker.py"
    assert config.marker["profile"] == "official_document"
    assert config.docker.security == EXPECTED_SECURITY


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update({"pull_policy": "always"}),
        lambda payload: payload["image"].update({"reference": "python:latest"}),
        lambda payload: payload["fixture"].update({"sha256": "0" * 64}),
        lambda payload: payload["marker"].update({"profile": "ops_token"}),
        lambda payload: payload["security"].update({"network_mode": "bridge"}),
        lambda payload: payload["security"].update({"read_only_rootfs": False}),
    ],
)
def test_config_rejects_identity_or_security_relaxation(tmp_path: Path, mutate) -> None:
    with pytest.raises(DockerBackendError):
        load_mcp_protocol_config(write_mutated_config(tmp_path, mutate))


def test_self_built_server_uses_real_stdio_sequence_and_marker_only_after_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _payload, token, rows, raw_stdout = protocol_exchange(tmp_path, monkeypatch)

    assert len(rows) == 3
    assert rows[0]["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert rows[1]["result"]["tools"][0]["name"] == MCP_TOOL_NAME
    assert token not in json.dumps(rows[:2], ensure_ascii=False)
    assert base64.b64encode(token.encode("utf-8")).decode("ascii") in json.dumps(
        rows[2], ensure_ascii=False
    )
    assert token not in raw_stdout


def test_server_returns_protocol_errors_for_unknown_tool_and_invalid_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "workspace" / fixture.MARKER_SOURCE_REF
    monkeypatch.setattr(fixture, "MARKER_SOURCE_PATH", source)
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": fixture.PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "unknown", "arguments": {}},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": fixture.TOOL_NAME, "arguments": {"action": "delete"}},
        },
    ]
    stdout = io.StringIO()
    fixture.run_server(
        io.StringIO("".join(fixture.compact_json(row) + "\n" for row in messages)),
        stdout,
    )
    rows = [json.loads(row) for row in stdout.getvalue().splitlines()]

    assert rows[1]["error"]["code"] == -32602
    assert rows[2]["error"]["code"] == -32602


def test_protocol_evaluator_forms_redacted_confirmed_witness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, token, _rows, _stdout = protocol_exchange(tmp_path, monkeypatch)
    evaluated = evaluate_mcp_protocol_payload(payload, load_mcp_protocol_config(CONFIG_PATH))
    internal_token = evaluated.pop("marker_token")

    assert internal_token == token
    assert all(evaluated["protocol_gates"].values())
    assert all(evaluated["runtime_gates"].values())
    assert evaluated["protocol_steps"]["passed"] == 4
    assert evaluated["pre_call_marker_witnesses"] == []
    assert len(evaluated["post_call_marker_witnesses"]) == 1
    assert evaluated["post_call_marker_witnesses"][0]["transform"] == "base64"
    assert evaluated["correlation"]["status"] == "confirmed"
    assert evaluated["correlation"]["static_decision_changed"] is False
    assert token not in json.dumps(evaluated, ensure_ascii=False)


def test_protocol_evaluator_detects_marker_on_pre_call_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, _token, rows, _stdout = protocol_exchange(tmp_path, monkeypatch)
    initialize = base64.b64decode(payload["pre_call_capture_b64"]).decode("utf-8").splitlines()[0]
    call = json.dumps(rows[2], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["pre_call_capture_b64"] = base64.b64encode(
        (initialize + "\n" + call).encode("utf-8")
    ).decode("ascii")
    evaluated = evaluate_mcp_protocol_payload(payload, load_mcp_protocol_config(CONFIG_PATH))

    assert evaluated["protocol_gates"]["pre_call_marker_absent"] is False
    assert len(evaluated["pre_call_marker_witnesses"]) == 1


def test_mcp_start_timeout_still_routes_to_exact_shared_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container_id = "b" * 64
    cleanup_calls: list[str] = []
    monkeypatch.setattr(mcp_protocol, "discover_docker_cli", lambda: Path("docker.exe"))
    monkeypatch.setattr(mcp_protocol.secrets, "token_hex", lambda _size: "0123456789abcdef")
    monkeypatch.setattr(
        mcp_protocol,
        "probe_docker_engine",
        lambda _docker: {"engine_version": "29.7.2", "api_version": "1.55"},
    )
    monkeypatch.setattr(
        mcp_protocol,
        "inspect_image_identity",
        lambda _docker, _config: ({"id": _config.image_id}, {"image": True}),
    )
    monkeypatch.setattr(
        mcp_protocol,
        "validate_container_inspect",
        lambda *_args, **_kwargs: {"inspect": True},
    )

    def fake_run(command: list[str], *, timeout_seconds: float) -> DockerCommandResult:
        if "create" in command:
            return DockerCommandResult(0, container_id, "", 1)
        if "inspect" in command:
            return DockerCommandResult(0, "{}", "", 1)
        if "start" in command:
            raise DockerBackendError("DOCKER_COMMAND_TIMEOUT", "docker_cli")
        raise AssertionError(command)

    def fake_cleanup(_docker: Path, exact_id: str):
        cleanup_calls.append(exact_id)
        return {"attempted": True, "removed": True, "residual": False}

    monkeypatch.setattr(mcp_protocol, "run_docker_cli", fake_run)
    monkeypatch.setattr(mcp_protocol, "_cleanup_container", fake_cleanup)
    result = mcp_protocol.run_mcp_protocol_probe(CONFIG_PATH)

    assert result["success"] is False
    assert result["error"]["code"] == "DOCKER_COMMAND_TIMEOUT"
    assert result["metrics"]["timeouts"] == 1
    assert result["cleanup"]["residual"] is False
    assert cleanup_calls == [container_id]
