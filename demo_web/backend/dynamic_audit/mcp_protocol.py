from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .docker_backend import (
    CONTAINER_ID_PATTERN,
    DEMO_ROOT,
    DOCKER_BACKEND_SCHEMA_VERSION,
    DOCKER_CONTEXT,
    EXPECTED_SECURITY,
    FIXTURE_CONTAINER_PATH,
    IMAGE_ID,
    IMAGE_REFERENCE,
    DockerBackendConfig,
    DockerBackendError,
    DockerCommandResult,
    _cleanup_container,
    _docker_prefix,
    _parse_json_object,
    _require_mapping,
    _require_success,
    build_create_command,
    discover_docker_cli,
    inspect_image_identity,
    probe_docker_engine,
    redact_docker_command,
    run_docker_cli,
    sha256_bytes,
    sha256_file,
    validate_container_inspect,
    validate_runtime_probe,
)
from .markers import MarkerEvidenceError, create_marker, find_marker_witnesses
from .planning import build_trigger_plan, correlate_dynamic_evidence


MCP_BACKEND_SCHEMA_VERSION = "1.0"
MCP_BACKEND_ID = "aegis-docker-mcp-protocol-v1"
MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_FIXTURE_ID = "mcp_protocol_marker"
MCP_FIXTURE_RUNTIME_ID = "aegis-mcp-protocol-marker-v1"
MCP_FIXTURE_RELATIVE_PATH = "tools/dynamic/docker/fixtures/mcp_protocol_marker.py"
MCP_FIXTURE_SHA256 = "7ad3190e5838096351b4874736b29d63b5ac8579fb5b967b0014ed8e35498d11"
MCP_TOOL_NAME = "read_official_document"
MAX_CAPTURE_BYTES = 128 * 1024
EXPECTED_MARKER = {
    "profile": "official_document",
    "seed": "2026-08-23-mcp-protocol-marker-dev-v1",
    "source_kind": "decoy_file",
    "source_ref": "decoys/official_document.txt",
}
EXPECTED_INPUT_SCHEMA = {
    "type": "object",
    "properties": {"action": {"type": "string", "const": "summarize"}},
    "required": ["action"],
    "additionalProperties": False,
}
EXPECTED_CLIENT_METHODS = (
    "initialize",
    "notifications/initialized",
    "tools/list",
    "tools/call",
)


@dataclass(frozen=True)
class McpProtocolConfig:
    config_path: Path
    config_sha256: str
    docker: DockerBackendConfig
    marker: dict[str, str]


def load_mcp_protocol_config(config_path: Path) -> McpProtocolConfig:
    config_path = config_path.resolve(strict=True)
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DockerBackendError("MCP_CONFIG_READ_FAILED", "config_load") from exc
    payload = _require_mapping(payload, "config")
    if set(payload) != {
        "schema_version",
        "backend_id",
        "docker_context",
        "pull_policy",
        "image",
        "fixture",
        "marker",
        "security",
    }:
        raise DockerBackendError("MCP_CONFIG_FIELDS_DENIED", "config_load")
    if payload.get("schema_version") != MCP_BACKEND_SCHEMA_VERSION:
        raise DockerBackendError("MCP_CONFIG_SCHEMA_DENIED", "config_load")
    if payload.get("backend_id") != MCP_BACKEND_ID:
        raise DockerBackendError("MCP_CONFIG_BACKEND_ID_DENIED", "config_load")
    if payload.get("docker_context") != DOCKER_CONTEXT:
        raise DockerBackendError("MCP_CONFIG_CONTEXT_DENIED", "config_load")
    if payload.get("pull_policy") != "never":
        raise DockerBackendError("MCP_CONFIG_PULL_POLICY_DENIED", "config_load")

    image = _require_mapping(payload.get("image"), "image")
    if image != {
        "reference": IMAGE_REFERENCE,
        "id": IMAGE_ID,
        "os": "linux",
        "architecture": "amd64",
    }:
        raise DockerBackendError("MCP_CONFIG_IMAGE_IDENTITY_DENIED", "config_load")

    fixture = _require_mapping(payload.get("fixture"), "fixture")
    if fixture != {
        "id": MCP_FIXTURE_ID,
        "path": MCP_FIXTURE_RELATIVE_PATH,
        "sha256": MCP_FIXTURE_SHA256,
        "container_path": FIXTURE_CONTAINER_PATH,
        "timeout_seconds": 10,
    }:
        raise DockerBackendError("MCP_CONFIG_FIXTURE_IDENTITY_DENIED", "config_load")
    fixture_path = (DEMO_ROOT / MCP_FIXTURE_RELATIVE_PATH).resolve(strict=True)
    fixture_root = (DEMO_ROOT / "tools" / "dynamic" / "docker" / "fixtures").resolve(
        strict=True
    )
    try:
        fixture_path.relative_to(fixture_root)
    except ValueError as exc:
        raise DockerBackendError("MCP_CONFIG_FIXTURE_PATH_DENIED", "config_load") from exc
    if fixture_path.is_symlink() or sha256_file(fixture_path) != MCP_FIXTURE_SHA256:
        raise DockerBackendError("MCP_CONFIG_FIXTURE_HASH_MISMATCH", "config_load")

    marker = _require_mapping(payload.get("marker"), "marker")
    if marker != EXPECTED_MARKER:
        raise DockerBackendError("MCP_CONFIG_MARKER_IDENTITY_DENIED", "config_load")
    security = _require_mapping(payload.get("security"), "security")
    if security != EXPECTED_SECURITY:
        raise DockerBackendError("MCP_CONFIG_SECURITY_RELAXATION_DENIED", "config_load")

    docker_config = DockerBackendConfig(
        config_path=config_path,
        config_sha256=sha256_file(config_path),
        image_reference=IMAGE_REFERENCE,
        image_id=IMAGE_ID,
        fixture_path=fixture_path,
        fixture_sha256=MCP_FIXTURE_SHA256,
        fixture_timeout_seconds=10.0,
        security=security,
    )
    return McpProtocolConfig(
        config_path=config_path,
        config_sha256=docker_config.config_sha256,
        docker=docker_config,
        marker=dict(EXPECTED_MARKER),
    )


def _decode_capture(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > MAX_CAPTURE_BYTES * 2:
        raise DockerBackendError("MCP_CAPTURE_BOUNDS_DENIED", label)
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise DockerBackendError("MCP_CAPTURE_DECODE_FAILED", label) from exc
    if not decoded or len(decoded) > MAX_CAPTURE_BYTES:
        raise DockerBackendError("MCP_CAPTURE_BOUNDS_DENIED", label)
    return decoded


def _json_lines(payload: bytes, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DockerBackendError("MCP_CAPTURE_UTF8_FAILED", label) from exc
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DockerBackendError("MCP_CAPTURE_JSON_FAILED", label) from exc
        if not isinstance(row, dict):
            raise DockerBackendError("MCP_CAPTURE_JSON_FAILED", label)
        rows.append(row)
    if not rows:
        raise DockerBackendError("MCP_CAPTURE_JSON_FAILED", label)
    return rows


def evaluate_mcp_protocol_payload(
    payload: dict[str, Any],
    config: McpProtocolConfig,
) -> dict[str, Any]:
    pre_call_capture = _decode_capture(payload.get("pre_call_capture_b64"), "pre_call")
    post_call_capture = _decode_capture(payload.get("post_call_capture_b64"), "post_call")
    pre_rows = _json_lines(pre_call_capture, "pre_call")
    post_rows = _json_lines(post_call_capture, "post_call")
    if len(pre_rows) != 2 or len(post_rows) != 1:
        raise DockerBackendError("MCP_CAPTURE_SEQUENCE_INVALID", "protocol_evaluation")

    marker = create_marker(
        config.marker["profile"],
        seed=config.marker["seed"],
        source_kind=config.marker["source_kind"],
        source_ref=config.marker["source_ref"],
    )
    try:
        pre_witnesses = find_marker_witnesses(
            [pre_call_capture],
            [marker],
            sink_kind="mcp_pre_call_surface",
            sink_ref=f"tools/list:{MCP_TOOL_NAME}",
        )
        post_witnesses = find_marker_witnesses(
            [post_call_capture],
            [marker],
            sink_kind="mcp_tool_output",
            sink_ref=f"tools/call:{MCP_TOOL_NAME}",
        )
    except MarkerEvidenceError as exc:
        raise DockerBackendError("MCP_MARKER_EVALUATION_FAILED", "marker_evaluation") from exc

    plan = build_trigger_plan(
        target_id="controlled-government-mcp",
        target_kind="mcp",
        static_findings=[{
            "id": "finding-controlled-mcp-official-document",
            "rule_id": "AEGIS_MCP_SENSITIVE_RESOURCE_URI",
            "category": "mcp sensitive official document resource",
            "title": "政企公文可能通过 MCP 工具输出",
        }],
        max_attempts=1,
    )
    correlation = correlate_dynamic_evidence(
        plan,
        execution_status="completed",
        observed_event_types=(
            "mcp_initialize",
            "mcp_tools_list",
            "mcp_tools_call",
            "file_read",
        ),
        marker_witnesses=[witness.to_dict() for witness in post_witnesses],
    )

    transcript = payload.get("transcript")
    if not isinstance(transcript, list):
        transcript = []
    client_methods = tuple(
        str(entry.get("method"))
        for entry in transcript
        if isinstance(entry, dict) and entry.get("direction") == "client_to_server"
    )
    initialize_result = pre_rows[0].get("result") or {}
    tools_result = pre_rows[1].get("result") or {}
    tool_call_result = post_rows[0].get("result") or {}
    listed_tools = tools_result.get("tools") or []
    listed_schema = listed_tools[0].get("inputSchema") if len(listed_tools) == 1 else None
    marker_identity = payload.get("marker_identity") or {}
    plan_actions = {step.action for step in plan.steps}
    protocol_gates = {
        "fixture_identity": payload.get("fixture_id") == MCP_FIXTURE_RUNTIME_ID,
        "protocol_version_exact": payload.get("protocol_version") == MCP_PROTOCOL_VERSION,
        "stdio_transport_exact": payload.get("transport")
        == "stdio_newline_delimited_jsonrpc",
        "server_subprocess_started": payload.get("server_subprocess_started") is True,
        "server_exit_zero": payload.get("server_exit_code") == 0,
        "server_stderr_empty": payload.get("server_stderr_bytes") == 0,
        "initialize_first_and_sequence_exact": client_methods == EXPECTED_CLIENT_METHODS,
        "initialize_success": payload.get("initialize_success") is True,
        "initialize_response_id_exact": pre_rows[0].get("id") == 1,
        "tools_capability_declared": isinstance(
            (initialize_result.get("capabilities") or {}).get("tools"), dict
        ),
        "initialized_notification_sent": payload.get("initialized_notification_sent") is True,
        "tools_list_success": payload.get("tools_list_success") is True,
        "tools_list_response_id_exact": pre_rows[1].get("id") == 2,
        "listed_tool_exact": payload.get("listed_tool_names") == [MCP_TOOL_NAME],
        "input_schema_exact": listed_schema == EXPECTED_INPUT_SCHEMA,
        "schema_valid_call_once": payload.get("schema_valid_calls") == 1,
        "tool_call_success": (
            payload.get("tool_call_success") is True
            and post_rows[0].get("id") == 3
            and tool_call_result.get("isError") is False
        ),
        "protocol_errors_zero": payload.get("protocol_errors") == 0,
        "marker_identity_exact": (
            marker_identity.get("marker_id") == marker.marker_id
            and marker_identity.get("profile") == marker.profile
            and marker_identity.get("source_kind") == marker.source_kind
            and marker_identity.get("source_ref") == marker.source_ref
            and marker_identity.get("token_sha256") == marker.token_sha256
            and marker_identity.get("source_sha256") == marker.token_sha256
        ),
        "pre_call_marker_absent": len(pre_witnesses) == 0,
        "post_call_single_marker": len(post_witnesses) == 1,
        "post_call_transform_base64": (
            len(post_witnesses) == 1 and post_witnesses[0].transform == "base64"
        ),
        "static_plan_has_mcp_actions": {
            "enumerate_mcp_tools",
            "invoke_schema_valid_tools",
        } <= plan_actions,
        "static_dynamic_correlation_confirmed": correlation.status == "confirmed",
    }
    runtime_gates = validate_runtime_probe(payload)
    kernel_telemetry = payload.get("kernel_telemetry")
    if not isinstance(kernel_telemetry, dict):
        kernel_telemetry = {}
    event_names = {
        str(value) for value in kernel_telemetry.get("inotify_event_names") or []
    }
    pid_digest = kernel_telemetry.get("server_pid_sha256")
    cmdline_digest = kernel_telemetry.get("cmdline_sha256")
    def digest_is_safe(value: Any) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
        )
    telemetry_gates = {
        "telemetry_identity": kernel_telemetry.get("telemetry_id")
        == "aegis-linux-kernel-telemetry-v1",
        "observer_role_independent": kernel_telemetry.get("observer_role")
        == "mcp_client_parent_process",
        "observer_started_before_call": kernel_telemetry.get("started_before_tool_call")
        is True,
        "inotify_supported": kernel_telemetry.get("inotify_supported") is True,
        "observed_source_exact": kernel_telemetry.get("observed_source_ref")
        == config.marker["source_ref"],
        "inotify_open_observed": "OPEN" in event_names,
        "inotify_access_observed": "ACCESS" in event_names,
        "inotify_close_observed": "CLOSE_NOWRITE" in event_names,
        "proc_fd_source_observed": kernel_telemetry.get("proc_fd_source_observed") is True,
        "proc_fd_observation_positive": int(
            kernel_telemetry.get("proc_fd_observation_count") or 0
        ) > 0,
        "proc_parent_relation_confirmed": kernel_telemetry.get(
            "parent_relation_confirmed"
        ) is True,
        "process_pid_hashed": digest_is_safe(pid_digest),
        "process_cmdline_hashed": digest_is_safe(cmdline_digest),
        "process_identity_bounded": (
            isinstance(kernel_telemetry.get("executable_basename"), str)
            and str(kernel_telemetry.get("executable_basename")).startswith("python")
            and 1 <= int(kernel_telemetry.get("cmdline_arg_count") or 0) <= 8
        ),
        "raw_process_values_not_retained": (
            kernel_telemetry.get("raw_pid_retained") is False
            and kernel_telemetry.get("raw_cmdline_retained") is False
        ),
        "telemetry_errors_zero": kernel_telemetry.get("errors") == [],
    }
    public_runtime = {
        "probe_id": payload.get("probe_id"),
        "uid": payload.get("uid"),
        "gid": payload.get("gid"),
        "cap_eff": payload.get("cap_eff"),
        "no_new_privs": payload.get("no_new_privs"),
        "seccomp": payload.get("seccomp"),
        "rootfs_write_succeeded": (payload.get("rootfs_write") or {}).get("succeeded"),
        "input_write_succeeded": (payload.get("input_write") or {}).get("succeeded"),
        "workspace_write_succeeded": (payload.get("workspace_write") or {}).get("succeeded"),
        "temp_write_succeeded": (payload.get("temp_write") or {}).get("succeeded"),
        "network_interfaces": payload.get("network_interfaces"),
        "cwd": payload.get("cwd"),
    }
    return {
        "protocol_gates": protocol_gates,
        "runtime_gates": runtime_gates,
        "telemetry_gates": telemetry_gates,
        "protocol_steps": {
            "expected": list(EXPECTED_CLIENT_METHODS),
            "observed": list(client_methods),
            "passed": sum(
                int(actual == expected)
                for actual, expected in zip(client_methods, EXPECTED_CLIENT_METHODS)
            ) if len(client_methods) == len(EXPECTED_CLIENT_METHODS) else 0,
            "total": len(EXPECTED_CLIENT_METHODS),
        },
        "transcript": transcript,
        "capture_evidence": {
            "pre_call_bytes": len(pre_call_capture),
            "pre_call_sha256": sha256_bytes(pre_call_capture),
            "post_call_bytes": len(post_call_capture),
            "post_call_sha256": sha256_bytes(post_call_capture),
            "raw_capture_retained": False,
        },
        "marker_public_identity": marker.public_identity(),
        "pre_call_marker_witnesses": [witness.to_dict() for witness in pre_witnesses],
        "post_call_marker_witnesses": [witness.to_dict() for witness in post_witnesses],
        "trigger_plan": plan.to_dict(),
        "correlation": correlation.to_dict(),
        "runtime_probe": public_runtime,
        "kernel_telemetry": kernel_telemetry,
        "marker_token": marker.token,
    }


def run_mcp_protocol_probe(config_path: Path) -> dict[str, Any]:
    started = time.perf_counter()
    config = load_mcp_protocol_config(config_path)
    docker_cli = discover_docker_cli()
    container_name = f"aegis-dyn-{secrets.token_hex(8)}"
    container_id = ""
    error: dict[str, str] | None = None
    engine: dict[str, Any] = {}
    image: dict[str, Any] = {}
    image_gates: dict[str, bool] = {}
    inspect_gates: dict[str, bool] = {}
    runtime_gates: dict[str, bool] = {}
    protocol_gates: dict[str, bool] = {}
    telemetry_gates: dict[str, bool] = {}
    evaluated: dict[str, Any] = {}
    raw_marker_leaks = 0
    start_result: DockerCommandResult | None = None
    command_plan = build_create_command(docker_cli, config.docker, container_name)
    cleanup = {"attempted": False, "removed": False, "residual": False}
    try:
        engine = probe_docker_engine(docker_cli)
        image, image_gates = inspect_image_identity(docker_cli, config.docker)
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
            config.docker,
            container_name=container_name,
        )
        if not all(inspect_gates.values()):
            raise DockerBackendError("CONTAINER_INSPECT_GATE_FAILED", "container_inspect")
        start_result = run_docker_cli(
            [*_docker_prefix(docker_cli), "container", "start", "--attach", container_id],
            timeout_seconds=config.docker.fixture_timeout_seconds,
        )
        runtime_payload = _parse_json_object(
            _require_success(start_result, "container_start"),
            "MCP_RUNTIME_PARSE_FAILED",
            "container_start",
        )
        evaluated = evaluate_mcp_protocol_payload(runtime_payload, config)
        runtime_gates = evaluated["runtime_gates"]
        protocol_gates = evaluated["protocol_gates"]
        telemetry_gates = evaluated["telemetry_gates"]
        marker_token = str(evaluated.pop("marker_token"))
        raw_marker_leaks = int(marker_token in start_result.stdout)
        protocol_gates["raw_marker_absent_from_container_stdout"] = raw_marker_leaks == 0
        public_check = json.dumps(evaluated, ensure_ascii=False, sort_keys=True)
        if marker_token in public_check:
            raw_marker_leaks += 1
            protocol_gates["raw_marker_absent_from_public_evidence"] = False
        else:
            protocol_gates["raw_marker_absent_from_public_evidence"] = True
        if not all(runtime_gates.values()):
            raise DockerBackendError("MCP_RUNTIME_SECURITY_GATE_FAILED", "container_start")
        if not all(protocol_gates.values()):
            raise DockerBackendError("MCP_PROTOCOL_GATE_FAILED", "protocol_evaluation")
        if not all(telemetry_gates.values()):
            raise DockerBackendError("MCP_TELEMETRY_GATE_FAILED", "telemetry_evaluation")
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

    all_gates = {
        **image_gates,
        **inspect_gates,
        **runtime_gates,
        **protocol_gates,
        **telemetry_gates,
    }
    success = (
        error is None
        and bool(all_gates)
        and all(all_gates.values())
        and cleanup.get("removed") is True
        and cleanup.get("residual") is False
    )
    steps = evaluated.get("protocol_steps") or {}
    post_witnesses = evaluated.get("post_call_marker_witnesses") or []
    pre_witnesses = evaluated.get("pre_call_marker_witnesses") or []
    correlation = evaluated.get("correlation") or {}
    kernel_telemetry = evaluated.get("kernel_telemetry") or {}
    metrics = {
        "schema_version": MCP_BACKEND_SCHEMA_VERSION,
        "backend_id": MCP_BACKEND_ID,
        "engine_ready": bool(engine.get("engine_version")),
        "image_gates_total": len(image_gates),
        "image_gates_passed": sum(image_gates.values()),
        "inspect_gates_total": len(inspect_gates),
        "inspect_gates_passed": sum(inspect_gates.values()),
        "runtime_gates_total": len(runtime_gates),
        "runtime_gates_passed": sum(runtime_gates.values()),
        "protocol_gates_total": len(protocol_gates),
        "protocol_gates_passed": sum(protocol_gates.values()),
        "telemetry_gates_total": len(telemetry_gates),
        "telemetry_gates_passed": sum(telemetry_gates.values()),
        "all_gates_total": len(all_gates),
        "all_gates_passed": sum(all_gates.values()),
        "protocol_steps_total": int(steps.get("total") or 0),
        "protocol_steps_passed": int(steps.get("passed") or 0),
        "mcp_initialize_success": int(protocol_gates.get("initialize_success") is True),
        "mcp_tools_list_success": int(protocol_gates.get("tools_list_success") is True),
        "mcp_schema_valid_calls": int(protocol_gates.get("schema_valid_call_once") is True),
        "pre_call_marker_witnesses": len(pre_witnesses),
        "post_call_marker_witnesses": len(post_witnesses),
        "source_to_sink_witness_rate": 1.0 if len(post_witnesses) == 1 else 0.0,
        "correlation_confirmed": int(correlation.get("status") == "confirmed"),
        "inotify_open_observed": int(
            telemetry_gates.get("inotify_open_observed") is True
        ),
        "inotify_access_observed": int(
            telemetry_gates.get("inotify_access_observed") is True
        ),
        "inotify_close_observed": int(
            telemetry_gates.get("inotify_close_observed") is True
        ),
        "proc_parent_relation_confirmed": int(
            telemetry_gates.get("proc_parent_relation_confirmed") is True
        ),
        "proc_fd_source_observed": int(
            telemetry_gates.get("proc_fd_source_observed") is True
        ),
        "independent_file_read_confirmed": int(
            all(
                telemetry_gates.get(key) is True
                for key in (
                    "inotify_open_observed",
                    "inotify_access_observed",
                    "inotify_close_observed",
                    "proc_fd_source_observed",
                    "proc_parent_relation_confirmed",
                )
            )
        ),
        "strace_available": int(kernel_telemetry.get("strace_available") is True),
        "telemetry_errors": len(kernel_telemetry.get("errors") or []),
        "raw_pid_leaks": int(kernel_telemetry.get("raw_pid_retained") is not False),
        "raw_cmdline_leaks": int(
            kernel_telemetry.get("raw_cmdline_retained") is not False
        ),
        "protocol_errors": 0 if protocol_gates.get("protocol_errors_zero") is True else 1,
        "policy_violations": int(bool(error) or any(not value for value in all_gates.values())),
        "timeouts": int(bool(error and error.get("code") == "DOCKER_COMMAND_TIMEOUT")),
        "raw_marker_leaks": raw_marker_leaks,
        "container_residuals": int(cleanup.get("residual") is True),
        "third_party_samples_read": 0,
        "third_party_samples_executed": 0,
        "internet_connections_allowed": 0,
        "image_pulls_allowed": 0,
        "gpu_used": False,
        "decision_changes": 0,
        "duration_ms": round((time.perf_counter() - started) * 1000),
    }
    return {
        "success": success,
        "error": error,
        "config": {
            "schema_version": MCP_BACKEND_SCHEMA_VERSION,
            "backend_id": MCP_BACKEND_ID,
            "config_sha256": config.config_sha256,
            "fixture_id": MCP_FIXTURE_ID,
            "fixture_sha256": config.docker.fixture_sha256,
            "image_reference": config.docker.image_reference,
            "image_id": config.docker.image_id,
            "pull_policy": "never",
        },
        "engine": engine,
        "image": image,
        "create_command": redact_docker_command(command_plan),
        "image_gates": image_gates,
        "inspect_gates": inspect_gates,
        "runtime_gates": runtime_gates,
        "protocol_gates": protocol_gates,
        "telemetry_gates": telemetry_gates,
        "runtime_probe": evaluated.get("runtime_probe") or {},
        "protocol": {
            "version": MCP_PROTOCOL_VERSION,
            "transport": "stdio_newline_delimited_jsonrpc",
            "steps": evaluated.get("protocol_steps") or {},
            "transcript": evaluated.get("transcript") or [],
            "capture_evidence": evaluated.get("capture_evidence") or {},
        },
        "marker_public_identity": evaluated.get("marker_public_identity") or {},
        "pre_call_marker_witnesses": pre_witnesses,
        "post_call_marker_witnesses": post_witnesses,
        "trigger_plan": evaluated.get("trigger_plan") or {},
        "correlation": correlation,
        "kernel_telemetry": kernel_telemetry,
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
            "Controlled self-built MCP stdio fixture with Linux inotify/procfs telemetry only; "
            "not a claim that arbitrary MCP servers or container escapes are safe."
        ),
        "policy_effect": "none",
        "static_decision_changed": False,
    }
