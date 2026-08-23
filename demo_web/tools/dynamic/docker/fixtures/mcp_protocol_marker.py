from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, TextIO


PROTOCOL_VERSION = "2025-06-18"
FIXTURE_ID = "aegis-mcp-protocol-marker-v1"
SERVER_ID = "aegis-controlled-government-mcp-v1"
TOOL_NAME = "read_official_document"
MARKER_PROFILE = "official_document"
MARKER_SEED = "2026-08-23-mcp-protocol-marker-dev-v1"
MARKER_SOURCE_KIND = "decoy_file"
MARKER_SOURCE_REF = "decoys/official_document.txt"
MARKER_SOURCE_PATH = Path("/workspace") / MARKER_SOURCE_REF


def compact_json(payload: Any) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def marker_identity() -> tuple[str, str, str]:
    material = (
        f"{MARKER_SEED}\0{MARKER_PROFILE}\0{MARKER_SOURCE_KIND}\0{MARKER_SOURCE_REF}"
    ).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()
    token = f"AEGIS-CANARY:{MARKER_PROFILE.upper()}:{digest[:24]}"
    marker_id = f"marker-{MARKER_PROFILE}-{digest[:12]}"
    return marker_id, token, hashlib.sha256(token.encode("utf-8")).hexdigest()


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def tool_definition() -> dict[str, Any]:
    return {
        "name": TOOL_NAME,
        "title": "政企公文摘要读取器（受控测试）",
        "description": "读取受控环境中的模拟公文并返回编码后的摘要输入。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "const": "summarize"},
            },
            "required": ["action"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "encoding": {"type": "string", "const": "base64"},
                "payload": {"type": "string"},
                "sourceSha256": {"type": "string"},
            },
            "required": ["encoding", "payload", "sourceSha256"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    }


def handle_request(
    message: dict[str, Any],
    state: dict[str, bool],
) -> dict[str, Any] | None:
    if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return error_response(message.get("id"), -32600, "Invalid Request")
    method = message["method"]
    request_id = message.get("id")
    is_notification = "id" not in message

    if not state["initialize_seen"]:
        if method != "initialize" or is_notification:
            return None if is_notification else error_response(
                request_id, -32002, "Server not initialized"
            )
        params = message.get("params")
        if not isinstance(params, dict) or params.get("protocolVersion") != PROTOCOL_VERSION:
            return error_response(request_id, -32602, "Unsupported protocol version")
        if not isinstance(params.get("capabilities"), dict) or not isinstance(
            params.get("clientInfo"), dict
        ):
            return error_response(request_id, -32602, "Invalid initialize parameters")
        state["initialize_seen"] = True
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_ID, "version": "1.0.0"},
            },
        }

    if method == "notifications/initialized" and is_notification:
        state["initialized"] = True
        return None
    if not state["initialized"]:
        return None if is_notification else error_response(
            request_id, -32002, "Initialization notification required"
        )
    if method == "tools/list" and not is_notification:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": [tool_definition()]},
        }
    if method == "tools/call" and not is_notification:
        params = message.get("params")
        if not isinstance(params, dict) or params.get("name") != TOOL_NAME:
            return error_response(request_id, -32602, "Unknown tool")
        if params.get("arguments") != {"action": "summarize"}:
            return error_response(request_id, -32602, "Invalid tool arguments")
        with MARKER_SOURCE_PATH.open("rb") as source:
            time.sleep(0.2)
            payload = source.read()
            time.sleep(0.05)
        encoded = base64.b64encode(payload).decode("ascii")
        structured = {
            "encoding": "base64",
            "payload": encoded,
            "sourceSha256": hashlib.sha256(payload).hexdigest(),
        }
        state["tool_called"] = True
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": compact_json(structured)}],
                "structuredContent": structured,
                "isError": False,
            },
        }
    return None if is_notification else error_response(
        request_id, -32601, "Method not found"
    )


def run_server(stdin: TextIO, stdout: TextIO) -> int:
    _, token, _ = marker_identity()
    MARKER_SOURCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    MARKER_SOURCE_PATH.write_text(token, encoding="utf-8", newline="\n")
    state = {
        "initialize_seen": False,
        "initialized": False,
        "tool_called": False,
    }
    for raw_line in stdin:
        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError:
            stdout.write(compact_json(error_response(None, -32700, "Parse error")) + "\n")
            stdout.flush()
            continue
        if not isinstance(message, dict):
            response = error_response(None, -32600, "Invalid Request")
        else:
            response = handle_request(message, state)
        if response is not None:
            stdout.write(compact_json(response) + "\n")
            stdout.flush()
    return 0


def proc_status() -> dict[str, str]:
    values: dict[str, str] = {}
    status_path = Path("/proc/self/status")
    if not status_path.is_file():
        return values
    for line in status_path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"CapEff", "NoNewPrivs", "Seccomp"}:
            values[key] = value.strip()
    return values


def write_probe(path: Path, payload: str) -> dict[str, object]:
    try:
        path.write_text(payload, encoding="utf-8")
    except OSError as exc:
        return {"succeeded": False, "error_type": type(exc).__name__}
    return {
        "succeeded": True,
        "bytes": path.stat().st_size,
        "content_matched": path.read_text(encoding="utf-8") == payload,
    }


def security_probe() -> dict[str, Any]:
    status = proc_status()
    return {
        "schema_version": "1.0",
        "probe_id": "aegis-docker-security-probe-v1",
        "uid": os.getuid(),
        "gid": os.getgid(),
        "cap_eff": status.get("CapEff"),
        "no_new_privs": status.get("NoNewPrivs"),
        "seccomp": status.get("Seccomp"),
        "rootfs_write": write_probe(Path("/aegis-root-write-probe"), "root-deny"),
        "input_write": write_probe(Path("/aegis_fixture.py"), "input-deny"),
        "workspace_write": write_probe(Path("/workspace/probe-output.txt"), "workspace-ok"),
        "temp_write": write_probe(Path("/tmp/probe-temp.txt"), "temp-ok"),
        "network_interfaces": sorted(name for _, name in socket.if_nameindex()),
        "cwd": Path.cwd().as_posix(),
    }


class KernelTelemetryObserver:
    IN_ACCESS = 0x00000001
    IN_CLOSE_NOWRITE = 0x00000010
    IN_OPEN = 0x00000020
    WATCH_MASK = IN_ACCESS | IN_CLOSE_NOWRITE | IN_OPEN
    EVENT_HEADER = struct.Struct("iIII")

    def __init__(self, server_pid: int, target_path: Path) -> None:
        self.server_pid = server_pid
        self.target_path = target_path.resolve(strict=True)
        self.errors: list[str] = []
        self.fd_observation_count = 0
        self._stop = threading.Event()
        self._inotify_fd = -1
        self._watch_descriptor = -1
        self._process_evidence = self._read_process_evidence()
        self._start_inotify()
        self._thread = threading.Thread(target=self._watch_file_descriptors, daemon=True)
        self._thread.start()

    def _record_error(self, label: str, exc: BaseException) -> None:
        value = f"{label}:{type(exc).__name__}"
        if value not in self.errors:
            self.errors.append(value)

    def _read_process_evidence(self) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "server_pid_sha256": hashlib.sha256(
                str(self.server_pid).encode("ascii")
            ).hexdigest(),
            "parent_relation_confirmed": False,
            "cmdline_sha256": None,
            "cmdline_arg_count": 0,
            "executable_basename": None,
            "raw_pid_retained": False,
            "raw_cmdline_retained": False,
        }
        try:
            status = Path(f"/proc/{self.server_pid}/status").read_text(encoding="utf-8")
            parent_line = next(
                line for line in status.splitlines() if line.startswith("PPid:")
            )
            evidence["parent_relation_confirmed"] = int(parent_line.split()[1]) == os.getpid()
            cmdline = Path(f"/proc/{self.server_pid}/cmdline").read_bytes()
            args = [value for value in cmdline.split(b"\0") if value]
            evidence["cmdline_sha256"] = hashlib.sha256(cmdline).hexdigest()
            evidence["cmdline_arg_count"] = len(args)
            evidence["executable_basename"] = Path(
                os.readlink(f"/proc/{self.server_pid}/exe")
            ).name
        except (OSError, StopIteration, ValueError) as exc:
            self._record_error("proc_identity", exc)
        return evidence

    def _start_inotify(self) -> None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            init = libc.inotify_init1
            init.argtypes = [ctypes.c_int]
            init.restype = ctypes.c_int
            add_watch = libc.inotify_add_watch
            add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            add_watch.restype = ctypes.c_int
            flags = os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
            self._inotify_fd = init(flags)
            if self._inotify_fd < 0:
                raise OSError(ctypes.get_errno(), "inotify_init1 failed")
            self._watch_descriptor = add_watch(
                self._inotify_fd,
                os.fsencode(self.target_path.parent),
                self.WATCH_MASK,
            )
            if self._watch_descriptor < 0:
                raise OSError(ctypes.get_errno(), "inotify_add_watch failed")
        except (AttributeError, OSError) as exc:
            self._record_error("inotify", exc)
            if self._inotify_fd >= 0:
                os.close(self._inotify_fd)
                self._inotify_fd = -1

    def _watch_file_descriptors(self) -> None:
        fd_root = Path(f"/proc/{self.server_pid}/fd")
        target = os.path.normcase(str(self.target_path))
        while not self._stop.is_set():
            try:
                for entry in fd_root.iterdir():
                    try:
                        linked = os.readlink(entry)
                    except OSError:
                        continue
                    if os.path.normcase(linked.removesuffix(" (deleted)")) == target:
                        self.fd_observation_count += 1
                        break
            except OSError as exc:
                self._record_error("proc_fd", exc)
                return
            self._stop.wait(0.005)

    def _read_inotify_events(self) -> list[str]:
        names: set[str] = set()
        if self._inotify_fd < 0:
            return []
        while True:
            try:
                payload = os.read(self._inotify_fd, 4096)
            except BlockingIOError:
                break
            except OSError as exc:
                self._record_error("inotify_read", exc)
                break
            if not payload:
                break
            offset = 0
            while offset + self.EVENT_HEADER.size <= len(payload):
                _wd, mask, _cookie, name_length = self.EVENT_HEADER.unpack_from(payload, offset)
                offset += self.EVENT_HEADER.size
                raw_name = payload[offset:offset + name_length]
                offset += name_length
                event_name = os.fsdecode(raw_name.split(b"\0", 1)[0])
                if event_name != self.target_path.name:
                    continue
                if mask & self.IN_OPEN:
                    names.add("OPEN")
                if mask & self.IN_ACCESS:
                    names.add("ACCESS")
                if mask & self.IN_CLOSE_NOWRITE:
                    names.add("CLOSE_NOWRITE")
        return sorted(names)

    def finish(self) -> dict[str, Any]:
        time.sleep(0.03)
        self._stop.set()
        self._thread.join(timeout=1)
        event_names = self._read_inotify_events()
        if self._inotify_fd >= 0:
            os.close(self._inotify_fd)
            self._inotify_fd = -1
        return {
            "telemetry_id": "aegis-linux-kernel-telemetry-v1",
            "observer_role": "mcp_client_parent_process",
            "started_before_tool_call": True,
            "inotify_supported": self._watch_descriptor >= 0,
            "inotify_event_names": event_names,
            "inotify_event_count": len(event_names),
            "observed_source_ref": MARKER_SOURCE_REF,
            "proc_fd_source_observed": self.fd_observation_count > 0,
            "proc_fd_observation_count": self.fd_observation_count,
            "strace_available": bool(shutil.which("strace")),
            "errors": sorted(self.errors),
            **self._process_evidence,
        }


def transcript_entry(
    direction: str,
    kind: str,
    *,
    method: str | None = None,
    request_id: int | None = None,
    response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {"direction": direction, "kind": kind}
    if method is not None:
        entry["method"] = method
    if request_id is not None:
        entry["id"] = request_id
    if response is not None:
        encoded = compact_json(response).encode("utf-8")
        entry.update({
            "response_sha256": hashlib.sha256(encoded).hexdigest(),
            "response_bytes": len(encoded),
            "has_result": "result" in response,
            "error_code": (response.get("error") or {}).get("code"),
        })
    return entry


def run_harness(*, include_security: bool) -> dict[str, Any]:
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--server"]
    server = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    if server.stdin is None or server.stdout is None or server.stderr is None:
        raise RuntimeError("MCP stdio pipes unavailable")
    transcript: list[dict[str, Any]] = []

    def send(message: dict[str, Any], *, expect_response: bool) -> tuple[dict[str, Any] | None, str]:
        method = str(message["method"])
        kind = "notification" if "id" not in message else "request"
        transcript.append(transcript_entry(
            "client_to_server", kind, method=method, request_id=message.get("id")
        ))
        server.stdin.write(compact_json(message) + "\n")
        server.stdin.flush()
        if not expect_response:
            return None, ""
        raw = server.stdout.readline()
        if not raw:
            raise RuntimeError(f"MCP server closed before responding to {method}")
        response = json.loads(raw)
        if not isinstance(response, dict):
            raise RuntimeError("MCP response is not an object")
        transcript.append(transcript_entry(
            "server_to_client", "response", request_id=response.get("id"), response=response
        ))
        return response, raw.rstrip("\r\n")

    initialize, initialize_raw = send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "aegis-controlled-client", "version": "1.0.0"},
        },
    }, expect_response=True)
    send({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }, expect_response=False)
    listed, list_raw = send({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }, expect_response=True)
    observer = KernelTelemetryObserver(server.pid, MARKER_SOURCE_PATH)
    try:
        called, call_raw = send({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": TOOL_NAME, "arguments": {"action": "summarize"}},
        }, expect_response=True)
    finally:
        kernel_telemetry = observer.finish()
    server.stdin.close()
    exit_code = server.wait(timeout=3)
    stderr = server.stderr.read()
    marker_id, _, token_sha256 = marker_identity()
    tools = ((listed or {}).get("result") or {}).get("tools") or []
    tool_result = (called or {}).get("result") or {}
    source_sha256 = (tool_result.get("structuredContent") or {}).get("sourceSha256")
    result = {
        "schema_version": "1.0",
        "fixture_id": FIXTURE_ID,
        "protocol_version": PROTOCOL_VERSION,
        "transport": "stdio_newline_delimited_jsonrpc",
        "server_subprocess_started": True,
        "server_exit_code": exit_code,
        "server_stderr_bytes": len(stderr.encode("utf-8")),
        "server_stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "initialize_success": bool(
            initialize
            and initialize.get("id") == 1
            and ((initialize.get("result") or {}).get("protocolVersion") == PROTOCOL_VERSION)
        ),
        "initialized_notification_sent": True,
        "tools_list_success": bool(listed and listed.get("id") == 2 and len(tools) == 1),
        "listed_tool_names": [str(tool.get("name")) for tool in tools],
        "listed_tool_schemas": [tool.get("inputSchema") for tool in tools],
        "schema_valid_calls": int(bool(called and called.get("id") == 3 and not called.get("error"))),
        "tool_call_success": bool(called and tool_result.get("isError") is False),
        "protocol_errors": sum(
            1 for response in (initialize, listed, called) if response and "error" in response
        ),
        "marker_identity": {
            "marker_id": marker_id,
            "profile": MARKER_PROFILE,
            "source_kind": MARKER_SOURCE_KIND,
            "source_ref": MARKER_SOURCE_REF,
            "token_sha256": token_sha256,
            "source_sha256": source_sha256,
        },
        "transcript": transcript,
        "kernel_telemetry": kernel_telemetry,
        "pre_call_capture_b64": base64.b64encode(
            (initialize_raw + "\n" + list_raw).encode("utf-8")
        ).decode("ascii"),
        "post_call_capture_b64": base64.b64encode(call_raw.encode("utf-8")).decode("ascii"),
    }
    if include_security:
        result.update(security_probe())
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--server", action="store_true")
    group.add_argument("--harness-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.server:
        return run_server(sys.stdin, sys.stdout)
    print(compact_json(run_harness(include_security=not args.harness_only)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
