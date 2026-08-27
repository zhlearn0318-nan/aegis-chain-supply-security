from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote_to_bytes


MAX_AUDIT_EVENTS = 5_000
MAX_AUDIT_LINE = 16 * 1024
MAX_CAPTURE_BYTES = 64 * 1024
MAX_SINK_BODY = 32 * 1024
DECOYS = {
    "official_document": "AEGIS-DYN-OFFICIAL-DOCUMENT-8B4D2F1A",
    "database_credential": "AEGIS_DYN_DB_PASSWORD_7F91C2E4",
    "ops_token": "AEGIS_DYN_OPS_TOKEN_6A3E5D8C",
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_entry(skill_root: Path, raw_entry: str) -> tuple[Path, str]:
    if "\\" in raw_entry or ":" in raw_entry or raw_entry.startswith("/"):
        raise ValueError("ENTRYPOINT_PATH_DENIED")
    parts = PurePosixPath(raw_entry).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("ENTRYPOINT_PATH_DENIED")
    relative = PurePosixPath(*parts).as_posix()
    if not relative.lower().endswith(".py"):
        raise ValueError("ENTRYPOINT_TYPE_DENIED")
    root = skill_root.resolve(strict=True)
    unresolved = root / Path(*parts)
    if unresolved.is_symlink():
        raise ValueError("ENTRYPOINT_LINK_DENIED")
    candidate = unresolved.resolve(strict=True)
    candidate.relative_to(root)
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("ENTRYPOINT_FILE_DENIED")
    return candidate, relative


class _SinkholeHandler(BaseHTTPRequestHandler):
    server_version = "AegisSinkhole/1"
    sys_version = ""

    def _handle(self) -> None:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = min(max(int(length_text), 0), MAX_SINK_BODY)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        path_bytes = unquote_to_bytes(self.path[:4096])
        combined = path_bytes + b"\n" + body
        witnesses: list[str] = []
        for marker_id, marker in DECOYS.items():
            raw = marker.encode("utf-8")
            variants = {raw, base64.b64encode(raw), raw.hex().encode("ascii")}
            if any(variant in combined for variant in variants):
                witnesses.append(marker_id)
        self.server.events.append(  # type: ignore[attr-defined]
            {
                "type": "marker.sink" if witnesses else "sinkhole.request",
                "marker_ids": witnesses,
                "method": self.command,
                "path_sha256": _sha256(path_bytes),
                "body_sha256": _sha256(body),
                "body_bytes": len(body),
            }
        )
        self.send_response(204)
        self.end_headers()

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle

    def log_message(self, _format: str, *args: Any) -> None:
        return


class _SinkholeServer(ThreadingHTTPServer):
    events: list[dict[str, Any]]


def _start_sinkhole() -> tuple[_SinkholeServer, threading.Thread]:
    server = _SinkholeServer(("127.0.0.1", 0), _SinkholeHandler)
    server.events = []
    thread = threading.Thread(target=server.serve_forever, name="aegis-sinkhole", daemon=True)
    thread.start()
    return server, thread


def _prepare_decoys(workspace: Path) -> dict[str, str]:
    decoy_root = workspace / "decoys"
    decoy_root.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for marker_id, value in DECOYS.items():
        path = decoy_root / f"{marker_id}.txt"
        path.write_text(value, encoding="utf-8")
        paths[marker_id] = str(path)
    return paths


def _read_audit_pipe(fd: int, events: list[dict[str, Any]], state: dict[str, bool]) -> None:
    try:
        with os.fdopen(fd, "rb", buffering=0) as handle:
            for raw_line in handle:
                if len(raw_line) > MAX_AUDIT_LINE or len(events) >= MAX_AUDIT_EVENTS:
                    state["complete"] = False
                    break
                try:
                    payload = json.loads(raw_line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    state["complete"] = False
                    continue
                if isinstance(payload, dict):
                    events.append(payload)
    except OSError:
        state["complete"] = False


def run_entrypoint(skill_root: Path, entry: str, timeout_seconds: float) -> dict[str, Any]:
    if os.name != "posix":
        raise RuntimeError("LINUX_CONTAINER_REQUIRED")
    target, relative = _validate_entry(skill_root, entry)
    workspace = Path("/workspace").resolve(strict=True)
    decoy_paths = _prepare_decoys(workspace)
    sinkhole, sinkhole_thread = _start_sinkhole()
    read_fd, write_fd = os.pipe()
    events: list[dict[str, Any]] = []
    telemetry_state = {"complete": True}
    reader = threading.Thread(
        target=_read_audit_pipe,
        args=(read_fd, events, telemetry_state),
        name="aegis-audit-reader",
        daemon=True,
    )
    reader.start()
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": "/aegis_tool",
        "AEGIS_AUDIT_FD": str(write_fd),
        "AEGIS_SINKHOLE_URL": f"http://127.0.0.1:{sinkhole.server_port}",
        "AEGIS_DECOY_DIR": "/workspace/decoys",
    }
    started = time.perf_counter()
    process = subprocess.Popen(
        [sys.executable, "-s", "-B", str(target)],
        cwd=workspace,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=(write_fd,),
    )
    os.close(write_fd)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    reader.join(timeout=2)
    sinkhole.shutdown()
    sinkhole.server_close()
    sinkhole_thread.join(timeout=2)
    events.extend(sinkhole.events)
    if timed_out:
        events.append({"type": "runtime.timeout", "timeout_seconds": timeout_seconds})
    telemetry_ready = any(event.get("type") == "telemetry.ready" for event in events)
    status = "timeout" if timed_out else ("completed" if process.returncode == 0 else "crashed")
    return {
        "schema_version": "1.0",
        "collector": "aegis-python-skill-runner-v1",
        "entrypoint": relative,
        "execution_status": status,
        "exit_code": process.returncode,
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "telemetry_complete": bool(telemetry_state["complete"] and telemetry_ready),
        "events": events,
        "stdout": {"bytes": len(stdout), "sha256": _sha256(stdout[:MAX_CAPTURE_BYTES]), "truncated": len(stdout) > MAX_CAPTURE_BYTES},
        "stderr": {"bytes": len(stderr), "sha256": _sha256(stderr[:MAX_CAPTURE_BYTES]), "truncated": len(stderr) > MAX_CAPTURE_BYTES},
        "decoys": {marker_id: {"path": path, "value_retained": False} for marker_id, path in decoy_paths.items()},
        "internet_used": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skill-root", required=True)
    parser.add_argument("--entry", required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    args = parser.parse_args()
    timeout = min(max(args.timeout_seconds, 1.0), 120.0)
    try:
        result = run_entrypoint(Path(args.skill_root), args.entry, timeout)
    except Exception as exc:
        result = {
            "schema_version": "1.0",
            "collector": "aegis-python-skill-runner-v1",
            "execution_status": "runner_failed",
            "telemetry_complete": False,
            "error_code": type(exc).__name__,
            "events": [],
            "internet_used": False,
        }
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.write("\n")
    return 0 if result.get("execution_status") in {"completed", "crashed", "timeout"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
