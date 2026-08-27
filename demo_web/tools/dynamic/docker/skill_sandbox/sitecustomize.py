"""Best-effort Python audit telemetry for the Aegis Skill sandbox.

This module is imported automatically by the isolated child interpreter through
PYTHONPATH. It is evidence collection, not the sandbox security boundary.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import PurePosixPath
from typing import Any


_FD_TEXT = os.environ.get("AEGIS_AUDIT_FD", "")
_MAX_TEXT = 400
_MAX_EVENTS = 5_000
_EVENT_COUNT = 0
_IN_HOOK = False


def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    text = "".join(character for character in str(value or "") if ord(character) >= 32)
    return " ".join(text.split())[:limit]


def _write(payload: dict[str, Any]) -> None:
    global _EVENT_COUNT
    if not _FD_TEXT.isdigit() or _EVENT_COUNT >= _MAX_EVENTS:
        return
    _EVENT_COUNT += 1
    payload["sequence"] = _EVENT_COUNT
    payload["monotonic_ns"] = time.monotonic_ns()
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        os.write(int(_FD_TEXT), encoded + b"\n")
    except (OSError, ValueError, TypeError):
        return


def _path(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    return text.replace("\\", "/")


def _command_name(value: Any) -> str:
    if isinstance(value, (list, tuple)) and value:
        value = value[0]
    return PurePosixPath(_path(value)).name


def _hook(event: str, args: tuple[Any, ...]) -> None:
    global _IN_HOOK
    if _IN_HOOK:
        return
    _IN_HOOK = True
    try:
        if event == "open" and args:
            path = _path(args[0])
            _write({"type": "file.open", "path": path, "mode": _text(args[1] if len(args) > 1 else "")})
            marker_root = "/workspace/decoys/"
            if path.casefold().startswith(marker_root):
                marker_id = PurePosixPath(path).stem
                _write({"type": "decoy.read", "marker_id": marker_id})
        elif event in {"os.remove", "os.unlink", "os.rmdir", "os.mkdir", "os.chmod"}:
            _write({"type": f"file.{event.split('.', 1)[1]}", "path": _path(args[0] if args else "")})
        elif event in {"os.rename", "os.replace"}:
            _write(
                {
                    "type": "file.rename",
                    "source": _path(args[0] if args else ""),
                    "target": _path(args[1] if len(args) > 1 else ""),
                }
            )
        elif event == "subprocess.Popen":
            executable = args[0] if args else ""
            argv = args[1] if len(args) > 1 else []
            _write(
                {
                    "type": "process.spawn",
                    "executable": _command_name(executable or argv),
                    "argv_count": len(argv) if isinstance(argv, (list, tuple)) else 1,
                }
            )
        elif event == "os.system":
            _write({"type": "os.system", "command": _command_name(args[0] if args else "")})
        elif event == "socket.connect" and len(args) > 1:
            address = args[1]
            host = address[0] if isinstance(address, tuple) and address else address
            port = address[1] if isinstance(address, tuple) and len(address) > 1 else None
            _write({"type": "socket.connect", "host": _text(host, 255), "port": port})
        elif event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex"}:
            _write({"type": "dns.resolve", "host": _text(args[0] if args else "", 255)})
        elif event == "ctypes.dlopen":
            _write({"type": "ctypes.dlopen", "target": _path(args[0] if args else "")})
    finally:
        _IN_HOOK = False


if _FD_TEXT.isdigit():
    import sys

    sys.addaudithook(_hook)
    _write({"type": "telemetry.ready", "collector": "python_audit_hook_v1"})
