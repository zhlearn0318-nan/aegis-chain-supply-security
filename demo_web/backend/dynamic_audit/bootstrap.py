from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
import sys
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.dynamic_audit.policy import (  # noqa: E402
    DynamicPolicyViolation,
    DynamicSafetyPolicy,
    open_has_write_intent,
)


EVENT_PREFIX = "AEGIS_DYNAMIC_EVENT\t"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _emit(event_type: str, **details: Any) -> None:
    record = {"event_type": event_type, "details": details}
    sys.__stderr__.write(EVENT_PREFIX + json.dumps(record, ensure_ascii=False) + "\n")
    sys.__stderr__.flush()


class _TracedStdin:
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def read(self, *args: Any, **kwargs: Any) -> str:
        value = self._stream.read(*args, **kwargs)
        _emit("stdin_read", length=len(value), sha256=_sha256_text(value))
        return value

    def readline(self, *args: Any, **kwargs: Any) -> str:
        value = self._stream.readline(*args, **kwargs)
        _emit("stdin_read", length=len(value), sha256=_sha256_text(value))
        return value

    def __iter__(self) -> "_TracedStdin":
        return self

    def __next__(self) -> str:
        value = self._stream.__next__()
        _emit("stdin_read", length=len(value), sha256=_sha256_text(value))
        return value

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def _fixture_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aegis trusted fixture audit bootstrap")
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--fixture-sha256", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--allowed-loopback-port", type=int, default=0)
    parser.add_argument("--allowed-process-argv-sha256", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    workspace = args.workspace.resolve(strict=True)
    fixture_root = args.fixture_root.resolve(strict=True)
    policy = DynamicSafetyPolicy(
        workspace=workspace,
        fixture_root=fixture_root,
        allowed_python=Path(sys.executable).resolve(strict=True),
        allowed_loopback_port=args.allowed_loopback_port or None,
        allowed_process_argv_sha256=frozenset(args.allowed_process_argv_sha256),
    )
    fixture = policy.validate_fixture(args.fixture)
    if _fixture_sha256(fixture) != args.fixture_sha256.lower():
        _emit("policy_violation", code="FIXTURE_HASH_MISMATCH", operation="fixture_load")
        return 3

    original_getenv = os.getenv

    def traced_getenv(key: str, default: str | None = None) -> str | None:
        value = original_getenv(key, default)
        if str(key).startswith("AEGIS_"):
            rendered = "" if value is None else str(value)
            _emit(
                "environment_read",
                name=str(key),
                present=value is not None,
                length=len(rendered),
                sha256=_sha256_text(rendered),
            )
        return value

    os.getenv = traced_getenv
    sys.stdin = _TracedStdin(sys.stdin)
    active = True

    def audit_hook(event: str, audit_args: tuple[Any, ...]) -> None:
        nonlocal active
        if not active:
            return
        try:
            if event == "open" and audit_args:
                path = audit_args[0]
                if not isinstance(path, (str, bytes, os.PathLike)):
                    return
                mode = audit_args[1] if len(audit_args) > 1 else None
                flags = audit_args[2] if len(audit_args) > 2 else None
                write_intent = open_has_write_intent(mode, flags)
                if write_intent:
                    policy.validate_write_path(path)
                relative = policy.relative_workspace_path(path)
                if relative is not None:
                    _emit(
                        "file_write" if write_intent else "file_read",
                        path=relative,
                        mode=str(mode or ""),
                    )
            elif event in {"os.remove", "os.rmdir", "os.mkdir"} and audit_args:
                resolved = policy.validate_write_path(audit_args[0])
                _emit(
                    "file_mutation",
                    operation=event,
                    path=resolved.relative_to(workspace).as_posix(),
                )
            elif event in {"os.rename", "os.replace"} and len(audit_args) >= 2:
                source = policy.validate_write_path(audit_args[0])
                target = policy.validate_write_path(audit_args[1])
                _emit(
                    "file_mutation",
                    operation=event,
                    source=source.relative_to(workspace).as_posix(),
                    target=target.relative_to(workspace).as_posix(),
                )
            elif event == "os.chdir" and audit_args:
                resolved = policy.validate_chdir_path(audit_args[0])
                _emit(
                    "directory_change",
                    path=resolved.relative_to(workspace).as_posix() or ".",
                )
            elif event in {"os.symlink", "os.link"}:
                policy.deny_link_creation()
            elif event == "subprocess.Popen" and len(audit_args) >= 2:
                canonical, digest = policy.validate_process(audit_args[0], audit_args[1])
                argument_form = (
                    "windows_command_line"
                    if canonical == ["<EXACT_WINDOWS_COMMAND_LINE>"]
                    else "argv"
                )
                _emit(
                    "process_spawn",
                    executable="python",
                    argument_form=argument_form,
                    argv_count=None if argument_form == "windows_command_line" else len(canonical),
                    argv_sha256=digest,
                    shell=False,
                )
            elif event == "os.system":
                raise DynamicPolicyViolation("OS_SYSTEM_DENIED", "process_spawn")
            elif event == "socket.getaddrinfo" and audit_args:
                port = audit_args[1] if len(audit_args) > 1 else 0
                policy.validate_network_address((audit_args[0], port))
            elif event == "socket.connect" and len(audit_args) >= 2:
                host, port = policy.validate_network_address(audit_args[1])
                _emit("network_connect", host=host, port=port, transport="tcp")
        except DynamicPolicyViolation as exc:
            _emit("policy_violation", code=exc.code, operation=exc.operation)
            raise

    sys.addaudithook(audit_hook)
    try:
        runpy.run_path(str(fixture), run_name="__main__")
    except DynamicPolicyViolation:
        return 3
    except BaseException as exc:  # trusted fixture failure is recorded without raw message
        _emit("fixture_exception", exception_type=type(exc).__name__)
        return 2
    finally:
        active = False
        os.getenv = original_getenv
    _emit("fixture_completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
