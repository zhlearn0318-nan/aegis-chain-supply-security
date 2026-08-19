from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


class DynamicPolicyViolation(PermissionError):
    def __init__(self, code: str, operation: str) -> None:
        super().__init__(f"{code}: {operation}")
        self.code = code
        self.operation = operation


def _normalized_path(path: Path) -> str:
    return os.path.normcase(str(path.resolve(strict=False)))


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def canonical_process_argv(
    executable: str | os.PathLike[str],
    argv: Iterable[Any],
    allowed_python: Path,
) -> list[str]:
    executable_path = Path(os.fsdecode(executable)).resolve(strict=False)
    if _normalized_path(executable_path) != _normalized_path(allowed_python):
        raise DynamicPolicyViolation("PROCESS_EXECUTABLE_DENIED", "process_spawn")

    normalized = [os.fsdecode(item) for item in argv]
    if not normalized:
        raise DynamicPolicyViolation("PROCESS_ARGV_EMPTY", "process_spawn")
    first_path = Path(normalized[0]).resolve(strict=False)
    if _normalized_path(first_path) != _normalized_path(allowed_python):
        raise DynamicPolicyViolation("PROCESS_ARGV0_DENIED", "process_spawn")
    return ["<PYTHON>", *normalized[1:]]


def canonical_argv_sha256(argv: Iterable[str]) -> str:
    payload = json.dumps(list(argv), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def command_line_sha256(command_line: str) -> str:
    return hashlib.sha256(command_line.encode("utf-8")).hexdigest()


def open_has_write_intent(mode: Any, flags: Any) -> bool:
    if isinstance(mode, str) and any(character in mode for character in "wax+"):
        return True
    if not isinstance(flags, int):
        return False
    write_flags = (
        getattr(os, "O_WRONLY", 0)
        | getattr(os, "O_RDWR", 0)
        | getattr(os, "O_CREAT", 0)
        | getattr(os, "O_TRUNC", 0)
        | getattr(os, "O_APPEND", 0)
    )
    return bool(flags & write_flags)


@dataclass(frozen=True)
class DynamicSafetyPolicy:
    workspace: Path
    fixture_root: Path
    allowed_python: Path
    allowed_loopback_port: int | None
    allowed_process_argv_sha256: frozenset[str]

    def validate_fixture(self, fixture: Path) -> Path:
        resolved = fixture.resolve(strict=True)
        if fixture.is_symlink() or not is_within(resolved, self.fixture_root):
            raise DynamicPolicyViolation("FIXTURE_PATH_DENIED", "fixture_load")
        return resolved

    def validate_write_path(self, path: str | os.PathLike[str]) -> Path:
        candidate = Path(os.fsdecode(path))
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        resolved = candidate.resolve(strict=False)
        if not is_within(resolved, self.workspace):
            raise DynamicPolicyViolation("WRITE_OUTSIDE_WORKSPACE", "file_write")
        return resolved

    def validate_chdir_path(self, path: str | os.PathLike[str]) -> Path:
        candidate = Path(os.fsdecode(path))
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        resolved = candidate.resolve(strict=False)
        if not is_within(resolved, self.workspace):
            raise DynamicPolicyViolation("CHDIR_OUTSIDE_WORKSPACE", "directory_change")
        return resolved

    def deny_link_creation(self) -> None:
        raise DynamicPolicyViolation("LINK_CREATION_DENIED", "file_link")

    def relative_workspace_path(self, path: str | os.PathLike[str]) -> str | None:
        candidate = Path(os.fsdecode(path))
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        resolved = candidate.resolve(strict=False)
        if not is_within(resolved, self.workspace):
            return None
        return resolved.relative_to(self.workspace.resolve(strict=False)).as_posix()

    def validate_network_address(self, address: Any) -> tuple[str, int]:
        if not isinstance(address, tuple) or len(address) < 2:
            raise DynamicPolicyViolation("NETWORK_ADDRESS_DENIED", "network_connect")
        host = str(address[0])
        try:
            parsed = ipaddress.ip_address(host)
        except ValueError as exc:
            raise DynamicPolicyViolation("NETWORK_HOSTNAME_DENIED", "network_connect") from exc
        if not parsed.is_loopback:
            raise DynamicPolicyViolation("NETWORK_NON_LOOPBACK_DENIED", "network_connect")
        try:
            port = int(address[1])
        except (TypeError, ValueError) as exc:
            raise DynamicPolicyViolation("NETWORK_PORT_INVALID", "network_connect") from exc
        if self.allowed_loopback_port is None or port != self.allowed_loopback_port:
            raise DynamicPolicyViolation("NETWORK_PORT_DENIED", "network_connect")
        return str(parsed), port

    def validate_process(self, executable: Any, argv: Any) -> tuple[list[str], str]:
        if executable is None and isinstance(argv, str):
            digest = command_line_sha256(argv)
            if digest not in self.allowed_process_argv_sha256:
                raise DynamicPolicyViolation("PROCESS_COMMAND_LINE_DENIED", "process_spawn")
            return ["<EXACT_WINDOWS_COMMAND_LINE>"], digest
        if not isinstance(argv, (list, tuple)):
            raise DynamicPolicyViolation("PROCESS_STRING_COMMAND_DENIED", "process_spawn")
        if executable is None and argv:
            executable = argv[0]
        if not isinstance(executable, (str, bytes, os.PathLike)):
            raise DynamicPolicyViolation("PROCESS_EXECUTABLE_INVALID", "process_spawn")
        canonical = canonical_process_argv(executable, argv, self.allowed_python)
        digest = canonical_argv_sha256(canonical)
        if digest not in self.allowed_process_argv_sha256:
            raise DynamicPolicyViolation("PROCESS_ARGV_DENIED", "process_spawn")
        return canonical, digest
