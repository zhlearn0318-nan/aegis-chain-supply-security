from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Sequence


WINDOWS_COMPATIBILITY_ENV = (
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
)
SCANNER_FIXED_ENV = {
    "PYTHONUTF8": "1",
    "PYTHONIOENCODING": "utf-8",
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "LITELLM_LOCAL_MODEL_COST_MAP": "True",
}


def build_scanner_environment(
    cache_root: Path,
    extra_path: Path | Sequence[Path] | None = None,
) -> dict[str, str]:
    """Build the complete environment passed across the scanner trust boundary."""
    cache_root.mkdir(parents=True, exist_ok=True)
    temporary_root = cache_root / "tmp"
    temporary_root.mkdir(parents=True, exist_ok=True)
    profile_root = cache_root / "profile"
    roaming_root = profile_root / "AppData" / "Roaming"
    local_root = profile_root / "AppData" / "Local"
    roaming_root.mkdir(parents=True, exist_ok=True)
    local_root.mkdir(parents=True, exist_ok=True)

    env = {
        name: value
        for name in WINDOWS_COMPATIBILITY_ENV
        if (value := os.environ.get(name))
    }
    env.update(SCANNER_FIXED_ENV)

    system_path_entries: list[str]
    if os.name == "nt":
        system_root = env.get("SYSTEMROOT") or env.get("WINDIR") or "C:\\Windows"
        system_path_entries = [
            str(Path(system_root) / "System32"),
            system_root,
            str(Path(system_root) / "System32" / "Wbem"),
        ]
    else:
        system_path_entries = ["/usr/local/bin", "/usr/bin", "/bin"]

    path_entries: list[str] = []
    if extra_path:
        extra_paths = [extra_path] if isinstance(extra_path, Path) else list(extra_path)
        path_entries.extend(str(path.resolve(strict=False)) for path in extra_paths)
    path_entries.extend(system_path_entries)
    env["PATH"] = os.pathsep.join(dict.fromkeys(path_entries))
    env["TEMP"] = str(temporary_root)
    env["TMP"] = str(temporary_root)
    env["USERPROFILE"] = str(profile_root)
    env["APPDATA"] = str(roaming_root)
    env["LOCALAPPDATA"] = str(local_root)
    env["XDG_CACHE_HOME"] = str(cache_root)
    return env


@dataclass(frozen=True)
class AdapterResult:
    report: dict[str, Any]
    logs: list[str]


class Runner(Protocol):
    def run(
        self,
        command: Sequence[str],
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True)
class ProcessRunner:
    timeout_seconds: int
    cache_root: Path
    extra_path: Path | Sequence[Path] | None = None

    def run(
        self,
        command: Sequence[str],
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if isinstance(command, (str, bytes)) or not command:
            raise TypeError("command must be a non-empty sequence of arguments")
        arguments = [str(part) for part in command]
        if any("\0" in part for part in arguments):
            raise ValueError("command arguments cannot contain null bytes")

        # Third-party scanners receive a newly constructed environment.  Never
        # copy the service environment: platform tokens, cloud credentials and
        # authenticated proxy URLs must not cross this trust boundary.
        env = build_scanner_environment(self.cache_root, self.extra_path)

        return subprocess.run(
            arguments,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_seconds,
            env=env,
            check=False,
            shell=False,
        )


def collect_logs(completed: subprocess.CompletedProcess[str]) -> list[str]:
    return [
        line for line in [completed.stdout.strip(), completed.stderr.strip()] if line
    ]


def log_tail(logs: list[str], limit: int = 1500) -> str:
    return " | ".join(logs)[-limit:]
