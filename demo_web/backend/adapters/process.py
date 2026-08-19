from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Sequence


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
    extra_path: Path | None = None

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

        env = os.environ.copy()
        for credential in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "VIRUSTOTAL_API_KEY",
            "AI_DEFENSE_API_KEY",
        ):
            env.pop(credential, None)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["HF_HUB_OFFLINE"] = "1"
        env["TRANSFORMERS_OFFLINE"] = "1"
        if self.extra_path:
            env["PATH"] = str(self.extra_path) + os.pathsep + env.get("PATH", "")
        self.cache_root.mkdir(parents=True, exist_ok=True)
        env["LOCALAPPDATA"] = str(self.cache_root)
        env["XDG_CACHE_HOME"] = str(self.cache_root)
        env["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"

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
