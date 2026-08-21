from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .process import AdapterResult, Runner, collect_logs, log_tail


@dataclass(frozen=True)
class DependencyAuditAdapter:
    executable: Path
    cache_dir: Path
    runner: Runner

    def scan(self, requirements: Path) -> AdapterResult:
        if not self.executable.is_file():
            raise RuntimeError(f"pip-audit is unavailable: {self.executable}")
        if not requirements.is_file():
            raise ValueError(f"Requirements file is unavailable: {requirements}")

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        completed = self.runner.run([
            str(self.executable),
            "-r",
            str(requirements),
            "--no-deps",
            "--disable-pip",
            "--format",
            "json",
            "--cache-dir",
            str(self.cache_dir),
        ])
        raw_logs = collect_logs(completed)
        if completed.returncode not in {0, 1} or not completed.stdout.strip():
            raise RuntimeError(
                "Dependency audit was incomplete and has been fail-closed: "
                f"{log_tail(raw_logs)}"
            )
        try:
            report = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Dependency audit returned invalid JSON: {exc}") from exc
        if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
            raise RuntimeError("Dependency audit JSON is missing dependencies")
        dependencies = report["dependencies"]
        vulnerability_count = sum(
            len(item.get("vulns") or []) for item in dependencies if isinstance(item, dict)
        )
        # stdout is the full JSON report and can be very large. Findings retain the
        # normalized evidence; persistent logs keep only bounded operational facts.
        logs = [
            f"pip-audit completed: dependencies={len(dependencies)} vulnerabilities={vulnerability_count} exit_code={completed.returncode}"
        ]
        return AdapterResult(report=report, logs=logs)
