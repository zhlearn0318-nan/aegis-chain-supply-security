from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .process import AdapterResult, Runner, collect_logs, log_tail


@dataclass(frozen=True)
class SkillScannerAdapter:
    scanner: Path
    runner: Runner

    def scan(self, skill_path: Path) -> AdapterResult:
        if not self.scanner.is_file():
            raise RuntimeError(f"Skill Scanner is unavailable: {self.scanner}")
        if not skill_path.is_dir():
            raise ValueError(f"Skill path is not a directory: {skill_path}")

        with tempfile.TemporaryDirectory(prefix="skill-gateway-") as temp:
            output = Path(temp) / "skill-result.json"
            completed = self.runner.run([
                str(self.scanner),
                "scan",
                str(skill_path),
                "--format",
                "json",
                "--output-json",
                str(output),
                "--compact",
            ])
            raw_logs = collect_logs(completed)
            if completed.returncode != 0 or not output.is_file():
                raise RuntimeError(
                    f"Skill Scanner failed with exit code {completed.returncode}: {log_tail(raw_logs)}"
                )
            try:
                report = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"Skill Scanner returned invalid JSON: {exc}") from exc
            if not isinstance(report, dict):
                raise RuntimeError("Skill Scanner JSON root must be an object")
            if isinstance(report.get("results"), list):
                results = report["results"]
            elif report.get("skill_name"):
                results = [report]
            else:
                results = []
            finding_count = sum(
                len(item.get("findings") or []) for item in results if isinstance(item, dict)
            )
            logs = [
                f"skill-scanner completed: results={len(results)} findings={finding_count} exit_code={completed.returncode}"
            ]
            return AdapterResult(report=report, logs=logs)
