from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .process import AdapterResult, Runner, collect_logs, log_tail


@dataclass(frozen=True)
class McpScannerAdapter:
    python: Path
    wrapper: Path
    scanner: Path
    runner: Runner

    def scan(self, tools: Path, prompts: Path, resources: Path) -> AdapterResult:
        for label, path in {
            "MCP Python": self.python,
            "MCP wrapper": self.wrapper,
            "MCP Scanner": self.scanner,
            "tools": tools,
            "prompts": prompts,
            "resources": resources,
        }.items():
            if not path.is_file():
                raise RuntimeError(f"{label} is unavailable: {path}")

        with tempfile.TemporaryDirectory(prefix="mcp-gateway-") as temp:
            output = Path(temp) / "mcp-result.json"
            completed = self.runner.run([
                str(self.python),
                str(self.wrapper),
                "--scanner",
                str(self.scanner),
                "--tools",
                str(tools),
                "--prompts",
                str(prompts),
                "--resources",
                str(resources),
                "--output",
                str(output),
            ])
            raw_logs = collect_logs(completed)
            if completed.returncode != 0 or not output.is_file():
                raise RuntimeError(
                    f"MCP Scanner failed with exit code {completed.returncode}: {log_tail(raw_logs)}"
                )
            try:
                report = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"MCP Scanner returned invalid JSON: {exc}") from exc
            if not isinstance(report, dict):
                raise RuntimeError("MCP Scanner JSON root must be an object")
            results = report.get("scan_results") if isinstance(report.get("scan_results"), list) else []
            unsafe = sum(
                not bool(item.get("is_safe", False)) for item in results if isinstance(item, dict)
            )
            logs = [
                f"mcp-scanner completed: results={len(results)} unsafe={unsafe} exit_code={completed.returncode}"
            ]
            return AdapterResult(report=report, logs=logs)
