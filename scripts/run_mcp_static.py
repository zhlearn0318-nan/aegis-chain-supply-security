"""Run Cisco MCP Scanner's static CLI and persist its JSON output.

MCP Scanner 4.8.2 accepts the global --output option for `static` but does not
write the file. This wrapper captures stdout, validates JSON, and fails closed.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--prompts", type=Path, required=True)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-unsafe", type=int, default=None)
    args = parser.parse_args()

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PATH"] = str(args.scanner.parent) + os.pathsep + env.get("PATH", "")

    command = [
        str(args.scanner),
        "--log-level",
        "error",
        "--analyzers",
        "yara",
        "--format",
        "raw",
        "static",
        "--tools",
        str(args.tools),
        "--prompts",
        str(args.prompts),
        "--resources",
        str(args.resources),
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr)
        return completed.returncode or 1

    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        print(f"MCP Scanner did not emit valid JSON: {exc}", file=sys.stderr)
        if completed.stderr:
            print(completed.stderr, file=sys.stderr)
        return 1

    results = report.get("scan_results", [])
    if not results:
        print("MCP Scanner returned no scan results; refusing to mark safe.", file=sys.stderr)
        return 1
    unsafe = sum(not item.get("is_safe", False) for item in results)
    safe = len(results) - unsafe

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"MCP static scan: total={len(results)} safe={safe} unsafe={unsafe}")
    print(f"Saved: {args.output}")

    if args.expected_unsafe is not None and unsafe != args.expected_unsafe:
        print(
            f"Expected {args.expected_unsafe} unsafe items, observed {unsafe}.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
