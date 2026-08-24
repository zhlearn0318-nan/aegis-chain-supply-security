from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path
import re
import sys


LOCK_ENTRY = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")


def expected_versions(lock_path: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        match = LOCK_ENTRY.match(line)
        if match:
            expected[match.group(1).lower().replace("_", "-")] = match.group(2)
    return expected


def verify(lock_path: Path) -> dict[str, object]:
    expected = expected_versions(lock_path)
    mismatches = []
    for name, wanted in sorted(expected.items()):
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            actual = "MISSING"
        if actual != wanted:
            mismatches.append({"name": name, "expected": wanted, "actual": actual})
    return {
        "decision": "PASS" if expected and not mismatches else "FAIL",
        "expected_packages": len(expected),
        "mismatches": mismatches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify installed distributions against a hash lock.")
    parser.add_argument("lock", type=Path)
    args = parser.parse_args()
    report = verify(args.lock)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["decision"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
