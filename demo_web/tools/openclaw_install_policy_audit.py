#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parents[1]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.install_policy_audit import (  # noqa: E402
    read_recent_install_policy_audits,
    resolve_audit_db,
    verify_install_policy_audit,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify and inspect minimized OpenClaw admission audit records."
    )
    parser.add_argument("--database", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    database = args.database.resolve(strict=False) if args.database else resolve_audit_db()
    verification = verify_install_policy_audit(database)
    output = {
        "schema_version": "1.0",
        "database": str(database),
        "verification": verification,
        "events": []
        if args.verify_only
        else read_recent_install_policy_audits(database, limit=args.limit),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if verification.get("valid") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
