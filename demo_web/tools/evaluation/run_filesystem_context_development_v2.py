from __future__ import annotations

import json
import sys
from pathlib import Path

DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from tools.evaluation import run_filesystem_context_development as base


RUN_ID = "2026-08-18-aegis-filesystem-context-dev-v2"
OUTPUT_DIR = base.DEMO_ROOT / "artifacts" / "experiment" / RUN_ID


def main() -> int:
    base.RUN_ID = RUN_ID
    try:
        result = base.run(Path(OUTPUT_DIR))
    except (
        base.EvaluationError,
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
    ) as exc:
        print(
            f"Filesystem context v2 evaluation failed: {type(exc).__name__}: {exc}",
            file=base.sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
