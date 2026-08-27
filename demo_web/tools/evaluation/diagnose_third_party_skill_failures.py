from __future__ import annotations

import json
import re
import sys
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.adapters import ProcessRunner, SkillScannerAdapter  # noqa: E402
from tools.evaluation.run_third_party_skill_pilot import DATA_ROOT, preflight, write_json  # noqa: E402


CASE_IDS = ("masb-048-api-design", "stb-case_03882")
OUTPUT = (
    DEMO_ROOT / "artifacts" / "analysis"
    / "2026-08-28-third-party-skill-pilot40-failure-recheck-v1"
    / "failure_diagnostics.json"
)


def safe_message(message: str) -> str:
    text = message.replace(str(REPRODUCTION_ROOT), "<REPRODUCTION_ROOT>")
    text = text.replace(str(DATA_ROOT), "<DATA_ROOT>")
    text = re.sub(r"[A-Za-z]:\\[^|\r\n]+", "<LOCAL_PATH>", text)
    return text[-1200:]


def main() -> int:
    records, _ = preflight()
    by_id = {row["case_id"]: row for row in records}
    scanner = REPRODUCTION_ROOT / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
    adapter = SkillScannerAdapter(
        scanner=scanner,
        runner=ProcessRunner(
            timeout_seconds=60,
            cache_root=DEMO_ROOT / "data" / "cache" / "third_party_skill_pilot40_v1",
            extra_path=scanner.parent,
        ),
    )
    diagnostics = []
    for case_id in CASE_IDS:
        try:
            adapter.scan(DATA_ROOT / by_id[case_id]["local_path"])
            diagnostics.append({"case_id": case_id, "status": "unexpected_success", "error_type": None})
        except Exception as exc:
            diagnostics.append({
                "case_id": case_id,
                "status": "failed",
                "error_type": type(exc).__name__,
                "safe_log_tail": safe_message(str(exc)),
            })
    payload = {
        "schema_version": "1.0",
        "scope": "diagnostic_only_no_sample_execution",
        "cases": diagnostics,
    }
    write_json(OUTPUT, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
