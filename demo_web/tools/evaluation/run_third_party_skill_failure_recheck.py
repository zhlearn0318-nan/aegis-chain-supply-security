from __future__ import annotations

import json
import sys
import time
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.adapters import ProcessRunner, SkillScannerAdapter  # noqa: E402
from backend.policy import load_policy  # noqa: E402
from tools.evaluation.run_third_party_skill_pilot import (  # noqa: E402
    DEFAULT_OUTPUT as PARENT_RUN_ROOT,
    RUN_ID as PARENT_RUN_ID,
    load_json,
    load_jsonl,
    now_iso,
    preflight,
    scan_case,
    sha256_file,
    write_json,
    write_jsonl,
)


ANALYSIS_RUN_ID = "2026-08-28-third-party-skill-pilot40-failure-recheck-v1"
OUTPUT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / ANALYSIS_RUN_ID


def main() -> int:
    parent_manifest = load_json(PARENT_RUN_ROOT / "run_manifest.json")
    if parent_manifest.get("run_id") != PARENT_RUN_ID or parent_manifest.get("status") != "completed":
        raise RuntimeError("The parent run is not the completed frozen main result")
    for name, identity in parent_manifest["outputs"].items():
        if sha256_file(PARENT_RUN_ROOT / name) != identity["sha256"]:
            raise RuntimeError(f"Parent output drift: {name}")
    parent_results = load_jsonl(PARENT_RUN_ROOT / "per_case_results.jsonl")
    failed_ids = [row["case_id"] for row in parent_results if row["status"] != "completed"]
    if not failed_ids:
        raise RuntimeError("The parent run has no failed cases to recheck")
    source_records, _ = preflight()
    source_by_id = {row["case_id"]: row for row in source_records}
    selected = [source_by_id[case_id] for case_id in failed_ids]
    if OUTPUT_ROOT.exists() and any(OUTPUT_ROOT.iterdir()):
        raise RuntimeError(f"Analysis output already exists: {OUTPUT_ROOT}")
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    scanner = REPRODUCTION_ROOT / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
    runner = ProcessRunner(
        timeout_seconds=60,
        cache_root=DEMO_ROOT / "data" / "cache" / "third_party_skill_pilot40_v1",
        extra_path=scanner.parent,
    )
    adapter = SkillScannerAdapter(scanner=scanner, runner=runner)
    policy = load_policy()
    started = time.perf_counter()
    results = []
    for record in selected:
        result = scan_case(adapter, policy, record)
        result["run_id"] = ANALYSIS_RUN_ID
        results.append(result)
    write_jsonl(OUTPUT_ROOT / "per_case_results.jsonl", results)
    summary = {
        "schema_version": "1.0",
        "analysis_run_id": ANALYSIS_RUN_ID,
        "parent_run_id": PARENT_RUN_ID,
        "question": "Are the two parent UNKNOWN outcomes reproducible when only parallelism changes from 4 to 1?",
        "fixed_conditions": ["dataset", "case hashes", "scanner binary", "Aegis analyzers", "policy", "60-second timeout"],
        "changed_condition": "parallel_workers: 4 -> 1",
        "cases": failed_ids,
        "outcomes": [
            {"case_id": row["case_id"], "status": row["status"], "decision": row["decision"], "duration_ms": row["duration_ms"]}
            for row in results
        ],
        "recovered_count": sum(row["status"] == "completed" for row in results),
        "wall_seconds": round(time.perf_counter() - started, 3),
        "completed_at": now_iso(),
        "comparability": "Failure robustness slice only; it does not replace or merge into the frozen parent metrics.",
    }
    write_json(OUTPUT_ROOT / "analysis_summary.json", summary)
    write_json(OUTPUT_ROOT / "verification.json", {
        "parent_manifest_sha256": sha256_file(PARENT_RUN_ROOT / "run_manifest.json"),
        "results_sha256": sha256_file(OUTPUT_ROOT / "per_case_results.jsonl"),
        "summary_sha256": sha256_file(OUTPUT_ROOT / "analysis_summary.json"),
    })
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
