from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.analyzers import (  # noqa: E402
    analyze_command_context,
    analyze_custom_rules,
    analyze_enterprise_controls,
    analyze_filesystem_context,
    analyze_network_context,
    analyze_sensitive_flows,
    analyze_skill_capability_alignment,
    analyze_skill_semantics,
    analyze_static_coverage,
    analyze_skill_tree,
    analyze_untrusted_exec_flows,
)
from backend.analyzers.finding_context import PROTECTED_COMPLETE_RULES, apply_finding_context  # noqa: E402
from backend.policy import evaluate_findings, load_policy  # noqa: E402
from tools.datasets.prepare_skilltrustbench import tree_sha256  # noqa: E402
from tools.evaluation.compare_skill_evidence_policy import replay_cisco_finding  # noqa: E402


RUN_ID = "2026-09-08-m15-e02-skilltrust-regression600-v3"
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / "2026-08-15-skilltrustbench-dev120-regression600-v1"
PARENT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
CASES_ROOT = REPOSITORY_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
REGRESSION_PATH = SPLIT_ROOT / "regression_cases.jsonl"
REGRESSION_IDS_PATH = SPLIT_ROOT / "regression_case_ids.txt"
PARENT_RESULTS_PATH = PARENT_ROOT / "per_case_results.jsonl"
EXPECTED_HASHES = {
    REGRESSION_PATH: "8ee8745594cf2d7ef643cf95e61ccd88c420b42c540780dadb7320cbe7c90492",
    REGRESSION_IDS_PATH: "cd83b4f4251b23701fdd98b6b9d3899777ca41f9d573d4fb502ce3307f0cc07d",
    PARENT_RESULTS_PATH: "15a9ec0cdb3b30d7d55d4a3f67e8a31b9f324f7724c46ede83ec07d5f79cd918",
}


class RegressionError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def normalize_cisco_finding(item: dict[str, Any], case_root: Path) -> dict[str, Any]:
    finding = replay_cisco_finding(item)
    location = dict(finding.get("location") or {})
    file_value = str(location.get("file") or "")
    if file_value:
        candidate = Path(file_value)
        if candidate.is_absolute():
            try:
                location["file"] = candidate.resolve().relative_to(case_root.resolve()).as_posix()
            except ValueError:
                location["file"] = candidate.name
        else:
            location["file"] = file_value.replace("\\", "/")
    finding["location"] = location
    return finding


def current_aegis_findings(case_root: Path, cisco: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for analyzer, uses_cisco in (
        (analyze_skill_tree, False),
        (analyze_sensitive_flows, False),
        (analyze_untrusted_exec_flows, False),
        (analyze_enterprise_controls, False),
        (analyze_static_coverage, False),
        (analyze_network_context, True),
        (analyze_filesystem_context, True),
        (analyze_command_context, True),
    ):
        current, _ = analyzer(case_root, cisco) if uses_cisco else analyzer(case_root)
        findings.extend(current)
    for analyzer in (analyze_skill_semantics, analyze_skill_capability_alignment):
        current, _ = analyzer(case_root)
        findings.extend(current)
    custom, _ = analyze_custom_rules(case_root, "skill")
    findings.extend(custom)
    return findings


def scan_case(
    regression: dict[str, Any], parent: dict[str, Any], policy: Any
) -> dict[str, Any]:
    case_id = str(regression["case_id"])
    expected_hash = str(regression["case_tree_sha256"])
    base = {
        "case_id": case_id,
        "ground_truth": str(regression["ground_truth"]),
        "risk_labels": regression.get("risk_labels") or [],
        "expected_tree_sha256": expected_hash,
    }
    if parent.get("status") != "completed":
        return {**base, "status": "parent_failed", "f0_decision": "UNKNOWN", "f3_decision": "UNKNOWN", "suppressed_to_info": 0}
    case_root = CASES_ROOT / case_id
    started = time.perf_counter()
    try:
        before = tree_sha256(case_root)
        if before != expected_hash or str(parent.get("case_tree_sha256_before")) != expected_hash:
            raise RegressionError("case identity mismatch")
        cisco = [normalize_cisco_finding(item, case_root) for item in parent.get("finding_index") or []]
        aegis = current_aegis_findings(case_root, cisco)
        f0_findings = [*cisco, *aegis]
        f3_findings = apply_finding_context(case_root, f0_findings, "F3")
        f0 = evaluate_findings(f0_findings, policy).decision.value
        f3 = evaluate_findings(f3_findings, policy).decision.value
        protected_before = {
            str(item.get("id")): str(item.get("severity")) for item in f0_findings
            if item.get("rule_id") in PROTECTED_COMPLETE_RULES
        }
        protected_after = {
            str(item.get("id")): str(item.get("severity")) for item in f3_findings
            if item.get("rule_id") in PROTECTED_COMPLETE_RULES
        }
        if protected_before != protected_after:
            raise RegressionError("protected complete finding changed")
        after = tree_sha256(case_root)
        if after != before:
            raise RegressionError("case changed during regression")
        return {
            **base,
            "status": "completed",
            "f0_decision": f0,
            "f3_decision": f3,
            "suppressed_to_info": sum(item.get("context_disposition") == "SUPPRESSED_TO_INFO" for item in f3_findings),
            "suppression_rules": dict(sorted(Counter(
                str(item.get("context_rule_id")) for item in f3_findings
                if item.get("context_disposition") == "SUPPRESSED_TO_INFO"
            ).items())),
            "protected_complete_downgrades": 0,
            "duration_ms": max(1, round((time.perf_counter() - started) * 1000)),
        }
    except Exception as exc:
        return {
            **base,
            "status": "failed",
            "f0_decision": "UNKNOWN",
            "f3_decision": "UNKNOWN",
            "suppressed_to_info": 0,
            "error_type": type(exc).__name__,
            "raw_error_retained": False,
        }


def metrics(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    malicious = [row for row in rows if row["ground_truth"] == "malicious"]
    normal = [row for row in rows if row["ground_truth"] == "normal"]
    return {
        "decision_counts": dict(sorted(Counter(row[key] for row in rows).items())),
        "malicious_non_allow_recall": sum(row[key] in {"REVIEW", "BLOCK"} for row in malicious) / len(malicious),
        "malicious_block_recall": sum(row[key] == "BLOCK" for row in malicious) / len(malicious),
        "normal_non_allow_rate": sum(row[key] in {"REVIEW", "BLOCK"} for row in normal) / len(normal),
        "normal_block_rate": sum(row[key] == "BLOCK" for row in normal) / len(normal),
        "unknown_count": sum(row[key] == "UNKNOWN" for row in rows),
    }


def run(output: Path, workers: int) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise RegressionError(f"Output is not empty: {output}")
    for path, expected in EXPECTED_HASHES.items():
        if sha256_file(path) != expected:
            raise RegressionError(f"Frozen input hash mismatch: {path}")
    regression = load_jsonl(REGRESSION_PATH)
    ids = REGRESSION_IDS_PATH.read_text(encoding="utf-8").splitlines()
    if len(regression) != 600 or [row["case_id"] for row in regression] != ids:
        raise RegressionError("Frozen regression identity mismatch")
    if Counter(row["ground_truth"] for row in regression) != {"normal": 200, "suspicious": 200, "malicious": 200}:
        raise RegressionError("Frozen regression balance mismatch")
    parents = {row["case_id"]: row for row in load_jsonl(PARENT_RESULTS_PATH)}
    policy = load_policy()
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="m15-e02-regression") as executor:
        rows = list(executor.map(lambda row: scan_case(row, parents[row["case_id"]], policy), regression))
    write_jsonl(output / "per_case_results.jsonl", rows)
    f0 = metrics(rows, "f0_decision")
    f3 = metrics(rows, "f3_decision")
    drop = f0["malicious_non_allow_recall"] - f3["malicious_non_allow_recall"]
    result = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "completed",
        "completed_at": now_iso(),
        "cases": len(rows),
        "workers": workers,
        "wall_seconds": round(time.perf_counter() - started, 3),
        "f0": f0,
        "f3": f3,
        "malicious_non_allow_drop_percentage_points": drop * 100,
        "acceptance_max_drop_percentage_points": 2.0,
        "acceptance_passed": drop <= 0.02,
        "changed_decisions": sum(row["f0_decision"] != row["f3_decision"] for row in rows),
        "transition_counts": dict(sorted(Counter(f"{row['f0_decision']}->{row['f3_decision']}" for row in rows).items())),
        "suppressed_to_info": sum(row.get("suppressed_to_info", 0) for row in rows),
        "failed_current_analysis": sum(row["status"] == "failed" for row in rows),
        "parent_failed": sum(row["status"] == "parent_failed" for row in rows),
        "protected_complete_downgrades": sum(row.get("protected_complete_downgrades", 0) for row in rows),
        "input_hashes": {str(path): expected for path, expected in EXPECTED_HASHES.items()},
        "sample_execution": False,
        "vendor_rescans": 0,
    }
    write_json(output / "metrics.json", result)
    write_json(output / "run_manifest.json", {
        **result,
        "outputs": {
            "per_case_results.jsonl": sha256_file(output / "per_case_results.jsonl"),
            "metrics.json": sha256_file(output / "metrics.json"),
        },
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run M15 E02 F0/F3 on the frozen SkillTrustBench regression600")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    try:
        result = run(args.output.resolve(), args.workers)
    except (RegressionError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
