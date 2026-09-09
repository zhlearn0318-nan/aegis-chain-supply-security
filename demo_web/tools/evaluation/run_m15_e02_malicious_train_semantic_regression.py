from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.analyzers.finding_context import apply_finding_context  # noqa: E402
from backend.analyzers.skill_semantic import analyze_skill_semantics  # noqa: E402
from backend.policy import evaluate_findings, load_policy  # noqa: E402
from tools.datasets.prepare_m15_e01_splits import verify_scan_inputs  # noqa: E402


RUN_ID = "2026-09-08-m15-e02-malicious-train-semantic-regression-v5"
DEFAULT_DATA_ROOT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_m15_e01_v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID


class SemanticRegressionError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


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


def decision_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    malicious = [row for row in rows if row["label"] == "1"]
    benign = [row for row in rows if row["label"] == "0"]
    return {
        "cases": len(rows),
        "malicious_cases": len(malicious),
        "benign_cases": len(benign),
        "decision_counts": dict(sorted(Counter(row[key] for row in rows).items())),
        "malicious_non_allow_recall": (
            sum(row[key] in {"REVIEW", "BLOCK"} for row in malicious) / len(malicious)
            if malicious
            else None
        ),
        "benign_non_allow_rate": (
            sum(row[key] in {"REVIEW", "BLOCK"} for row in benign) / len(benign)
            if benign
            else None
        ),
        "unknown_count": sum(row[key] == "UNKNOWN" for row in rows),
    }


def run(data_root: Path, output: Path) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise SemanticRegressionError(f"Output is not empty: {output}")
    verification = verify_scan_inputs(data_root, ("train",))
    train_root = data_root / "train"
    scan_rows = load_jsonl(train_root / "scan_manifest.jsonl")
    if len(scan_rows) != 7_513:
        raise SemanticRegressionError("Expected 7,513 frozen train rows")
    policy = load_policy()
    label_blind: list[dict[str, Any]] = []
    for row in scan_rows:
        case_id = row["case_id"]
        if not row.get("scan_ready"):
            label_blind.append({"case_id": case_id, "f0_decision": "UNKNOWN", "f3_decision": "UNKNOWN", "suppressed": 0})
            continue
        skill_root = train_root / row["local_path"]
        f0_findings, _ = analyze_skill_semantics(skill_root)
        f3_findings = apply_finding_context(skill_root, f0_findings, "F3")
        label_blind.append({
            "case_id": case_id,
            "f0_decision": evaluate_findings(f0_findings, policy).decision.value,
            "f3_decision": evaluate_findings(f3_findings, policy).decision.value,
            "suppressed": sum(item.get("context_disposition") == "SUPPRESSED_TO_INFO" for item in f3_findings),
        })
    output.mkdir(parents=True, exist_ok=True)
    prediction_path = output / "predictions.label_blind.jsonl"
    write_jsonl(prediction_path, label_blind)
    after = verify_scan_inputs(data_root, ("train",))
    if after["splits"]["train"]["scan_input_tree_sha256"] != verification["splits"]["train"]["scan_input_tree_sha256"]:
        raise SemanticRegressionError("Train input changed during semantic regression")

    labels = load_jsonl(train_root / "ground_truth" / "labels.jsonl")
    by_id = {row["case_id"]: row for row in labels}
    joined = [{**row, **by_id[row["case_id"]]} for row in label_blind]
    f0 = decision_metrics(joined, "f0_decision")
    f3 = decision_metrics(joined, "f3_decision")
    per_source = {}
    for source_id in sorted({row["source_id"] for row in joined}):
        subset = [row for row in joined if row["source_id"] == source_id]
        per_source[source_id] = {
            "cases": len(subset),
            "labels": dict(sorted(Counter(row["label"] for row in subset).items())),
            "f0": decision_metrics(subset, "f0_decision"),
            "f3": decision_metrics(subset, "f3_decision"),
        }
    drop = f0["malicious_non_allow_recall"] - f3["malicious_non_allow_recall"]
    result = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "completed",
        "completed_at": now_iso(),
        "cases": len(joined),
        "source_groups": len(per_source),
        "f0_semantic_only": f0,
        "f3_semantic_only": f3,
        "per_source": per_source,
        "malicious_non_allow_drop_percentage_points": drop * 100,
        "acceptance_max_drop_percentage_points": 2.0,
        "acceptance_passed": drop <= 0.02,
        "changed_decisions": sum(row["f0_decision"] != row["f3_decision"] for row in joined),
        "suppressed_to_info": sum(row["suppressed"] for row in joined),
        "input_tree_sha256": verification["splits"]["train"]["scan_input_tree_sha256"],
        "validation_ground_truth_opened": False,
        "sample_execution": False,
        "vendor_scans": 0,
        "claim_boundary": "Deterministic semantic component regression on train only; not an independent benchmark score.",
    }
    write_json(output / "metrics.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run M15 E02 semantic-only train source-group regression")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        result = run(args.data_root.resolve(), args.output.resolve())
    except (SemanticRegressionError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
