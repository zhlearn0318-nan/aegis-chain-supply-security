from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
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

from backend.adapters import ProcessRunner, SkillScannerAdapter  # noqa: E402
from backend.dynamic_audit.skill_sandbox import evaluate_dynamic_result, serialize_dynamic_evaluation  # noqa: E402
from backend.policy import load_policy  # noqa: E402
from tools.datasets.prepare_third_party_skill_dynamic_pairs import tree_sha256  # noqa: E402
from tools.evaluation.run_third_party_skill_dynamic_pairs import static_scan, verify_dataset  # noqa: E402


RUN_ID = "2026-09-08-m15-e03-dynamic-round-ablation-v2"
DATA_ROOT = REPOSITORY_ROOT / "datasets" / "third_party_skill_dynamic_pairs_v1"
SOURCE_ROOT = DEMO_ROOT / "artifacts" / "analysis" / "2026-08-31-third-party-skill-dynamic-pairs-main-v1"
CONTRACT_PATH = DEMO_ROOT / "config" / "m15_e03_dynamic_round_ablation_v1.json"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2, "UNKNOWN": 2}


class AblationError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AblationError(f"Expected object: {path}")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def percentile(values: list[int], percentile_value: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile_value * len(ordered)) - 1)]


def fuse(static: str, dynamic: str | None) -> str:
    if static == "UNKNOWN":
        return "BLOCK"
    if dynamic is None:
        return static
    return dynamic if RANK.get(dynamic, 2) > RANK.get(static, 2) else static


def prefix_evaluation(payload: dict[str, Any], rounds: tuple[str, ...]) -> dict[str, Any]:
    runner = payload.get("runner") or {}
    events = [item for item in runner.get("events") or [] if str(item.get("round") or "") in rounds]
    round_rows = [item for item in runner.get("rounds") or [] if str(item.get("id") or "") in rounds]
    def round_completed(item: dict[str, Any]) -> bool:
        if "execution_status" in item:
            return str(item.get("execution_status") or "").casefold() in {"completed", "clean"}
        return item.get("timed_out") is False and item.get("exit_code") == 0

    complete = (
        runner.get("telemetry_complete") is True
        and len(round_rows) == len(rounds)
        and all(round_completed(item) for item in round_rows)
    )
    execution_status = "completed" if complete else "infrastructure_failed"
    evaluation = evaluate_dynamic_result(events, execution_status=execution_status, telemetry_complete=complete)
    return {
        "rounds": list(rounds),
        "event_count": len(events),
        "evaluation": serialize_dynamic_evaluation(evaluation),
        "round_duration_ms": sum(int(item.get("duration_ms") or 0) for item in round_rows),
    }


def analyze_prefixes(
    records: list[dict[str, Any]], static_rows: list[dict[str, Any]], source_root: Path
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    static_by_id = {row["case_id"]: row for row in static_rows}
    rows: list[dict[str, Any]] = []
    for record in records:
        case_id = str(record["case_id"])
        payload = load_json(source_root / "dynamic_results" / f"{case_id}.json")
        d1 = prefix_evaluation(payload, ("typical",))
        d3 = prefix_evaluation(payload, ("typical", "edge", "adversarial"))
        full_duration = int(payload.get("duration_ms") or 0)
        all_rounds = payload.get("runner", {}).get("rounds") or []
        measured_round_durations = all(isinstance(item.get("duration_ms"), (int, float)) for item in all_rounds)
        later_duration = sum(
            int(item.get("duration_ms") or 0)
            for item in all_rounds
            if str(item.get("id") or "") in {"edge", "adversarial"}
        )
        static_row = static_by_id[case_id]
        static_decision = str(static_row["decision"])
        d1_decision = str(d1["evaluation"]["decision"])
        d3_decision = str(d3["evaluation"]["decision"])
        d1_rules = sorted({str(item["rule_id"]) for item in d1["evaluation"]["findings"]})
        d3_rules = sorted({str(item["rule_id"]) for item in d3["evaluation"]["findings"]})
        expected = record.get("expected_rule_id")
        first_trigger = None
        if expected:
            for round_id in ("typical", "edge", "adversarial"):
                prefix = ("typical",) if round_id == "typical" else (("typical", "edge") if round_id == "edge" else ("typical", "edge", "adversarial"))
                rules = {
                    str(item["rule_id"])
                    for item in prefix_evaluation(payload, prefix)["evaluation"]["findings"]
                }
                if expected in rules:
                    first_trigger = round_id
                    break
        static_ms = int(static_row.get("duration_ms") or 0)
        rows.append({
            "case_id": case_id,
            "variant": record["variant"],
            "risk_type": record["risk_type"],
            "expected_rule_id": expected,
            "static_decision": static_decision,
            "D0": {"decision": static_decision, "duration_ms": static_ms, "rule_ids": []},
            "D1": {
                "dynamic_decision": d1_decision,
                "decision": fuse(static_decision, d1_decision),
                "duration_ms": static_ms + (
                    max(0, full_duration - later_duration)
                    if measured_round_durations
                    else math.ceil(full_duration / 3)
                ),
                "latency_attribution": "measured_round_subtraction" if measured_round_durations else "conservative_one_third_lower_bound",
                "rule_ids": d1_rules,
            },
            "D3": {
                "dynamic_decision": d3_decision,
                "decision": fuse(static_decision, d3_decision),
                "duration_ms": static_ms + full_duration,
                "rule_ids": d3_rules,
            },
            "first_expected_rule_round": first_trigger,
            "source_security_gates": all((payload.get("image_gates") or {}).values()) and all((payload.get("inspect_gates") or {}).values()),
            "source_cleanup_verified": (payload.get("cleanup") or {}).get("removed") is True and (payload.get("cleanup") or {}).get("residual") is False,
        })
    risks = [row for row in rows if row["variant"] == "controlled_risk_twin"]
    originals = [row for row in rows if row["variant"] == "original"]
    systems: dict[str, Any] = {}
    for system in ("D0", "D1", "D3"):
        risk_nonallow = sum(row[system]["decision"] in {"REVIEW", "BLOCK"} for row in risks)
        expected_detected = sum(
            bool(row["expected_rule_id"]) and row["expected_rule_id"] in row[system]["rule_ids"]
            for row in risks
        )
        durations = [int(row[system]["duration_ms"]) for row in rows]
        systems[system] = {
            "decision_counts": dict(sorted(Counter(row[system]["decision"] for row in rows).items())),
            "risk_non_allow": risk_nonallow,
            "risk_non_allow_recall": risk_nonallow / len(risks),
            "expected_dynamic_rule_recall": expected_detected / len(risks),
            "original_dynamic_allow_rate": (
                1.0 if system == "D0" else sum(row[system]["dynamic_decision"] == "ALLOW" for row in originals) / len(originals)
            ),
            "static_allow_to_dynamic_non_allow": sum(
                row["static_decision"] == "ALLOW" and row[system]["decision"] in {"REVIEW", "BLOCK"}
                for row in risks
            ),
            "static_review_to_dynamic_block": sum(
                row["static_decision"] == "REVIEW" and row[system]["decision"] == "BLOCK"
                for row in risks
            ),
            "latency_ms": {"p50": round(statistics.median(durations)), "p95": percentile(durations, 0.95)},
            "container_instances": 0 if system == "D0" else len(rows),
            "script_round_invocations": 0 if system == "D0" else len(rows) * (1 if system == "D1" else 3),
        }
    d1_types = {
        row["risk_type"] for row in risks
        if row["expected_rule_id"] in row["D1"]["rule_ids"]
    }
    d3_types = {
        row["risk_type"] for row in risks
        if row["expected_rule_id"] in row["D3"]["rule_ids"]
    }
    metrics = {
        "systems": systems,
        "first_expected_rule_round": dict(sorted(Counter(str(row["first_expected_rule_round"] or "not_detected") for row in risks).items())),
        "d3_incremental_risk_types_vs_d1": sorted(d3_types - d1_types),
        "d3_recall_gain_percentage_points": (systems["D3"]["risk_non_allow_recall"] - systems["D1"]["risk_non_allow_recall"]) * 100,
        "d3_to_d1_p95_total_latency_ratio": systems["D3"]["latency_ms"]["p95"] / max(1, systems["D1"]["latency_ms"]["p95"]),
        "source_security_and_cleanup_gate_rate": sum(row["source_security_gates"] and row["source_cleanup_verified"] for row in rows) / len(rows),
    }
    return rows, metrics


def run(output: Path, workers: int, static_input: Path | None = None) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise AblationError(f"Output is not empty: {output}")
    contract = load_json(CONTRACT_PATH)
    records, _, _ = verify_dataset()
    checks = {
        "dataset_manifest": sha256_file(DATA_ROOT / "manifest.jsonl") == contract["dataset_manifest_sha256"],
        "dataset_tree": tree_sha256(DATA_ROOT) == contract["dataset_tree_sha256"],
        "source_run_manifest": sha256_file(SOURCE_ROOT / "run_manifest.json") == contract["source_run_manifest_sha256"],
        "source_dynamic_summary": sha256_file(SOURCE_ROOT / "dynamic_results.jsonl") == contract["source_dynamic_summary_sha256"],
        "source_dynamic_detail_tree": tree_sha256(SOURCE_ROOT / "dynamic_results") == contract["source_dynamic_detail_tree_sha256"],
    }
    if not all(checks.values()):
        raise AblationError(f"Frozen input verification failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    if static_input is not None:
        static_rows = load_jsonl(static_input.resolve(strict=True))
        if {row.get("case_id") for row in static_rows} != {row.get("case_id") for row in records}:
            raise AblationError("Reused static result case IDs do not match the frozen dataset")
    else:
        scanner = REPOSITORY_ROOT / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
        process_runner = ProcessRunner(
            timeout_seconds=150,
            cache_root=DEMO_ROOT / "data" / "cache" / "m15_e03",
            extra_path=scanner.parent,
        )
        adapter = SkillScannerAdapter(scanner=scanner, runner=process_runner)
        policy = load_policy()
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="m15-e03-static") as executor:
            static_rows = list(executor.map(lambda record: static_scan(adapter, policy, record), records))
    write_jsonl(output / "static_v5_results.jsonl", static_rows)
    rows, metrics = analyze_prefixes(records, static_rows, SOURCE_ROOT)
    write_jsonl(output / "paired_results.jsonl", rows)
    thresholds = contract["acceptance"]
    acceptance = {
        "d3_has_incremental_detection": (
            len(metrics["d3_incremental_risk_types_vs_d1"]) >= thresholds["minimum_d3_incremental_risk_types"]
            or metrics["d3_recall_gain_percentage_points"] >= thresholds["minimum_d3_recall_gain_percentage_points"]
        ),
        "p95_ratio_within_limit": metrics["d3_to_d1_p95_total_latency_ratio"] <= thresholds["maximum_d3_to_d1_p95_total_latency_ratio"],
        "original_dynamic_allow_d1": metrics["systems"]["D1"]["original_dynamic_allow_rate"] == thresholds["original_dynamic_allow_rate"],
        "original_dynamic_allow_d3": metrics["systems"]["D3"]["original_dynamic_allow_rate"] == thresholds["original_dynamic_allow_rate"],
        "source_security_and_cleanup": metrics["source_security_and_cleanup_gate_rate"] == thresholds["source_security_and_cleanup_gate_rate"],
        "dataset_immutable": tree_sha256(DATA_ROOT) == contract["dataset_tree_sha256"],
    }
    decision = "KEEP_THREE_ROUNDS_DEFAULT" if all(acceptance.values()) else "USE_ONE_ROUND_OR_CONDITIONAL_ESCALATION"
    result = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "completed",
        "completed_at": now_iso(),
        "wall_seconds": round(time.perf_counter() - started, 3),
        "input_checks": checks,
        "metrics": metrics,
        "acceptance": acceptance,
        "accepted": all(acceptance.values()),
        "engineering_decision": decision,
        "known_malicious_third_party_executed": False,
        "d1_latency_kind": "prefix_attribution_from_same_measured_d3_container_run",
        "static_input": {
            "reused": static_input is not None,
            "sha256": sha256_file(static_input.resolve(strict=True)) if static_input is not None else sha256_file(output / "static_v5_results.jsonl"),
        },
    }
    write_json(output / "metrics.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run M15 E03 D0/D1/D3 prefix-replay ablation")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--static-input", type=Path)
    args = parser.parse_args()
    if not 1 <= args.workers <= 8:
        raise AblationError("workers must be 1..8")
    result = run(args.output.resolve(), args.workers, args.static_input)
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
