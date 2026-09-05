from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.policy import DEFAULT_POLICY_PATH, evaluate_findings, load_policy  # noqa: E402


RUN_ID = "2026-08-31-skill-evidence-policy-replay600-v3"
SOURCE_RUN_ID = "2026-08-22-static-audit-regression600-v1"
PARENT_RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
SOURCE_RESULTS = DEMO_ROOT / "artifacts" / "experiment" / SOURCE_RUN_ID / "per_case_results.jsonl"
PARENT_RESULTS = DEMO_ROOT / "artifacts" / "analysis" / PARENT_RUN_ID / "per_case_results.jsonl"
FROZEN_POLICY = DEMO_ROOT / "config" / "admission_policy.yaml"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
EXPECTED_FROZEN_POLICY_SHA256 = "010ca27b327e5098b11d7819563b40a607cac7698ac01019740557b8eaececf5"
DECISION_TO_LABEL = {
    "ALLOW": "normal",
    "REVIEW": "suspicious",
    "BLOCK": "malicious",
    "UNKNOWN": "abstain",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise RuntimeError(f"JSONL row is not an object: {path}:{line_number}")
            rows.append(payload)
    return rows


def write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def replay_cisco_finding(item: dict[str, Any]) -> dict[str, Any]:
    """Recreate the trusted provenance fields added by the current normalizer.

    The sealed parent result deliberately retains no raw snippet, so this replay
    changes only provenance metadata and leaves rule, severity and analyzer intact.
    """
    original_id = str(item.get("id") or item.get("rule_id") or "finding")
    identity = hashlib.sha256(original_id.encode("utf-8")).hexdigest()[:20]
    return {
        **item,
        "id": f"vendor-skill-replay-{identity}",
        "category": "vendor_skill_finding",
        "evidence_confidence": "POTENTIAL",
        "reachability": "UNKNOWN",
        "behavior_alignment": "UNKNOWN",
        "evidence_source": "CISCO",
    }


def decision_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    class_counts = Counter(str(row["ground_truth"]) for row in rows)
    decision_counts = Counter(str(row[key]) for row in rows)
    normal_total = class_counts["normal"]
    malicious_total = class_counts["malicious"]
    return {
        "decision_counts": dict(sorted(decision_counts.items())),
        "overall_review_rate": decision_counts["REVIEW"] / len(rows) if rows else 0.0,
        "normal_auto_allow_rate": (
            sum(row["ground_truth"] == "normal" and row[key] == "ALLOW" for row in rows)
            / normal_total
            if normal_total
            else 0.0
        ),
        "normal_false_positive_rate": (
            sum(
                row["ground_truth"] == "normal" and row[key] in {"REVIEW", "BLOCK"}
                for row in rows
            )
            / normal_total
            if normal_total
            else 0.0
        ),
        "normal_block_rate": (
            sum(row["ground_truth"] == "normal" and row[key] == "BLOCK" for row in rows)
            / normal_total
            if normal_total
            else 0.0
        ),
        "malicious_block_recall": (
            sum(
                row["ground_truth"] == "malicious" and row[key] == "BLOCK"
                for row in rows
            )
            / malicious_total
            if malicious_total
            else 0.0
        ),
        "malicious_non_allow_recall": (
            sum(
                row["ground_truth"] == "malicious"
                and row[key] in {"REVIEW", "BLOCK"}
                for row in rows
            )
            / malicious_total
            if malicious_total
            else 0.0
        ),
    }


def run(output: Path) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"Output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    frozen_hash = sha256_file(FROZEN_POLICY)
    if frozen_hash != EXPECTED_FROZEN_POLICY_SHA256:
        raise RuntimeError("Frozen v1.0.0 policy hash changed")
    if DEFAULT_POLICY_PATH.resolve() == FROZEN_POLICY.resolve():
        raise RuntimeError("Current and frozen policies must use separate files")

    source_rows = load_jsonl(SOURCE_RESULTS)
    parent_rows = {
        str(row["case_id"]): row
        for row in load_jsonl(PARENT_RESULTS)
        if isinstance(row.get("case_id"), str)
    }
    if len(source_rows) != 600:
        raise RuntimeError(f"Expected 600 sealed rows, got {len(source_rows)}")

    frozen_policy = load_policy(FROZEN_POLICY)
    current_policy = load_policy(DEFAULT_POLICY_PATH)
    replay_rows: list[dict[str, Any]] = []
    deltas: list[dict[str, Any]] = []
    baseline_mismatches: list[str] = []
    aegis_high_downgrades: list[str] = []

    for source in source_rows:
        case_id = str(source["case_id"])
        parent = parent_rows.get(case_id)
        if parent is None:
            raise RuntimeError(f"Parent row missing: {case_id}")

        if source.get("enhancement_status") != "completed" or parent.get("status") != "completed":
            old_decision = str(source.get("enhanced_decision") or "UNKNOWN")
            new_decision = old_decision
            candidate_count = 0
            aegis_blocking_count = 0
            old_rule = str((source.get("enhanced_policy_trace") or {}).get("rule_id") or "")
            new_rule = old_rule
        else:
            cisco = [replay_cisco_finding(item) for item in parent.get("finding_index") or []]
            aegis = [dict(item) for item in source.get("aegis_findings") or []]
            findings = [*cisco, *aegis]
            old_evaluation = evaluate_findings(findings, frozen_policy)
            new_evaluation = evaluate_findings(findings, current_policy)
            old_decision = old_evaluation.decision.value
            new_decision = new_evaluation.decision.value
            old_rule = old_evaluation.trace.rule_id
            new_rule = new_evaluation.trace.rule_id
            candidate_count = sum(
                str(item.get("severity") or "").upper() == "HIGH" for item in cisco
            )
            aegis_blocking_count = sum(
                str(item.get("severity") or "").upper() in {"HIGH", "CRITICAL"}
                for item in aegis
            )
            if old_decision != source.get("enhanced_decision"):
                baseline_mismatches.append(case_id)
            if aegis_blocking_count and old_decision == "BLOCK" and new_decision != "BLOCK":
                aegis_high_downgrades.append(case_id)

        replay = {
            "case_id": case_id,
            "ground_truth": str(source["ground_truth"]),
            "old_decision": old_decision,
            "new_decision": new_decision,
            "old_rule": old_rule,
            "new_rule": new_rule,
            "cisco_high_candidates": candidate_count,
            "aegis_high_or_critical": aegis_blocking_count,
        }
        replay_rows.append(replay)
        if old_decision != new_decision:
            deltas.append(replay)

    if baseline_mismatches:
        raise RuntimeError(
            f"Replay is not comparable with sealed decisions: {len(baseline_mismatches)} mismatches"
        )
    if aegis_high_downgrades:
        raise RuntimeError(
            f"Aegis HIGH/CRITICAL blockers were downgraded: {len(aegis_high_downgrades)}"
        )

    transitions = Counter(f"{row['old_decision']}->{row['new_decision']}" for row in replay_rows)
    old_metrics = decision_metrics(replay_rows, "old_decision")
    new_metrics = decision_metrics(replay_rows, "new_decision")
    metrics = {
        "run_id": RUN_ID,
        "status": "completed",
        "cases": len(replay_rows),
        "comparable_to_sealed_decisions": True,
        "baseline_mismatches": 0,
        "aegis_high_or_critical_downgrades": 0,
        "changed_cases": len(deltas),
        "changed_ground_truth_counts": dict(
            sorted(Counter(row["ground_truth"] for row in deltas).items())
        ),
        "transitions": dict(sorted(transitions.items())),
        "old_policy": old_metrics,
        "new_policy": new_metrics,
        "deltas": {
            "normal_false_positive_rate": (
                new_metrics["normal_false_positive_rate"]
                - old_metrics["normal_false_positive_rate"]
            ),
            "normal_block_rate": (
                new_metrics["normal_block_rate"] - old_metrics["normal_block_rate"]
            ),
            "malicious_block_recall": (
                new_metrics["malicious_block_recall"]
                - old_metrics["malicious_block_recall"]
            ),
            "malicious_non_allow_recall": (
                new_metrics["malicious_non_allow_recall"]
                - old_metrics["malicious_non_allow_recall"]
            ),
            "overall_review_rate": (
                new_metrics["overall_review_rate"] - old_metrics["overall_review_rate"]
            ),
        },
    }
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "started_and_completed_at": now_iso(),
        "research_type": "policy-only replay on sealed static findings",
        "research_question": (
            "Does evidence-aware handling of uncorroborated Cisco Skill HIGH findings "
            "reduce direct blocks without downgrading Aegis HIGH/CRITICAL chains?"
        ),
        "null_hypothesis": "The new policy does not change decisions or weakens Aegis blockers.",
        "alternative_hypothesis": (
            "The new policy moves Cisco-only HIGH blocks to REVIEW while preserving Aegis blockers."
        ),
        "source_run": {
            "run_id": SOURCE_RUN_ID,
            "path": str(SOURCE_RESULTS),
            "sha256": sha256_file(SOURCE_RESULTS),
        },
        "parent_run": {
            "run_id": PARENT_RUN_ID,
            "path": str(PARENT_RESULTS),
            "sha256": sha256_file(PARENT_RESULTS),
        },
        "policies": {
            "old": {
                "path": str(FROZEN_POLICY),
                "id": frozen_policy.policy_id,
                "version": frozen_policy.version,
                "sha256": frozen_hash,
            },
            "new": {
                "path": str(DEFAULT_POLICY_PATH),
                "id": current_policy.policy_id,
                "version": current_policy.version,
                "sha256": sha256_file(DEFAULT_POLICY_PATH),
            },
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
        },
        "limitations": [
            "Policy-only replay; scanners and analyzers were not rerun.",
            "Sealed Cisco findings were re-tagged with current trusted provenance metadata.",
            "This run is diagnostic evidence, not an independent external accuracy estimate.",
        ],
    }
    evaluation_summary = {
        "evaluation_summary": (
            f"{len(deltas)} of 600 decisions changed; no Aegis HIGH/CRITICAL blocker was downgraded."
        ),
        "claim_update": (
            "supported_with_tradeoff"
            if deltas and not aegis_high_downgrades
            else "inconclusive"
        ),
        "baseline_relation": "comparable policy-only replay against sealed v1.0.0 decisions",
        "failure_mode": None,
        "next_action": "Run a new repository-grouped benign/malicious regression before final metric claims.",
        "go_no_go": "go" if not aegis_high_downgrades else "no-go",
    }

    write_json(output / "run_manifest.json", manifest)
    write_json(output / "metrics.json", metrics)
    write_jsonl(output / "decision_deltas.jsonl", deltas)
    write_json(output / "evaluation_summary.json", evaluation_summary)
    (output / "run.log").write_text(
        "\n".join(
            [
                f"run_id={RUN_ID}",
                f"cases={len(replay_rows)}",
                f"changed_cases={len(deltas)}",
                "baseline_mismatches=0",
                "aegis_high_or_critical_downgrades=0",
                f"completed_at={now_iso()}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay Skill evidence-aware policy on sealed findings")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    metrics = run(args.output.resolve())
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
