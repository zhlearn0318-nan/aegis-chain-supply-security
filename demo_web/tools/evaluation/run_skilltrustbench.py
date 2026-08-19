from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
import platform
import shlex
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.adapters import ProcessRunner, SkillScannerAdapter  # noqa: E402
from backend.normalizers import normalize_skill  # noqa: E402
from backend.policy import evaluate_findings, load_policy, summarize  # noqa: E402
from tools.datasets.prepare_skilltrustbench import tree_sha256  # noqa: E402


RUN_ID = "2026-08-10-skilltrustbench-smoke5"
PILOT_RUN_ID = "2026-08-10-skilltrustbench-pilot90-v1"
OFFICIAL_RUN_ID = "2026-08-14-skilltrustbench-official10pct-cisco-v1"
FULL_RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
DATASET_REVISION = "762d5388b3a047b26df9679582af868a0e5b2c8f"
PILOT_IDS_SHA256 = "59dd01a97225b9efef24fa0a7a7a0213fd7e36614b71f5adb7522d16fa518800"
OFFICIAL_RESULTS_REVISION = "326ec286d082199cb270b25b8b4fc93c8762281e"
OFFICIAL_SUBSET_FILE_SHA256 = "dff7621ffcc7a42f1a8ff64c8e47d2fafc1cd332431fd533be88bb684aaa6843"
OFFICIAL_IDS_SHA256 = "903a036e4b7b16ee28e22d5d9db57a00b3764cfe41e43144acad67921e5196c2"
OFFICIAL_COUNTS = {"normal": 166, "suspicious": 105, "malicious": 285}
FULL_IDS_SHA256 = "99ed464424ef589d76d28f5762fd88dc0b62bd96dc88dfcd9a5b867add9ab4a1"
FULL_COUNTS = {"normal": 1643, "suspicious": 1014, "malicious": 2863}
FULL_GROUND_TRUTH_SHA256 = "46009af2edd1119901d4e0a1e139f5bf555c769b28b1a2fe2235051f6a902660"
FULL_ARCHIVE_SHA256 = "e1d8950ef01c3b24fa80e32101844abc8c5ab3a0a38525427e8b16f00a414ae4"
SMOKE_IDS = (
    "case_00567",
    "case_03729",
    "case_03970",
    "case_01235",
    "case_00019",
)
CLASSES = ("normal", "suspicious", "malicious")
PREDICTIONS = (*CLASSES, "abstain")
DECISION_TO_LABEL = {
    "ALLOW": "normal",
    "REVIEW": "suspicious",
    "BLOCK": "malicious",
    "UNKNOWN": "abstain",
}
ALLOWED_ANALYZERS = {"static_analyzer", "bytecode", "pipeline"}
EXTERNAL_ANALYZER_TOKENS = {"llm", "virustotal", "aidefense", "behavioral"}


class EvaluationError(RuntimeError):
    """Raised when the frozen evaluation contract cannot be trusted."""


class SafetyBoundaryError(EvaluationError):
    """Raised when a scanner crosses the frozen local-static boundary."""


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def case_ids_sha256(records: list[dict[str, Any]]) -> str:
    text = "".join(f"{case_id}\n" for case_id in sorted(str(row["id"]) for row in records))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    os.replace(temporary, path)


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvaluationError(f"Expected JSON object: {path}")
    return payload


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise EvaluationError(f"Expected JSON object at {path}:{line_number}")
        records.append(payload)
    return records


def select_records(records: list[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    by_id = {str(record.get("id")): record for record in records}
    if len(by_id) != len(records):
        raise EvaluationError("Evaluation manifest contains duplicate case IDs")
    selected_ids = list(SMOKE_IDS) if mode == "smoke" else [str(record["id"]) for record in records]
    missing = [case_id for case_id in selected_ids if case_id not in by_id]
    if missing:
        raise EvaluationError(f"Frozen case IDs missing from evaluation manifest: {missing}")
    return [by_id[case_id] for case_id in selected_ids]


def is_read_only(path: Path) -> bool:
    if os.name != "nt":
        return not os.access(path, os.W_OK)
    attributes = getattr(path.stat(), "st_file_attributes", 0)
    read_only_flag = getattr(__import__("stat"), "FILE_ATTRIBUTE_READONLY", 1)
    return bool(attributes & read_only_flag)


def verify_case(
    case_root: Path,
    record: dict[str, Any],
    expected_root: Path | None = None,
) -> str:
    expected_root = expected_root or (
        REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "pilot" / "cases"
    ).resolve()
    expected_root = expected_root.resolve()
    resolved = case_root.resolve()
    if expected_root not in resolved.parents:
        raise EvaluationError(f"Case path escaped frozen pilot root: {record['id']}")
    files = [path for path in resolved.rglob("*") if path.is_file()]
    if record.get("scanner_eligible") is False:
        if files and any(not is_read_only(path) for path in files):
            raise SafetyBoundaryError(f"Scanner-ineligible case has a writable residual file: {record['id']}")
        expected = str(record.get("case_tree_sha256") or "")
        if not expected:
            raise EvaluationError(f"Archive-only case hash is missing: {record['id']}")
        return expected
    if not (resolved / "SKILL.md").is_file():
        raise EvaluationError(f"SKILL.md is missing: {record['id']}")
    if not files or any(not is_read_only(path) for path in files):
        raise SafetyBoundaryError(f"Case files are not all read-only: {record['id']}")
    actual = tree_sha256(resolved)
    if actual != record.get("case_tree_sha256"):
        raise EvaluationError(f"Case tree hash mismatch before scan: {record['id']}")
    return actual


def sanitize_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    for finding in findings:
        location = finding.get("location") or {}
        safe_location = {
            key: location.get(key)
            for key in ("file", "line", "object", "type")
            if location.get(key) is not None
        }
        safe.append({
            "id": finding.get("id"),
            "rule_id": finding.get("rule_id"),
            "category": finding.get("category"),
            "severity": finding.get("severity"),
            "analyzer": finding.get("analyzer"),
            "location": safe_location,
        })
    return safe


def validate_analyzers(analyzers: list[str]) -> None:
    normalized = {str(analyzer).lower() for analyzer in analyzers}
    if not normalized:
        raise EvaluationError("Skill Scanner did not report analyzers_used")
    if not normalized <= ALLOWED_ANALYZERS:
        raise SafetyBoundaryError(f"Unexpected analyzer set: {sorted(normalized)}")
    if any(token in analyzer for analyzer in normalized for token in EXTERNAL_ANALYZER_TOKENS):
        raise SafetyBoundaryError(f"External or behavioral analyzer detected: {sorted(normalized)}")


def confusion_matrix(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    matrix = {truth: {prediction: 0 for prediction in PREDICTIONS} for truth in CLASSES}
    for record in records:
        truth = str(record["ground_truth"])
        prediction = str(record["predicted_label"])
        matrix[truth][prediction] += 1
    return matrix


def class_f1(records: list[dict[str, Any]], label: str) -> float:
    tp = sum(row["ground_truth"] == label and row["predicted_label"] == label for row in records)
    fp = sum(row["ground_truth"] != label and row["predicted_label"] == label for row in records)
    fn = sum(row["ground_truth"] == label and row["predicted_label"] != label for row in records)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def nearest_rank(values: list[int], percentile: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def compute_metrics(records: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    total = len(records)
    abstentions = sum(row["predicted_label"] == "abstain" for row in records)
    covered = [row for row in records if row["predicted_label"] != "abstain"]
    malicious = [row for row in records if row["ground_truth"] == "malicious"]
    non_normal = [row for row in records if row["ground_truth"] != "normal"]
    normal = [row for row in records if row["ground_truth"] == "normal"]
    latencies = [int(row["duration_ms"]) for row in records]

    malicious_recall = (
        sum(row["predicted_label"] == "malicious" for row in malicious) / len(malicious)
        if malicious else 0.0
    )
    non_normal_recall = (
        sum(row["predicted_label"] in {"suspicious", "malicious"} for row in non_normal) / len(non_normal)
        if non_normal else 0.0
    )
    normal_fpr = (
        sum(row["predicted_label"] in {"suspicious", "malicious"} for row in normal) / len(normal)
        if normal else 0.0
    )
    per_label: dict[str, dict[str, int | float | None]] = {}
    for label in (f"T{index:02d}" for index in range(1, 10)):
        matching = [row for row in records if label in (row.get("risk_labels") or [])]
        detected = sum(row["predicted_label"] in {"suspicious", "malicious"} for row in matching)
        per_label[label] = {
            "support": len(matching),
            "detected": detected,
            "recall": detected / len(matching) if matching else None,
        }

    strict_macro = statistics.fmean(class_f1(records, label) for label in CLASSES) if records else 0.0
    covered_macro = statistics.fmean(class_f1(covered, label) for label in CLASSES) if covered else 0.0
    binary_tp = sum(
        row["ground_truth"] != "normal"
        and row["predicted_label"] in {"suspicious", "malicious"}
        for row in records
    )
    binary_fp = sum(
        row["ground_truth"] == "normal"
        and row["predicted_label"] in {"suspicious", "malicious"}
        for row in records
    )
    binary_fn = sum(
        row["ground_truth"] != "normal"
        and row["predicted_label"] not in {"suspicious", "malicious"}
        for row in records
    )
    binary_tn = sum(
        row["ground_truth"] == "normal" and row["predicted_label"] == "normal"
        for row in records
    )
    binary_precision = binary_tp / (binary_tp + binary_fp) if binary_tp + binary_fp else 0.0
    binary_recall = binary_tp / (binary_tp + binary_fn) if binary_tp + binary_fn else 0.0
    binary_f1 = (
        2 * binary_precision * binary_recall / (binary_precision + binary_recall)
        if binary_precision + binary_recall else 0.0
    )
    scope = {
        "smoke": "smoke_diagnostics",
        "pilot": "pilot90_main_test",
        "official10": "official_fixed_10pct_robustness",
        "full": "full_dataset_evaluation",
    }[mode]
    return {
        "schema_version": "1.0",
        "scope": scope,
        "cases": total,
        "coverage": len(covered) / total if total else 0.0,
        "failure_rate": abstentions / total if total else 0.0,
        "abstention_count": abstentions,
        "strict_macro_f1": strict_macro,
        "covered_macro_f1": covered_macro,
        "malicious_recall": malicious_recall,
        "malicious_fnr": 1.0 - malicious_recall,
        "non_normal_recall": non_normal_recall,
        "normal_fpr": normal_fpr,
        "supplementary_accuracy": (
            sum(row["ground_truth"] == row["predicted_label"] for row in records) / total
            if total else 0.0
        ),
        "aegis_policy_loose_non_normal": {
            "mapping": "truth malicious/suspicious=positive; prediction BLOCK/REVIEW=positive",
            "not_equivalent_to_official_cisco_actual_safe": True,
            "tp": binary_tp,
            "fp": binary_fp,
            "fn": binary_fn,
            "tn": binary_tn,
            "abstention_count": abstentions,
            "precision": binary_precision,
            "recall": binary_recall,
            "loose_f1": binary_f1,
            "fpr": binary_fp / len(normal) if normal else 0.0,
        },
        "per_risk_label_recall": per_label,
        "latency_median_ms": statistics.median(latencies) if latencies else 0,
        "latency_p95_ms": nearest_rank(latencies, 0.95),
        "latency_max_ms": max(latencies, default=0),
        "confusion_matrix": confusion_matrix(records),
        "warning": "Smoke metrics validate wiring only and must not be used as a performance claim."
        if mode == "smoke" else None,
    }


def error_slices(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return {
        "false_positives": [
            row for row in records
            if row["ground_truth"] == "normal"
            and row["predicted_label"] in {"suspicious", "malicious"}
        ],
        "false_negatives": [
            row for row in records
            if row["ground_truth"] == "malicious"
            and row["predicted_label"] != "malicious"
        ],
        "classification_errors": [
            row for row in records
            if row["ground_truth"] != row["predicted_label"]
        ],
    }


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        for record in records:
            output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(temporary, path)


def preflight(mode: str) -> dict[str, Any]:
    data_root = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0"
    baseline_root = DEMO_ROOT / "baseline" / "skilltrustbench_v1_0"
    metric_contract_path = baseline_root / "json" / "metric_contract.json"
    if mode in {"smoke", "pilot"}:
        intake_path = data_root / "intake_manifest.json"
        manifest_path = data_root / "pilot" / "pilot_manifest.jsonl"
        verification_path = baseline_root / "verification.json"
        pilot_ids_path = baseline_root / "pilot_case_ids.txt"
        intake = load_json(intake_path)
        verification = load_json(verification_path)
        if intake.get("content_revision") != DATASET_REVISION:
            raise EvaluationError("Dataset revision differs from the frozen baseline")
        if intake.get("pilot", {}).get("case_ids_sha256") != PILOT_IDS_SHA256:
            raise EvaluationError("Pilot ID hash differs from the frozen baseline")
        if sha256_file(pilot_ids_path) != PILOT_IDS_SHA256:
            raise EvaluationError("Committed pilot ID list hash differs from the frozen baseline")
        if sha256_file(manifest_path) != verification["pilot"]["pilot_manifest_sha256"]:
            raise EvaluationError("Pilot manifest hash differs from the verified baseline")
        records = load_jsonl(manifest_path)
        committed_ids = pilot_ids_path.read_text(encoding="utf-8").splitlines()
        if [str(record["id"]) for record in records] != committed_ids:
            raise EvaluationError("Pilot manifest order differs from the committed ID list")
        selected = select_records(records, mode)
        cases_root = data_root / "pilot" / "cases"
        selection_hash = PILOT_IDS_SHA256
        dataset_metadata = {
            "repository": "cuhk-zhuque/SkillTrustBench",
            "revision": DATASET_REVISION,
            "evaluation_scope": "smoke5" if mode == "smoke" else "balanced_pilot90",
            "case_ids_sha256": selection_hash,
            "source_manifest_sha256": sha256_file(manifest_path),
            "selected_case_ids": [record["id"] for record in selected],
        }
    elif mode == "official10":
        official_root = data_root / "official_10pct"
        intake_path = official_root / "intake_manifest.json"
        manifest_path = official_root / "official_subset_manifest.jsonl"
        subset_path = official_root / "evaluation_subset_10pct.jsonl"
        ids_path = official_root / "official_case_ids.txt"
        intake = load_json(intake_path)
        if intake.get("dataset_content_revision") != DATASET_REVISION:
            raise EvaluationError("Official subset dataset revision differs from the frozen contract")
        if intake.get("results_revision") != OFFICIAL_RESULTS_REVISION:
            raise EvaluationError("Official results repository revision differs from the frozen contract")
        identity = intake.get("source_identity", {})
        official = intake.get("official_subset", {})
        if identity.get("subset_file_sha256") != OFFICIAL_SUBSET_FILE_SHA256:
            raise EvaluationError("Official subset file identity differs from the frozen contract")
        if sha256_file(subset_path) != OFFICIAL_SUBSET_FILE_SHA256:
            raise EvaluationError("Official subset file hash differs from the frozen contract")
        if official.get("computed_sorted_newline_case_ids_sha256") != OFFICIAL_IDS_SHA256:
            raise EvaluationError("Official subset ID hash differs from the frozen contract")
        if official.get("published_subset_case_ids_sha256") != OFFICIAL_IDS_SHA256:
            raise EvaluationError("Published official subset ID hash differs from the frozen contract")
        if official.get("published_hash_matches_current_file") is not True:
            raise EvaluationError("Official subset published/computed hashes do not match")
        if sha256_file(manifest_path) != official.get("manifest_sha256"):
            raise EvaluationError("Official subset manifest hash differs from intake evidence")
        records = load_jsonl(manifest_path)
        counts = dict(sorted(Counter(str(row.get("judgment")) for row in records).items()))
        if len(records) != 556 or counts != OFFICIAL_COUNTS:
            raise EvaluationError(f"Official subset size or label distribution changed: {len(records)}, {counts}")
        if case_ids_sha256(records) != OFFICIAL_IDS_SHA256:
            raise EvaluationError("Official subset manifest IDs differ from the fixed case list")
        if sha256_file(ids_path) != OFFICIAL_IDS_SHA256:
            raise EvaluationError("Official subset ID file differs from the fixed case list")
        selected = select_records(records, mode)
        cases_root = official_root / "cases"
        selection_hash = OFFICIAL_IDS_SHA256
        dataset_metadata = {
            "repository": "cuhk-zhuque/SkillTrustBench",
            "revision": DATASET_REVISION,
            "results_repository": "cuhk-zhuque/SkillTrustBench-results",
            "results_revision": OFFICIAL_RESULTS_REVISION,
            "evaluation_scope": "fixed_10pct_subset",
            "subset_file_sha256": OFFICIAL_SUBSET_FILE_SHA256,
            "case_ids_sha256": selection_hash,
            "source_manifest_sha256": sha256_file(manifest_path),
            "selected_case_ids": [record["id"] for record in selected],
            "scanner_eligible_cases": sum(row.get("scanner_eligible") is not False for row in selected),
            "endpoint_protection_blocked_cases": sum(row.get("scanner_eligible") is False for row in selected),
        }
    else:
        full_root = data_root / "full"
        intake_path = full_root / "intake_manifest.json"
        manifest_path = full_root / "full_manifest.jsonl"
        ids_path = full_root / "full_case_ids.txt"
        ground_truth_path = data_root / "raw" / "benchmark_full_v1.0" / "ground_truth.json"
        archive_path = data_root / "raw" / "benchmark_full_v1.0.zip"
        intake = load_json(intake_path)
        if intake.get("dataset_content_revision") != DATASET_REVISION:
            raise EvaluationError("Full dataset revision differs from the frozen contract")
        identity = intake.get("source_identity", {})
        full = intake.get("full_dataset", {})
        if identity.get("ground_truth_sha256") != FULL_GROUND_TRUTH_SHA256:
            raise EvaluationError("Full ground-truth identity differs from the frozen contract")
        if identity.get("archive_sha256") != FULL_ARCHIVE_SHA256:
            raise EvaluationError("Full archive identity differs from the frozen contract")
        if sha256_file(ground_truth_path) != FULL_GROUND_TRUTH_SHA256:
            raise EvaluationError("Full ground-truth file hash differs from the frozen contract")
        if sha256_file(archive_path) != FULL_ARCHIVE_SHA256:
            raise EvaluationError("Full archive file hash differs from the frozen contract")
        if full.get("case_ids_sha256") != FULL_IDS_SHA256:
            raise EvaluationError("Full dataset ID hash differs from the frozen contract")
        if sha256_file(manifest_path) != full.get("manifest_sha256"):
            raise EvaluationError("Full manifest hash differs from intake evidence")
        records = load_jsonl(manifest_path)
        counts = dict(sorted(Counter(str(row.get("judgment")) for row in records).items()))
        if len(records) != 5520 or counts != FULL_COUNTS:
            raise EvaluationError(f"Full dataset size or label distribution changed: {len(records)}, {counts}")
        if case_ids_sha256(records) != FULL_IDS_SHA256:
            raise EvaluationError("Full manifest IDs differ from the frozen case list")
        if sha256_file(ids_path) != FULL_IDS_SHA256:
            raise EvaluationError("Full ID file differs from the frozen case list")
        selected = select_records(records, mode)
        cases_root = full_root / "cases"
        selection_hash = FULL_IDS_SHA256
        dataset_metadata = {
            "repository": "cuhk-zhuque/SkillTrustBench",
            "revision": DATASET_REVISION,
            "evaluation_scope": "full_dataset_v1.0",
            "ground_truth_sha256": FULL_GROUND_TRUTH_SHA256,
            "archive_sha256": FULL_ARCHIVE_SHA256,
            "case_ids_sha256": selection_hash,
            "source_manifest_sha256": sha256_file(manifest_path),
            "selected_case_ids": [record["id"] for record in selected],
            "scanner_eligible_cases": sum(row.get("scanner_eligible") is not False for row in selected),
            "scanner_ineligible_cases": sum(row.get("scanner_eligible") is False for row in selected),
            "scanner_ineligible_reasons": dict(sorted(Counter(
                str(row.get("local_read_status"))
                for row in selected if row.get("scanner_eligible") is False
            ).items())),
        }
    return {
        "data_root": data_root,
        "baseline_root": baseline_root,
        "metric_contract_path": metric_contract_path,
        "source_manifest_path": manifest_path,
        "cases_root": cases_root,
        "case_ids_sha256": selection_hash,
        "dataset_metadata": dataset_metadata,
        "selected": selected,
        "intake": intake,
    }


def scan_case(
    adapter: SkillScannerAdapter,
    record: dict[str, Any],
    data_root: Path,
    cases_root: Path,
    run_id: str,
    policy,
    log,
) -> dict[str, Any]:
    case_id = str(record["id"])
    case_root = (data_root / str(record["local_path"])).resolve()
    before_hash = verify_case(case_root, record, cases_root)
    started = time.perf_counter()
    log(f"case_start id={case_id} truth={record['judgment']}")
    if record.get("scanner_eligible") is False:
        findings = []
        analyzers = []
        status = "failed"
        decision = "UNKNOWN"
        unavailable_status = str(record.get("local_read_status") or "scanner_ineligible")
        if unavailable_status == "blocked_by_platform_path_incompatibility":
            error_type = "PlatformPathIncompatible"
            rule_id = "PLATFORM_PATH_INCOMPATIBLE"
            reason = "样本包含当前 Windows 文件系统无法安全还原的路径；不改写样本，按失败闭锁策略记为 UNKNOWN。"
        else:
            error_type = "EndpointProtectionBlocked"
            rule_id = "ENDPOINT_PROTECTION_BLOCKED"
            reason = "端点防护阻止本地读取样本；按失败闭锁策略记为 UNKNOWN，不绕过系统防护。"
        policy_trace = {
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "rule_id": rule_id,
            "reason": reason,
            "matched_severities": [],
            "matched_finding_ids": [],
            "fail_closed": True,
        }
        error = {
            "type": error_type,
            "message": "The sample was not locally scannable under the frozen safety boundary; Cisco scan was not invoked.",
        }
        log(f"case_blocked id={case_id} reason={unavailable_status} scanner_invoked=false")
    else:
        try:
            execution = adapter.scan(case_root)
            findings, analyzers = normalize_skill(execution.report)
            validate_analyzers(analyzers)
            evaluation = evaluate_findings(findings, policy)
            status = "completed"
            decision = evaluation.decision.value
            policy_trace = evaluation.trace.model_dump(mode="json")
            error = None
        except SafetyBoundaryError:
            raise
        except Exception as exc:
            findings = []
            analyzers = []
            status = "failed"
            decision = "UNKNOWN"
            policy_trace = {
                "policy_id": policy.policy_id,
                "policy_version": policy.version,
                "rule_id": "SCAN_EXECUTION_FAILED",
                "reason": "扫描器执行或结果归一化失败；按失败闭锁策略记为 UNKNOWN。",
                "matched_severities": [],
                "matched_finding_ids": [],
                "fail_closed": True,
            }
            error = {
                "type": type(exc).__name__,
                "message": "Raw scanner error omitted to avoid propagating untrusted sample content.",
            }
    duration_ms = max(1, round((time.perf_counter() - started) * 1000))
    after_hash = verify_case(case_root, record, cases_root)
    if after_hash != before_hash:
        raise SafetyBoundaryError(f"Sample tree changed during scan: {case_id}")
    predicted_label = DECISION_TO_LABEL[decision]
    result = {
        "schema_version": "1.0",
        "run_id": run_id,
        "case_id": case_id,
        "ground_truth": record["judgment"],
        "risk_labels": record.get("risk_labels") or [],
        "source": record.get("source"),
        "base_category": record.get("base_category"),
        "case_tree_sha256_before": before_hash,
        "case_tree_sha256_after": after_hash,
        "hash_verification": (
            "archive_identity_only_scanner_ineligible"
            if record.get("scanner_eligible") is False
            else "filesystem_content_before_and_after"
        ),
        "status": status,
        "decision": decision,
        "predicted_label": predicted_label,
        "duration_ms": duration_ms,
        "analyzers": analyzers,
        "summary": summarize(findings),
        "policy_trace": policy_trace,
        "finding_index": sanitize_findings(findings),
        "error": error,
    }
    log(
        f"case_end id={case_id} status={status} decision={decision} "
        f"findings={len(findings)} duration_ms={duration_ms} hash_unchanged=true"
    )
    return result


def scanner_version(runner: ProcessRunner, scanner: Path) -> str:
    completed = runner.run([str(scanner), "--version"])
    if completed.returncode != 0:
        raise EvaluationError("Unable to query Skill Scanner version")
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return text[0] if text else "unknown"


def validate_resume_prefix(
    results: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    run_id: str,
) -> None:
    if len(results) > len(selected):
        raise EvaluationError("Resume results contain more cases than the frozen selection")
    expected_ids = [str(row["id"]) for row in selected[:len(results)]]
    actual_ids = [str(row.get("case_id")) for row in results]
    if actual_ids != expected_ids:
        raise EvaluationError("Resume results are not an exact prefix of the frozen case order")
    if any(row.get("run_id") != run_id for row in results):
        raise EvaluationError("Resume results contain a different run ID")


def run(
    mode: str,
    output_dir: Path,
    timeout_seconds: int,
    resume: bool = False,
    workers: int = 1,
) -> int:
    if not 1 <= workers <= 8:
        raise EvaluationError("Parallel workers must be between 1 and 8")
    segment_started_at = now_iso()
    segment_started = time.perf_counter()
    context = preflight(mode)
    output_dir = output_dir.resolve()
    data_root = context["data_root"].resolve()
    cases_root = context["cases_root"].resolve()
    if output_dir == data_root or data_root in output_dir.parents:
        raise EvaluationError("Experiment output must not be written inside the dataset root")
    protected_outputs = [
        "run_manifest.json", "per_case_results.jsonl", "metrics.json",
        "confusion_matrix.json", "false_positive_cases.jsonl",
        "false_negative_cases.jsonl", "classification_errors.jsonl",
        "run.log", "evaluation_summary.json",
    ]
    existing_outputs = [name for name in protected_outputs if (output_dir / name).exists()]
    if existing_outputs and not resume:
        raise EvaluationError("Output directory already contains a run; use a new directory or --resume")
    if resume and not all((output_dir / name).is_file() for name in ("run_manifest.json", "per_case_results.jsonl")):
        raise EvaluationError("Resume requires run_manifest.json and per_case_results.jsonl")
    output_dir.mkdir(parents=True, exist_ok=True)

    scanner = REPRODUCTION_ROOT / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
    if not scanner.is_file():
        raise EvaluationError(f"Skill Scanner is unavailable: {scanner}")
    runner = ProcessRunner(
        timeout_seconds=timeout_seconds,
        cache_root=DEMO_ROOT / "data" / "cache" / "skilltrustbench",
        extra_path=scanner.parent,
    )
    version = scanner_version(runner, scanner)
    adapter = SkillScannerAdapter(scanner=scanner, runner=runner)
    policy = load_policy()
    policy_path = DEMO_ROOT / "config" / "admission_policy.yaml"
    metric_contract_path = context["metric_contract_path"]
    selected = context["selected"]
    run_id = {
        "smoke": RUN_ID,
        "pilot": PILOT_RUN_ID,
        "official10": OFFICIAL_RUN_ID,
        "full": FULL_RUN_ID,
    }[mode]
    command_argv = [sys.executable, *sys.argv]
    command_record = {
        "at": now_iso(),
        "argv": command_argv,
        "display": " ".join(shlex.quote(part) for part in command_argv),
        "resume": resume,
    }
    experiment_tier = {
        "smoke": "auxiliary/dev",
        "pilot": "main/test",
        "official10": "supporting/robustness",
        "full": "claim-carrying/full-evaluation",
    }[mode]
    claim_boundary = {
        "smoke": "Smoke run validates engineering wiring only; no performance claim.",
        "pilot": "Balanced pilot90 is a descriptive local baseline, not a market-prevalence estimate.",
        "official10": (
            "Fixed official 10% subset; Aegis policy labels and loose metrics are not equivalent "
            "to the official Cisco actual_safe leaderboard mapping."
        ),
        "full": (
            "Complete audited SkillTrustBench v1.0 dataset; results describe the frozen local "
            "Cisco-plus-policy configuration and are not an official leaderboard reproduction."
        ),
    }[mode]
    expected_manifest = {
        "schema_version": "1.1",
        "run_id": run_id,
        "status": "running",
        "experiment_tier": experiment_tier,
        "mode": mode,
        "started_at": now_iso(),
        "command_history": [command_record],
        "dataset": context["dataset_metadata"],
        "scanner": {
            "name": "Cisco Skill Scanner",
            "version_output": version,
            "executable_sha256": sha256_file(scanner),
            "command_template": [
                str(scanner), "scan", "<case_dir>", "--format", "json",
                "--output-json", "<temporary_output>", "--compact",
            ],
            "allowed_analyzers": sorted(ALLOWED_ANALYZERS),
            "optional_flags_enabled": [],
            "timeout_seconds_per_case": timeout_seconds,
            "parallel_workers": workers,
        },
        "policy": {
            "id": policy.policy_id,
            "version": policy.version,
            "sha256": sha256_file(policy_path),
        },
        "metric_contract": {
            "path": str(metric_contract_path.relative_to(DEMO_ROOT)),
            "sha256": sha256_file(metric_contract_path),
            "primary_metric": "strict_macro_f1",
            "supplementary_metric": "aegis_policy_loose_non_normal",
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "sequential": workers == 1,
            "parallel_workers": workers,
            "sample_execution": False,
            "sample_import": False,
            "sample_install": False,
            "cloud_upload": False,
            "raw_scanner_reports_retained": False,
            "endpoint_protection_bypass": False,
        },
        "claim_boundary": claim_boundary,
    }

    results: list[dict[str, Any]] = []
    if resume:
        manifest = load_json(output_dir / "run_manifest.json")
        for key in ("run_id", "mode"):
            if manifest.get(key) != expected_manifest[key]:
                raise EvaluationError(f"Resume manifest {key} differs from the frozen run")
        if manifest.get("status") == "completed":
            raise EvaluationError("Completed run must not be resumed")
        for section in ("dataset", "scanner", "policy", "metric_contract"):
            if manifest.get(section) != expected_manifest[section]:
                raise EvaluationError(f"Resume manifest {section} contract differs from the current preflight")
        results = load_jsonl(output_dir / "per_case_results.jsonl")
        validate_resume_prefix(results, selected, run_id)
        if len(results) == len(selected):
            raise EvaluationError("Resume run already contains all frozen cases")
        for record, prior in zip(selected, results):
            current_hash = verify_case(
                (data_root / str(record["local_path"])).resolve(), record, cases_root
            )
            if prior.get("case_tree_sha256_before") != current_hash or prior.get("case_tree_sha256_after") != current_hash:
                raise EvaluationError(f"Resume case hash differs from prior result: {record['id']}")
        manifest["status"] = "running"
        manifest.pop("completed_at", None)
        manifest.pop("outputs", None)
        manifest["command_history"] = [*manifest.get("command_history", []), command_record]
        manifest.setdefault("resume_history", []).append({
            "at": command_record["at"],
            "verified_prefix_cases": len(results),
        })
    else:
        manifest = expected_manifest
    write_json(output_dir / "run_manifest.json", manifest)

    log_path = output_dir / "run.log"
    log_mode = "a" if resume else "w"
    result_mode = "a" if resume else "w"
    fatal_error: str | None = None
    with log_path.open(log_mode, encoding="utf-8", newline="\n") as log_output:
        log_lock = threading.Lock()

        def log(message: str) -> None:
            with log_lock:
                log_output.write(f"{now_iso()} {message}\n")
                log_output.flush()

        log(
            f"{'run_resume' if resume else 'run_start'} id={run_id} mode={mode} "
            f"completed_prefix={len(results)} cases={len(selected)}"
        )
        per_case_path = output_dir / "per_case_results.jsonl"
        segment_start_count = len(results)
        remaining = selected[segment_start_count:]
        with per_case_path.open(result_mode, encoding="utf-8", newline="\n") as output:
            if workers == 1:
                batches = ([record] for record in remaining)
            else:
                batches = (
                    remaining[index:index + workers]
                    for index in range(0, len(remaining), workers)
                )
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="skill-scan") as executor:
                for batch in batches:
                    futures = [
                        executor.submit(
                            scan_case, adapter, record, data_root, cases_root, run_id, policy, log
                        )
                        for record in batch
                    ]
                    for record, future in zip(batch, futures):
                        try:
                            result = future.result()
                        except SafetyBoundaryError as exc:
                            fatal_error = str(exc)
                            log(f"safety_stop type={type(exc).__name__} case={record['id']}")
                            break
                        results.append(result)
                        output.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
                        output.flush()
                    if fatal_error:
                        break

        segment_wall_seconds = round(time.perf_counter() - segment_started, 3)
        segment_processed = len(results) - segment_start_count
        manifest.setdefault("execution_segments", []).append({
            "started_at": segment_started_at,
            "completed_at": now_iso(),
            "workers": workers,
            "starting_case_count": segment_start_count,
            "processed_cases": segment_processed,
            "wall_seconds": segment_wall_seconds,
        })
        active_wall_seconds = round(sum(
            float(segment.get("wall_seconds", 0))
            for segment in manifest["execution_segments"]
        ), 3)

        metrics = compute_metrics(results, mode)
        metrics["execution"] = {
            "parallel_workers": workers,
            "active_wall_seconds": active_wall_seconds,
            "throughput_cases_per_second": (
                len(results) / active_wall_seconds if active_wall_seconds else 0.0
            ),
            "throughput_cases_per_minute": (
                len(results) * 60 / active_wall_seconds if active_wall_seconds else 0.0
            ),
        }
        write_json(output_dir / "metrics.json", metrics)
        write_json(output_dir / "confusion_matrix.json", {
            "schema_version": "1.0",
            "labels": list(PREDICTIONS),
            "matrix": metrics["confusion_matrix"],
        })
        slices = error_slices(results)
        write_jsonl(output_dir / "false_positive_cases.jsonl", slices["false_positives"])
        write_jsonl(output_dir / "false_negative_cases.jsonl", slices["false_negatives"])
        write_jsonl(output_dir / "classification_errors.jsonl", slices["classification_errors"])
        all_processed = len(results) == len(selected)
        all_completed = all_processed and all(result["status"] == "completed" for result in results)
        if fatal_error or not all_processed:
            final_status = "partial"
            verdict = "inconclusive"
        elif all_completed:
            final_status = "completed"
            verdict = "supported"
        else:
            final_status = "completed_with_abstentions"
            verdict = "supported_with_caveats"
        abstention_types = dict(sorted(Counter(
            str(row.get("error", {}).get("type"))
            for row in results if row.get("status") != "completed" and row.get("error")
        ).items()))
        evaluation_summary = {
            "takeaway": (
                f"{len(results)}/{len(selected)} fixed cases were processed; "
                f"failure_rate={metrics['failure_rate']:.3f}; no scanner-eligible sample hash changed."
            ),
            "claim_update": "robustness_evidence" if mode == "official10" else "neutral",
            "baseline_relation": (
                "follow_up_to_pilot90_with_distribution_shift"
                if mode == "official10" else "not_comparable"
            ),
            "comparability": "limited_by_sample_distribution" if mode == "official10" else ("low" if mode == "smoke" else "high"),
            "failure_mode": "none" if all_completed else ("recorded_abstentions" if all_processed else "implementation"),
            "abstention_types": abstention_types,
            "next_action": "analyze_error_slices" if all_processed else "resume_or_revise",
        }
        write_json(output_dir / "evaluation_summary.json", {
            "schema_version": "1.0",
            "run_id": manifest["run_id"],
            "claim_verdict": verdict,
            "fatal_error": fatal_error,
            "evaluation_summary": evaluation_summary,
        })
        log(
            f"run_end status={final_status} processed={len(results)}/{len(selected)} "
            f"failure_rate={metrics['failure_rate']:.6f} verdict={verdict}"
        )
        log_output.flush()
        manifest.update({
            "status": final_status,
            "completed_at": now_iso(),
            "processed_cases": len(results),
            "expected_cases": len(selected),
            "completed_cases": sum(row["status"] == "completed" for row in results),
            "abstention_types": abstention_types,
            "fatal_error": fatal_error,
            "outputs": {
                name: {"sha256": sha256_file(output_dir / name), "bytes": (output_dir / name).stat().st_size}
                for name in (
                    "per_case_results.jsonl", "metrics.json", "confusion_matrix.json",
                    "false_positive_cases.jsonl", "false_negative_cases.jsonl",
                    "classification_errors.jsonl", "evaluation_summary.json", "run.log",
                )
            },
        })
        write_json(output_dir / "run_manifest.json", manifest)
        print(json.dumps({
            "run_id": manifest["run_id"],
            "status": final_status,
            "processed": len(results),
            "expected": len(selected),
            "failure_rate": metrics["failure_rate"],
            "strict_macro_f1": metrics["strict_macro_f1"],
            "loose_f1": metrics["aegis_policy_loose_non_normal"]["loose_f1"],
            "output_dir": str(output_dir),
        }, ensure_ascii=False, indent=2))
        return 0 if all_processed and not fatal_error else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Run frozen SkillTrustBench cases through local Cisco static scanning")
    parser.add_argument("--mode", choices=("smoke", "pilot", "official10", "full"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=150)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be between 1 and 600")
    try:
        return run(
            args.mode,
            args.output_dir,
            args.timeout_seconds,
            resume=args.resume,
            workers=args.workers,
        )
    except (EvaluationError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
