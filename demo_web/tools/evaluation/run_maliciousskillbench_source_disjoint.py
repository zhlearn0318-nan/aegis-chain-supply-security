from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.adapters.process import AdapterResult, ProcessRunner  # noqa: E402
from backend.dynamic_audit.skill_sandbox_multiruntime import run_skill_sandbox_v2  # noqa: E402
from backend.models import Decision  # noqa: E402
from backend.openclaw_install_policy import _apply_required_dynamic_scan  # noqa: E402
from backend.policy import evaluate_findings, load_policy, summarize  # noqa: E402
from backend.runtime_paths import runtime_path_entries  # noqa: E402
from backend.semantic_model import configured_semantic_provider  # noqa: E402
from backend.skill_static_pipeline import run_skill_static_pipeline  # noqa: E402


EXPERIMENT_ID = "2026-08-31-maliciousskillbench-source-disjoint-main-v1"
DEFAULT_DATA_ROOT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_source_disjoint_v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "analysis" / EXPERIMENT_ID
CONFIG_PATH = DEMO_ROOT / "config" / "maliciousskillbench_source_disjoint_eval_v1.json"
CISCO_POLICY_PATH = DEMO_ROOT / "config" / "admission_policy.yaml"
P0_POLICY_PATH = DEMO_ROOT / "config" / "admission_policy.skill-evidence-v1.yaml"
DYNAMIC_CONFIG_PATH = DEMO_ROOT / "config" / "skill_dynamic_sandbox_v2.json"
SKILL_RUNTIME = REPOSITORY_ROOT / ".runtime_skill"
SKILL_SCANNER = SKILL_RUNTIME / "Scripts" / "skill-scanner.exe"
EXPECTED_CASES = 1_384
EXPECTED_LABELS = {"0": 545, "1": 839}
SYSTEMS = ("cisco_only", "cisco_plus_p0", "cisco_plus_p0_p1")


class EvaluationError(RuntimeError):
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
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvaluationError(f"Expected JSON object: {path}")
    return payload


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def sanitized_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for finding in findings:
        location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
        result.append({
            "id": str(finding.get("id") or ""),
            "rule_id": str(finding.get("rule_id") or ""),
            "category": str(finding.get("category") or ""),
            "severity": str(finding.get("severity") or "UNKNOWN"),
            "analyzer": str(finding.get("analyzer") or ""),
            "evidence_source": str(finding.get("evidence_source") or "UNKNOWN"),
            "location": {
                key: location[key]
                for key in ("file", "line", "object", "type")
                if location.get(key) is not None
            },
        })
    return result


def preflight(data_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    config = load_json(CONFIG_PATH)
    intake = load_json(data_root / "intake_manifest.json")
    scan_rows = load_jsonl(data_root / "scan_manifest.jsonl")
    if config.get("experiment_id") != EXPERIMENT_ID or config.get("expected_cases") != EXPECTED_CASES:
        raise EvaluationError("Experiment config identity changed")
    if intake.get("status") != "verified_before_first_scan" or intake.get("cases") != EXPECTED_CASES:
        raise EvaluationError("Dataset intake is not frozen")
    if len(scan_rows) != EXPECTED_CASES or len({row.get("case_id") for row in scan_rows}) != EXPECTED_CASES:
        raise EvaluationError("Label-blind scan manifest size or identity changed")
    forbidden = {"label", "ground_truth", "attack_category_codes", "source_id"}
    if any(forbidden & set(row) for row in scan_rows):
        raise EvaluationError("Ground-truth fields crossed the scan-manifest firewall")
    if any(row.get("case_id") != row.get("benchmark_id", "").lower() for row in scan_rows):
        raise EvaluationError("Case ID normalization drifted")
    for row in scan_rows:
        root = (data_root / str(row["local_path"])).resolve()
        if data_root.resolve() not in root.parents:
            raise EvaluationError(f"Case escaped dataset root: {row['case_id']}")
        skill = root / "SKILL.md"
        if row.get("scan_ready"):
            if not skill.is_file() or skill.is_symlink() or sha256_file(skill) != row["skill_text_sha256"]:
                raise EvaluationError(f"Materialized case drifted: {row['case_id']}")
        elif skill.exists():
            raise EvaluationError(f"Unavailable case unexpectedly has scan content: {row['case_id']}")
    identity = {
        "experiment_id": EXPERIMENT_ID,
        "config_sha256": sha256_file(CONFIG_PATH),
        "intake_manifest_sha256": sha256_file(data_root / "intake_manifest.json"),
        "scan_manifest_sha256": sha256_file(data_root / "scan_manifest.jsonl"),
        "case_ids_sha256": sha256_file(data_root / "case_ids.txt"),
        "cisco_policy_sha256": sha256_file(CISCO_POLICY_PATH),
        "p0_policy_sha256": sha256_file(P0_POLICY_PATH),
        "dynamic_config_sha256": sha256_file(DYNAMIC_CONFIG_PATH),
        "scanner_sha256": sha256_file(SKILL_SCANNER),
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    identity["contract_sha256"] = hashlib.sha256(canonical).hexdigest()
    return scan_rows, identity


def scanner_version() -> str:
    completed = subprocess.run(
        [str(SKILL_SCANNER), "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise EvaluationError("Cisco Skill Scanner version probe failed")
    return (completed.stdout or completed.stderr).strip()


def run_cisco_batch(data_root: Path, output_root: Path, identity: dict[str, Any]) -> dict[str, Any]:
    report_path = output_root / "cisco_batch_report.json"
    receipt_path = output_root / "cisco_batch_receipt.json"
    if report_path.is_file() and receipt_path.is_file():
        receipt = load_json(receipt_path)
        if receipt.get("contract_sha256") != identity["contract_sha256"]:
            raise EvaluationError("Existing Cisco batch report belongs to another contract")
        if sha256_file(report_path) != receipt.get("report_sha256"):
            raise EvaluationError("Existing Cisco batch report drifted")
        return load_json(report_path)

    output_root.mkdir(parents=True, exist_ok=True)
    temporary = output_root / "cisco_batch_report.partial.json"
    runner = ProcessRunner(
        timeout_seconds=600,
        cache_root=output_root / "scanner_cache",
        extra_path=runtime_path_entries(SKILL_RUNTIME),
    )
    started = time.perf_counter()
    completed = runner.run([
        str(SKILL_SCANNER),
        "scan-all",
        str((data_root / "cases").resolve()),
        "--recursive",
        "--format",
        "json",
        "--output-json",
        str(temporary.resolve()),
        "--compact",
    ])
    duration_ms = round((time.perf_counter() - started) * 1000)
    if completed.returncode != 0 or not temporary.is_file():
        raise EvaluationError(f"Cisco batch scan failed: exit={completed.returncode}")
    payload = load_json(temporary)
    results = payload.get("results")
    if not isinstance(results, list):
        raise EvaluationError("Cisco batch report has no results list")
    os.replace(temporary, report_path)
    write_json(receipt_path, {
        "schema_version": "1.0",
        "contract_sha256": identity["contract_sha256"],
        "scanner_version": scanner_version(),
        "report_sha256": sha256_file(report_path),
        "completed_at": now_iso(),
        "duration_ms": duration_ms,
        "results": len(results),
        "stdout_lines": len((completed.stdout or "").splitlines()),
        "stderr_lines": len((completed.stderr or "").splitlines()),
        "raw_console_content_retained": False,
    })
    return payload


def index_cisco_results(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for result in payload.get("results") or []:
        path = str(result.get("skill_path") or "").replace("\\", "/").rstrip("/")
        case_id = path.rsplit("/", 1)[-1].lower()
        if not case_id or case_id in indexed:
            raise EvaluationError(f"Cisco batch result cannot be uniquely indexed: {case_id!r}")
        indexed[case_id] = result
    return indexed


class PrecomputedAdapter:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result

    def scan(self, _skill_path: Path) -> AdapterResult:
        return AdapterResult(
            report={"results": [self.result]},
            logs=[
                "skill-scanner batch result reused: "
                f"findings={len(self.result.get('findings') or [])}"
            ],
        )


class CachedProvider:
    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.cache: dict[str, dict[str, Any]] = {}
        self.calls = 0
        self.cache_hits = 0

    def review(self, features: dict[str, Any]) -> dict[str, Any]:
        key = json.dumps(features, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if key in self.cache:
            self.cache_hits += 1
            return self.cache[key]
        self.calls += 1
        result = self.delegate.review(features)
        self.cache[key] = result
        return result


def unknown_system(reason_code: str) -> dict[str, Any]:
    return {
        "decision": "UNKNOWN",
        "reason_code": reason_code,
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
        "finding_index": [],
        "policy_trace": {"rule_id": reason_code, "fail_closed": True},
    }


def evaluated_system(findings: list[dict[str, Any]], policy: Any) -> dict[str, Any]:
    evaluation = evaluate_findings(findings, policy)
    return {
        "decision": evaluation.decision.value,
        "reason_code": evaluation.trace.rule_id,
        "summary": summarize(findings),
        "finding_index": sanitized_findings(findings),
        "policy_trace": evaluation.trace.model_dump(mode="json"),
    }


def scan_case(
    row: dict[str, Any],
    data_root: Path,
    cisco_index: dict[str, dict[str, Any]],
    cisco_policy: Any,
    p0_policy: Any,
) -> dict[str, Any]:
    started = time.perf_counter()
    case_id = str(row["case_id"])
    base = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "case_id": case_id,
        "benchmark_id": row["benchmark_id"],
        "skill_text_sha256": row["skill_text_sha256"],
        "scan_ready": bool(row.get("scan_ready")),
    }
    if not row.get("scan_ready"):
        system = unknown_system(str(row.get("unavailability_reason") or "MATERIALIZATION_UNAVAILABLE"))
        return {**base, "systems": {name: system for name in SYSTEMS}, "duration_ms": 0, "model_calls": 0, "model_cache_hits": 0, "p1_execution_kind": "not_run"}
    cisco = cisco_index.get(case_id)
    if cisco is None:
        system = unknown_system("CISCO_STRICT_LOAD_SKIPPED")
        return {**base, "systems": {name: system for name in SYSTEMS}, "duration_ms": 0, "model_calls": 0, "model_cache_hits": 0, "p1_execution_kind": "not_run"}

    case_root = (data_root / str(row["local_path"])).resolve()
    before = sha256_file(case_root / "SKILL.md")
    provider = None
    try:
        configured = configured_semantic_provider()
        provider = CachedProvider(configured) if configured is not None else None
    except Exception:
        provider = None
    pipeline = run_skill_static_pipeline(
        case_root,
        PrecomputedAdapter(cisco),
        semantic_provider=provider,
    )
    findings = pipeline["findings"]
    cisco_findings = [
        item for item in findings
        if str(item.get("evidence_source") or "").upper() == "CISCO"
    ]
    cisco_system = evaluated_system(cisco_findings, cisco_policy)
    p0_system = evaluated_system(findings, p0_policy)
    p0_decision = Decision(p0_system["decision"])
    p1_execution_kind = "not_run"
    p1_findings = findings
    p1_decision = p0_decision
    p1_reason = str(p0_system["policy_trace"].get("reason") or "")
    if p0_decision not in {Decision.BLOCK, Decision.UNKNOWN}:
        dynamic_result: dict[str, Any] = {}

        def dynamic_scan(root: Path) -> dict[str, Any]:
            nonlocal dynamic_result
            dynamic_result = run_skill_sandbox_v2(
                DYNAMIC_CONFIG_PATH,
                root,
                semantic_provider=provider,
            )
            return dynamic_result

        p1_decision, p1_reason, p1_findings = _apply_required_dynamic_scan(
            case_root,
            p0_decision,
            p1_reason,
            findings,
            dynamic_scan,
        )
        p1_execution_kind = str(dynamic_result.get("execution_kind") or "unknown")
    p1_system = {
        "decision": p1_decision.value,
        "reason_code": "P1_MONOTONIC_FUSION",
        "summary": summarize(p1_findings),
        "finding_index": sanitized_findings(p1_findings),
        "policy_trace": {
            "policy_id": p0_policy.policy_id,
            "policy_version": p0_policy.version,
            "rule_id": "P1_MONOTONIC_FUSION",
            "reason": p1_reason,
            "fail_closed": True,
        },
    }
    after = sha256_file(case_root / "SKILL.md")
    if before != row["skill_text_sha256"] or after != before:
        raise EvaluationError(f"Case changed during scan: {case_id}")
    return {
        **base,
        "systems": {
            "cisco_only": cisco_system,
            "cisco_plus_p0": p0_system,
            "cisco_plus_p0_p1": p1_system,
        },
        "duration_ms": max(1, round((time.perf_counter() - started) * 1000)),
        "model_calls": provider.calls if provider is not None else 0,
        "model_cache_hits": provider.cache_hits if provider is not None else 0,
        "p1_execution_kind": p1_execution_kind,
    }


def scan(data_root: Path, output_root: Path, workers: int) -> dict[str, Any]:
    rows, identity = preflight(data_root)
    output_root.mkdir(parents=True, exist_ok=True)
    run_manifest_path = output_root / "run_manifest.json"
    if run_manifest_path.exists():
        existing = load_json(run_manifest_path)
        if existing.get("contract_sha256") != identity["contract_sha256"]:
            raise EvaluationError("Output directory contains a different experiment contract")
    else:
        write_json(run_manifest_path, {
            "schema_version": "1.0",
            **identity,
            "status": "scanning",
            "started_at": now_iso(),
            "workers": workers,
            "label_firewall": "ground truth not loaded by scan command",
        })
    cisco_payload = run_cisco_batch(data_root, output_root, identity)
    cisco_index = index_cisco_results(cisco_payload)
    cisco_policy = load_policy(CISCO_POLICY_PATH)
    p0_policy = load_policy(P0_POLICY_PATH)
    shards = output_root / "scan_shards"
    shards.mkdir(exist_ok=True)
    pending: list[dict[str, Any]] = []
    for row in rows:
        shard = shards / f"{row['case_id']}.json"
        if shard.is_file():
            existing = load_json(shard)
            if existing.get("case_id") != row["case_id"] or existing.get("skill_text_sha256") != row["skill_text_sha256"]:
                raise EvaluationError(f"Resume shard identity mismatch: {row['case_id']}")
        else:
            pending.append(row)

    lock = threading.Lock()
    completed = len(rows) - len(pending)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 8))) as executor:
        futures = {
            executor.submit(scan_case, row, data_root, cisco_index, cisco_policy, p0_policy): row
            for row in pending
        }
        for future in as_completed(futures):
            row = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                system = unknown_system(f"CASE_SCAN_FAILED_{type(exc).__name__}")
                result = {
                    "schema_version": "1.0",
                    "experiment_id": EXPERIMENT_ID,
                    "case_id": row["case_id"],
                    "benchmark_id": row["benchmark_id"],
                    "skill_text_sha256": row["skill_text_sha256"],
                    "scan_ready": bool(row.get("scan_ready")),
                    "systems": {name: system for name in SYSTEMS},
                    "duration_ms": 0,
                    "model_calls": 0,
                    "model_cache_hits": 0,
                    "p1_execution_kind": "not_run",
                }
            write_json(shards / f"{row['case_id']}.json", result)
            with lock:
                completed += 1
                if completed % 100 == 0 or completed == len(rows):
                    print(f"progress={completed}/{len(rows)}", flush=True)

    results = [load_json(shards / f"{row['case_id']}.json") for row in rows]
    write_jsonl(output_root / "scan_results.label_blind.jsonl", results)
    manifest = load_json(run_manifest_path)
    manifest.update({
        "status": "scan_complete_labels_not_joined",
        "scan_completed_at": now_iso(),
        "scan_duration_ms_this_invocation": round((time.perf_counter() - started) * 1000),
        "cases": len(results),
        "cisco_results": len(cisco_index),
        "unknown_cases": sum(
            row["systems"]["cisco_plus_p0_p1"]["decision"] == "UNKNOWN" for row in results
        ),
        "model_calls": sum(int(row.get("model_calls") or 0) for row in results),
        "model_cache_hits": sum(int(row.get("model_cache_hits") or 0) for row in results),
        "label_blind_results_sha256": sha256_file(output_root / "scan_results.label_blind.jsonl"),
    })
    write_json(run_manifest_path, manifest)
    return manifest


def _binary_metrics(rows: list[dict[str, Any]], system: str) -> dict[str, Any]:
    malicious = [row for row in rows if row["label"] == "1"]
    benign = [row for row in rows if row["label"] == "0"]
    decisions = Counter(row["systems"][system]["decision"] for row in rows)
    tp = sum(row["label"] == "1" and row["systems"][system]["decision"] == "BLOCK" for row in rows)
    fp = sum(row["label"] == "0" and row["systems"][system]["decision"] == "BLOCK" for row in rows)
    fn = len(malicious) - tp
    tn = len(benign) - fp
    tpr = tp / len(malicious) if malicious else 0.0
    tnr = tn / len(benign) if benign else 0.0
    p1 = tp / (tp + fp) if tp + fp else 0.0
    r1 = tpr
    f1_pos = 2 * p1 * r1 / (p1 + r1) if p1 + r1 else 0.0
    p0 = tn / (tn + fn) if tn + fn else 0.0
    r0 = tnr
    f1_neg = 2 * p0 * r0 / (p0 + r0) if p0 + r0 else 0.0
    has_both_classes = bool(malicious) and bool(benign)
    return {
        "cases": len(rows),
        "decision_counts": dict(sorted(decisions.items())),
        "malicious_non_allow_recall": (
            sum(row["systems"][system]["decision"] != "ALLOW" for row in malicious) / len(malicious)
            if malicious else None
        ),
        "malicious_block_rate": tpr if malicious else None,
        "benign_allow_rate": (
            sum(row["systems"][system]["decision"] == "ALLOW" for row in benign) / len(benign)
            if benign else None
        ),
        "benign_block_rate": fp / len(benign) if benign else None,
        "unknown_rate": decisions["UNKNOWN"] / len(rows) if rows else None,
        "macro_f1_binary_block": (f1_pos + f1_neg) / 2 if has_both_classes else None,
        "balanced_accuracy_binary_block": (tpr + tnr) / 2 if has_both_classes else None,
        "confusion_binary_block": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    }


def _bootstrap_paired_delta(
    left: list[bool],
    right: list[bool],
    *,
    seed: int = 20260831,
    rounds: int = 5_000,
) -> dict[str, Any]:
    if len(left) != len(right) or not left:
        return {"estimate": None, "ci95": [None, None], "rounds": rounds}
    differences = [int(r) - int(l) for l, r in zip(left, right)]
    estimate = statistics.fmean(differences)
    rng = random.Random(seed)
    size = len(differences)
    samples = sorted(
        statistics.fmean(differences[rng.randrange(size)] for _ in range(size))
        for _ in range(rounds)
    )
    return {
        "estimate": estimate,
        "ci95": [samples[math.floor(0.025 * rounds)], samples[min(rounds - 1, math.ceil(0.975 * rounds) - 1)]],
        "rounds": rounds,
    }


def _mcnemar_exact(left: list[bool], right: list[bool]) -> dict[str, Any]:
    left_only = sum(l and not r for l, r in zip(left, right))
    right_only = sum(r and not l for l, r in zip(left, right))
    discordant = left_only + right_only
    if discordant == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, index) for index in range(min(left_only, right_only) + 1))
        p_value = min(1.0, 2.0 * tail / (2 ** discordant))
    return {
        "left_success_right_failure": left_only,
        "left_failure_right_success": right_only,
        "discordant": discordant,
        "two_sided_exact_p": p_value,
    }


def _paired_comparison(
    rows: list[dict[str, Any]], left: str, right: str
) -> dict[str, Any]:
    malicious = [row for row in rows if row["label"] == "1"]
    benign = [row for row in rows if row["label"] == "0"]
    malicious_left = [row["systems"][left]["decision"] != "ALLOW" for row in malicious]
    malicious_right = [row["systems"][right]["decision"] != "ALLOW" for row in malicious]
    benign_left = [row["systems"][left]["decision"] == "ALLOW" for row in benign]
    benign_right = [row["systems"][right]["decision"] == "ALLOW" for row in benign]
    return {
        "left": left,
        "right": right,
        "malicious_non_allow_recall_delta": {
            **_bootstrap_paired_delta(malicious_left, malicious_right),
            "mcnemar": _mcnemar_exact(malicious_left, malicious_right),
        },
        "benign_allow_rate_delta": {
            **_bootstrap_paired_delta(benign_left, benign_right, seed=20260832),
            "mcnemar": _mcnemar_exact(benign_left, benign_right),
        },
    }


def _error_analysis(rows: list[dict[str, Any]], system: str) -> dict[str, Any]:
    groups = {
        "malicious_allow": [row for row in rows if row["label"] == "1" and row["systems"][system]["decision"] == "ALLOW"],
        "malicious_non_allow": [row for row in rows if row["label"] == "1" and row["systems"][system]["decision"] != "ALLOW"],
        "benign_allow": [row for row in rows if row["label"] == "0" and row["systems"][system]["decision"] == "ALLOW"],
        "benign_non_allow": [row for row in rows if row["label"] == "0" and row["systems"][system]["decision"] != "ALLOW"],
    }
    result: dict[str, Any] = {}
    for name, subset in groups.items():
        rules = Counter(
            finding["rule_id"]
            for row in subset
            for finding in row["systems"][system]["finding_index"]
            if finding["severity"] not in {"INFO", "SAFE"}
        )
        result[name] = {
            "cases": len(subset),
            "source_counts": dict(sorted(Counter(row["source_id"] for row in subset).items())),
            "top_non_info_rules": [
                {"rule_id": rule_id, "count": count}
                for rule_id, count in rules.most_common(15)
            ],
        }
    return result


def evaluate(data_root: Path, output_root: Path) -> dict[str, Any]:
    scan_rows, identity = preflight(data_root)
    manifest = load_json(output_root / "run_manifest.json")
    if manifest.get("contract_sha256") != identity["contract_sha256"]:
        raise EvaluationError("Run manifest does not match the frozen contract")
    result_path = output_root / "scan_results.label_blind.jsonl"
    if sha256_file(result_path) != manifest.get("label_blind_results_sha256"):
        raise EvaluationError("Label-blind results changed before evaluation")
    results = load_jsonl(result_path)
    if len(results) != EXPECTED_CASES:
        raise EvaluationError("Label-blind result count is incomplete")

    labels = load_jsonl(data_root / "ground_truth" / "labels.jsonl")
    label_counts = Counter(str(row.get("label")) for row in labels)
    if len(labels) != EXPECTED_CASES or dict(label_counts) != EXPECTED_LABELS:
        raise EvaluationError("Ground truth identity changed")
    by_id = {row["case_id"]: row for row in labels}
    joined: list[dict[str, Any]] = []
    for result in results:
        truth = by_id.get(result["case_id"])
        if truth is None:
            raise EvaluationError(f"Missing ground truth after scan: {result['case_id']}")
        joined.append({**result, **truth})

    metrics = {system: _binary_metrics(joined, system) for system in SYSTEMS}
    per_source: dict[str, Any] = {}
    for source_id in sorted({row["source_id"] for row in joined}):
        subset = [row for row in joined if row["source_id"] == source_id]
        per_source[source_id] = {
            "label_counts": dict(sorted(Counter(row["label"] for row in subset).items())),
            "systems": {system: _binary_metrics(subset, system) for system in SYSTEMS},
        }
    category_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in joined:
        for category in row.get("attack_category_codes") or []:
            category_rows[str(category)].append(row)
    per_attack = {
        category: {
            "support": len(subset),
            "systems": {
                system: {
                    "non_allow_recall": sum(row["systems"][system]["decision"] != "ALLOW" for row in subset) / len(subset),
                    "block_rate": sum(row["systems"][system]["decision"] == "BLOCK" for row in subset) / len(subset),
                }
                for system in SYSTEMS
            },
        }
        for category, subset in sorted(category_rows.items())
    }
    durations = [int(row.get("duration_ms") or 0) for row in joined]
    report = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "evaluated_at": now_iso(),
        "contract_sha256": identity["contract_sha256"],
        "cases": len(joined),
        "label_counts": dict(sorted(label_counts.items())),
        "systems": metrics,
        "paired_comparisons": {
            "p0_vs_cisco": _paired_comparison(joined, "cisco_only", "cisco_plus_p0"),
            "p1_vs_p0": _paired_comparison(joined, "cisco_plus_p0", "cisco_plus_p0_p1"),
        },
        "error_analysis": {
            system: _error_analysis(joined, system) for system in SYSTEMS
        },
        "per_source": per_source,
        "per_attack_category": per_attack,
        "runtime": {
            "case_duration_p50_ms": statistics.median(durations),
            "case_duration_p95_ms": sorted(durations)[max(0, math.ceil(0.95 * len(durations)) - 1)],
            "model_calls": sum(int(row.get("model_calls") or 0) for row in joined),
            "model_cache_hits": sum(int(row.get("model_cache_hits") or 0) for row in joined),
            "p1_pure_instruction_cases": sum(row.get("p1_execution_kind") == "pure_instruction" for row in joined),
            "p1_container_code_execution_cases": sum(row.get("p1_execution_kind") == "container_scripts" for row in joined),
        },
        "claim_boundary": "Main benchmark uses released static text snapshots; P1 is pure-instruction audit and does not execute known malicious code.",
    }
    write_json(output_root / "metrics.json", report)
    write_jsonl(output_root / "evaluated_results.jsonl", joined)
    write_markdown_report(output_root / "REPORT.md", report)
    manifest.update({
        "status": "evaluation_complete",
        "evaluation_completed_at": now_iso(),
        "ground_truth_sha256": sha256_file(data_root / "ground_truth" / "labels.jsonl"),
        "metrics_sha256": sha256_file(output_root / "metrics.json"),
        "report_sha256": sha256_file(output_root / "REPORT.md"),
    })
    write_json(output_root / "run_manifest.json", manifest)
    return report


def write_markdown_report(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# MaliciousSkillBench Source-Disjoint 1,384 条评测报告",
        "",
        f"- 样本：{report['cases']}（恶意 {report['label_counts']['1']}，良性 {report['label_counts']['0']}）",
        "- 扫描阶段不读取标签；三组结果完成后才合并官方真值。",
        "- 主实验为静态文本快照；P1 只做纯指令三场景审计，不执行已知恶意代码。",
        "",
        "## 总体结果",
        "",
        "| 系统 | 恶意不放行召回 | 恶意阻断率 | 良性允许率 | 良性阻断率 | BLOCK宏F1 | 平衡准确率 | UNKNOWN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    names = {
        "cisco_only": "Cisco-only",
        "cisco_plus_p0": "Cisco + P0",
        "cisco_plus_p0_p1": "Cisco + P0 + P1",
    }
    for system in SYSTEMS:
        item = report["systems"][system]
        lines.append(
            f"| {names[system]} | {item['malicious_non_allow_recall']:.1%} | "
            f"{item['malicious_block_rate']:.1%} | {item['benign_allow_rate']:.1%} | "
            f"{item['benign_block_rate']:.1%} | {item['macro_f1_binary_block']:.3f} | "
            f"{item['balanced_accuracy_binary_block']:.3f} | {item['unknown_rate']:.1%} |"
        )
    lines.extend([
        "",
        "## 配对改善",
        "",
        (
            "- P0 相对 Cisco：恶意不放行召回变化 "
            f"{report['paired_comparisons']['p0_vs_cisco']['malicious_non_allow_recall_delta']['estimate']:+.1%}，"
            "良性允许率变化 "
            f"{report['paired_comparisons']['p0_vs_cisco']['benign_allow_rate_delta']['estimate']:+.1%}。"
        ),
        (
            "- P1 相对 P0：恶意不放行召回变化 "
            f"{report['paired_comparisons']['p1_vs_p0']['malicious_non_allow_recall_delta']['estimate']:+.1%}，"
            "良性允许率变化 "
            f"{report['paired_comparisons']['p1_vs_p0']['benign_allow_rate_delta']['estimate']:+.1%}。"
        ),
        "- 置信区间、McNemar 精确检验、按来源和按攻击类别明细见 `metrics.json`。",
        "",
        "## 运行与边界",
        "",
        f"- 单样本流水线耗时 P50/P95：{report['runtime']['case_duration_p50_ms']} / {report['runtime']['case_duration_p95_ms']} ms。",
        f"- 本地语义模型真实调用：{report['runtime']['model_calls']}；P1 复用缓存：{report['runtime']['model_cache_hits']}。",
        f"- P1 纯指令审计：{report['runtime']['p1_pure_instruction_cases']}；容器代码执行：{report['runtime']['p1_container_code_execution_cases']}。",
        "- 来源和标签存在分布关联，正式结论必须同时查看 `metrics.json` 中的 `per_source`，不能只引用总指标。",
        "- 被主机内容防护拦截或不满足正式 Skill 结构的样本按 UNKNOWN 失败关闭，不计为安全。",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the frozen MaliciousSkillBench Source-Disjoint evaluation.")
    parser.add_argument("command", choices=("scan", "evaluate", "all"))
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--workers", type=int, default=4)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data_root = args.data_root.resolve()
    output_root = args.output_root.resolve()
    if args.command in {"scan", "all"}:
        scan(data_root, output_root, args.workers)
    if args.command in {"evaluate", "all"}:
        report = evaluate(data_root, output_root)
        print(json.dumps({"cases": report["cases"], "systems": report["systems"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
