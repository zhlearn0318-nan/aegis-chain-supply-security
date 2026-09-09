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
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.adapters.process import AdapterResult, ProcessRunner  # noqa: E402
from backend.adapters.skill import SkillScannerAdapter  # noqa: E402
from backend.analyzers.skill_capability_alignment import ANALYZER_ID as CAPABILITY_ANALYZER  # noqa: E402
from backend.analyzers.skill_semantic import (  # noqa: E402
    ANALYZER_ID as SEMANTIC_ANALYZER,
    analyze_skill_semantics,
)
from backend.models import EvidenceSource  # noqa: E402
from backend.normalizers import finding_dict  # noqa: E402
from backend.policy import evaluate_findings, load_policy, summarize  # noqa: E402
from backend.runtime_paths import runtime_path_entries  # noqa: E402
from backend.semantic_model import configured_semantic_provider, load_semantic_model_config  # noqa: E402
from backend.skill_static_pipeline import run_skill_static_pipeline  # noqa: E402
from tools.datasets.prepare_m15_e01_splits import (  # noqa: E402
    sha256_file,
    verify_scan_inputs,
)


EXPERIMENT_ID = "2026-09-06-m15-e01-static-ablation-v5"
CONFIG_PATH = DEMO_ROOT / "config" / "m15_e01_static_ablation_v5.json"
DEFAULT_DATA_ROOT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_m15_e01_v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / EXPERIMENT_ID
SKILL_RUNTIME = REPOSITORY_ROOT / ".runtime_skill"
SKILL_SCANNER = SKILL_RUNTIME / "Scripts" / "skill-scanner.exe"
CISCO_POLICY_PATH = DEMO_ROOT / "config" / "admission_policy.yaml"
AEGIS_POLICY_PATH = DEMO_ROOT / "config" / "admission_policy.skill-evidence-v1.yaml"
SEMANTIC_CONFIG_PATH = DEMO_ROOT / "config" / "skill_semantic_model.json"
QWEN_SMOKE_CASES_PATH = DEMO_ROOT / "config" / "m15_e01_qwen_smoke_case_ids.txt"
SYSTEMS = ("S0", "S1", "S2", "S3", "S4", "S5", "S6")
ML_ANALYZER = "aegis-tfidf-logistic-v1"


class ScanError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ScanError(f"Expected JSON object: {path}")
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


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def sanitized_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for finding in findings:
        location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
        result.append(
            {
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
            }
        )
    return result


def unknown_system(reason_code: str) -> dict[str, Any]:
    return {
        "decision": "UNKNOWN",
        "reason_code": reason_code,
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0,
        },
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


class PrecomputedAdapter:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result

    def scan(self, _skill_path: Path) -> AdapterResult:
        return AdapterResult(
            report={"results": [self.result]},
            logs=[f"skill-scanner batch result reused: findings={len(self.result.get('findings') or [])}"],
        )


class PerCaseProvider:
    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.calls = 0
        self.failures = 0
        self.error_codes: list[str] = []

    def review(self, features: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        try:
            return self.delegate.review(features)
        except Exception as exc:
            self.failures += 1
            self.error_codes.append(str(exc)[:120] or type(exc).__name__)
            raise


def warm_semantic_provider(delegate: Any, attempts: int = 5) -> dict[str, Any]:
    errors: list[str] = []
    started = time.perf_counter()
    for attempt in range(1, attempts + 1):
        try:
            response = delegate.review(
                {
                    "signal_kinds": ["concealment"],
                    "line_count": 1,
                    "has_sensitive_signal": False,
                    "has_outbound_signal": False,
                    "has_execution_signal": False,
                    "defensive_context": True,
                    "content_sha256": hashlib.sha256(b"aegis-qwen-warmup-v1").hexdigest(),
                    "redacted_segments": ["L1: Defensive UI wording test."],
                }
            )
            return {
                "status": "ready",
                "attempts": attempt,
                "duration_ms": round((time.perf_counter() - started) * 1000),
                "response_risk": str(response.get("risk") or ""),
                "errors": errors,
            }
        except Exception as exc:
            errors.append(str(exc)[:120] or type(exc).__name__)
    raise ScanError(
        f"Qwen warmup failed after {attempts} attempts: {errors[-1] if errors else 'unknown'}"
    )


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
        raise ScanError("Cisco Skill Scanner version probe failed")
    return (completed.stdout or completed.stderr).strip()


def ollama_identity() -> dict[str, Any]:
    config = load_semantic_model_config()
    if config.mode != "local":
        raise ScanError("E01 S4 requires the frozen local semantic model mode")
    try:
        with urllib.request.urlopen(f"{config.local_endpoint}/api/tags", timeout=5) as response:
            payload = json.loads(response.read(2 * 1024 * 1024))
    except Exception as exc:
        raise ScanError("Local Ollama health probe failed") from exc
    matches = [item for item in payload.get("models") or [] if item.get("name") == config.local_model]
    if len(matches) != 1:
        raise ScanError(f"Frozen local model is unavailable: {config.local_model}")
    item = matches[0]
    return {
        "mode": "local",
        "endpoint": config.local_endpoint,
        "model": config.local_model,
        "digest": str(item.get("digest") or ""),
        "size": int(item.get("size") or 0),
    }


def prediction_paths(output_root: Path, split_name: str, limit: int | None) -> tuple[Path, Path]:
    suffix = f"smoke{limit}" if limit is not None else "full"
    return (
        output_root / f"{split_name}_model_predictions_{suffix}.label_blind.jsonl",
        output_root / f"{split_name}_model_predictions_{suffix}.receipt.json",
    )


def scan_root(output_root: Path, split_name: str, limit: int | None) -> Path:
    return output_root / (f"smoke_{split_name}_{limit}" if limit is not None else f"{split_name}_scan")


def preflight(
    data_root: Path, output_root: Path, split_name: str, limit: int | None
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, Any]]:
    if not SKILL_SCANNER.is_file():
        raise ScanError("Pinned Cisco Skill Scanner is unavailable")
    config = load_json(CONFIG_PATH)
    if config.get("experiment_id") != EXPERIMENT_ID:
        raise ScanError("Experiment contract identity drifted")
    verified = verify_scan_inputs(data_root, (split_name,))
    split_root = data_root / split_name
    rows = load_jsonl(split_root / "scan_manifest.jsonl")
    if limit is not None:
        if not 1 <= limit <= 100:
            raise ScanError("Smoke limit must be between 1 and 100")
        rows = rows[:limit]
    prediction_path, receipt_path = prediction_paths(output_root, split_name, limit)
    predictions = load_jsonl(prediction_path)
    prediction_receipt = load_json(receipt_path)
    if len(predictions) != len(rows):
        raise ScanError("Prediction and scan case counts disagree")
    if sha256_file(prediction_path) != prediction_receipt.get("results_sha256"):
        raise ScanError("Label-blind model predictions drifted")
    if prediction_receipt.get("ground_truth_opened") is not False:
        raise ScanError("Prediction label firewall receipt is invalid")
    prediction_by_id = {str(row["case_id"]): row for row in predictions}
    if [row["case_id"] for row in rows] != [row["case_id"] for row in predictions]:
        raise ScanError("Prediction and scan case ordering disagrees")
    forbidden = {"label", "source_id", "ground_truth"}
    if any(forbidden & set(row) for row in predictions):
        raise ScanError("Ground truth crossed into model prediction results")
    identity = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "config_sha256": sha256_file(CONFIG_PATH),
        "input_tree_sha256": verified["splits"][split_name]["scan_input_tree_sha256"],
        "prediction_results_sha256": sha256_file(prediction_path),
        "prediction_receipt_sha256": sha256_file(receipt_path),
        "cisco_policy_sha256": sha256_file(CISCO_POLICY_PATH),
        "aegis_policy_sha256": sha256_file(AEGIS_POLICY_PATH),
        "semantic_config_sha256": sha256_file(SEMANTIC_CONFIG_PATH),
        "scanner_sha256": sha256_file(SKILL_SCANNER),
        "scanner_version": scanner_version(),
        "ollama": ollama_identity(),
        "split": split_name,
        "limit": limit,
        "cases": len(rows),
        "ground_truth_opened": False,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    identity["scan_contract_sha256"] = hashlib.sha256(canonical).hexdigest()
    return rows, prediction_by_id, identity


def run_cisco_batch(data_root: Path, run_root: Path, identity: dict[str, Any]) -> dict[str, dict[str, Any]]:
    report_path = run_root / "cisco_batch_report.json"
    receipt_path = run_root / "cisco_batch_receipt.json"
    if report_path.is_file() and receipt_path.is_file():
        receipt = load_json(receipt_path)
        if (
            receipt.get("scan_contract_sha256") != identity["scan_contract_sha256"]
            or receipt.get("report_sha256") != sha256_file(report_path)
        ):
            raise ScanError("Existing Cisco batch output drifted")
        payload = load_json(report_path)
    else:
        run_root.mkdir(parents=True, exist_ok=True)
        temporary = run_root / "cisco_batch_report.partial.json"
        runner = ProcessRunner(
            timeout_seconds=600,
            cache_root=run_root / "scanner_cache",
            extra_path=runtime_path_entries(SKILL_RUNTIME),
        )
        started = time.perf_counter()
        completed = runner.run(
            [
                str(SKILL_SCANNER),
                "scan-all",
                str((data_root / str(identity["split"]) / "cases").resolve()),
                "--recursive",
                "--format",
                "json",
                "--output-json",
                str(temporary.resolve()),
                "--compact",
            ]
        )
        if completed.returncode != 0 or not temporary.is_file():
            raise ScanError(f"Cisco batch scan failed: exit={completed.returncode}")
        payload = load_json(temporary)
        if not isinstance(payload.get("results"), list):
            raise ScanError("Cisco batch output has no results list")
        os.replace(temporary, report_path)
        write_json(
            receipt_path,
            {
                "schema_version": "1.0",
                "scan_contract_sha256": identity["scan_contract_sha256"],
                "completed_at": now_iso(),
                "duration_ms": round((time.perf_counter() - started) * 1000),
                "results": len(payload["results"]),
                "report_sha256": sha256_file(report_path),
                "stdout_sha256": hashlib.sha256((completed.stdout or "").encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256((completed.stderr or "").encode()).hexdigest(),
            },
        )
    indexed: dict[str, dict[str, Any]] = {}
    for result in payload.get("results") or []:
        path = str(result.get("skill_path") or "").replace("\\", "/").rstrip("/")
        case_id = path.rsplit("/", 1)[-1].lower()
        if not case_id or case_id in indexed:
            raise ScanError(f"Cisco result identity is not unique: {case_id!r}")
        indexed[case_id] = result
    return indexed


def ml_finding(prediction: dict[str, Any]) -> dict[str, Any] | None:
    if prediction.get("status") != "predicted" or not prediction.get("adds_medium_review_finding"):
        return None
    probability = float(prediction["probability_malicious"])
    threshold = float(prediction["threshold"])
    identity = f"{prediction['case_id']}|{probability:.12f}|{threshold:.12f}"
    return finding_dict(
        id=f"AEGIS_ML_TEXT_RISK_REVIEW_{hashlib.sha256(identity.encode()).hexdigest()[:12]}",
        rule_id="AEGIS_ML_TEXT_RISK_REVIEW",
        title="轻量文本模型建议人工复核",
        category="model_risk_evidence",
        severity="MEDIUM",
        analyzer=ML_ANALYZER,
        location={"file": "SKILL.md"},
        evidence=(
            f"probability_malicious={probability:.6f}; threshold={threshold:.6f}; "
            "raw_content_retained=false; direct_block=false"
        ),
        description="来源隔离训练的轻量文本模型发现统计风险，但不能作为独立阻断证据。",
        remediation="结合确定性规则、能力声明、语义复核和动态审计确认后再决定准入。",
        evidence_confidence="POTENTIAL",
        reachability="UNKNOWN",
        behavior_alignment="UNKNOWN",
        evidence_source=EvidenceSource.AEGIS_SEMANTIC,
    )


def partition_findings(
    deterministic: list[dict[str, Any]], qwen_semantic: list[dict[str, Any]], prediction: dict[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    base = [
        item
        for item in deterministic
        if item.get("analyzer") not in {SEMANTIC_ANALYZER, CAPABILITY_ANALYZER}
    ]
    capability = [item for item in deterministic if item.get("analyzer") == CAPABILITY_ANALYZER]
    deterministic_semantic = [
        item for item in deterministic if item.get("analyzer") == SEMANTIC_ANALYZER
    ]
    cisco = [item for item in deterministic if str(item.get("evidence_source") or "").upper() == "CISCO"]
    model = ml_finding(prediction)
    return {
        "S0": cisco,
        "S1": base,
        "S2": [*base, *capability],
        "S3": [*base, *deterministic_semantic],
        "S4": [*base, *capability, *qwen_semantic],
        "S5": [*base, *capability, *qwen_semantic, *([model] if model else [])],
        "S6": [*base, *capability, *deterministic_semantic, *([model] if model else [])],
    }


def scan_case(
    row: dict[str, Any],
    prediction: dict[str, Any],
    split_root: Path,
    cisco_result: dict[str, Any] | None,
    run_root: Path,
    semantic_delegate: Any,
    cisco_policy: Any,
    aegis_policy: Any,
) -> dict[str, Any]:
    started = time.perf_counter()
    case_id = str(row["case_id"])
    base_result = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "case_id": case_id,
        "benchmark_id": row["benchmark_id"],
        "skill_text_sha256": row["skill_text_sha256"],
        "scan_ready": bool(row.get("scan_ready")),
    }
    if not row.get("scan_ready"):
        reason = str(row.get("unavailability_reason") or "MATERIALIZATION_UNAVAILABLE")
        system = unknown_system(reason)
        return {**base_result, "systems": {name: system for name in SYSTEMS}, "duration_ms": 0, "qwen_calls": 0, "qwen_failures": 0}
    if prediction.get("status") != "predicted":
        system = unknown_system("LIGHTWEIGHT_MODEL_PREDICTION_UNAVAILABLE")
        return {**base_result, "systems": {name: system for name in SYSTEMS}, "duration_ms": 0, "qwen_calls": 0, "qwen_failures": 0}

    case_root = (split_root / str(row["local_path"])).resolve()
    before = sha256_file(case_root / "SKILL.md")
    if cisco_result is None:
        adapter = SkillScannerAdapter(
            SKILL_SCANNER,
            ProcessRunner(
                timeout_seconds=120,
                cache_root=run_root / "scanner_cache" / case_id,
                extra_path=runtime_path_entries(SKILL_RUNTIME),
            ),
        )
    else:
        adapter = PrecomputedAdapter(cisco_result)
    pipeline = run_skill_static_pipeline(case_root, adapter, semantic_provider=None)
    deterministic = pipeline["findings"]
    deterministic_semantic = [
        item for item in deterministic if item.get("analyzer") == SEMANTIC_ANALYZER
    ]
    needs_qwen = any(
        item.get("rule_id") == "AEGIS_SEMANTIC_AMBIGUOUS_CONTROL_LANGUAGE"
        for item in deterministic_semantic
    )
    per_case_provider = PerCaseProvider(semantic_delegate)
    qwen_semantic = deterministic_semantic
    if needs_qwen:
        qwen_semantic, _ = analyze_skill_semantics(case_root, provider=per_case_provider)
    findings_by_system = partition_findings(deterministic, qwen_semantic, prediction)
    systems: dict[str, Any] = {}
    for name, findings in findings_by_system.items():
        if per_case_provider.failures and name in {"S4", "S5"}:
            systems[name] = unknown_system("QWEN_SEMANTIC_PROVIDER_FAILED")
        else:
            systems[name] = evaluated_system(findings, cisco_policy if name == "S0" else aegis_policy)
    after = sha256_file(case_root / "SKILL.md")
    if before != row["skill_text_sha256"] or after != before:
        raise ScanError(f"Case changed during scan: {case_id}")
    return {
        **base_result,
        "systems": systems,
        "duration_ms": max(1, round((time.perf_counter() - started) * 1000)),
        "qwen_routed": needs_qwen,
        "qwen_calls": per_case_provider.calls,
        "qwen_failures": per_case_provider.failures,
        "lightweight_model_review": bool(prediction.get("adds_medium_review_finding")),
    }


def scan(data_root: Path, output_root: Path, split_name: str, limit: int | None, workers: int) -> dict[str, Any]:
    rows, predictions, identity = preflight(data_root, output_root, split_name, limit)
    run_root = scan_root(output_root, split_name, limit)
    run_root.mkdir(parents=True, exist_ok=True)
    run_manifest_path = run_root / "run_manifest.json"
    if run_manifest_path.is_file():
        manifest = load_json(run_manifest_path)
        if manifest.get("scan_contract_sha256") != identity["scan_contract_sha256"]:
            raise ScanError("Existing scan directory belongs to another contract")
    else:
        manifest = {
            **identity,
            "status": "scanning",
            "started_at": now_iso(),
            "workers": max(1, min(workers, 8)),
            "label_firewall": "ground truth is not loaded by this command",
        }
        write_json(run_manifest_path, manifest)

    cisco_index = run_cisco_batch(data_root, run_root, identity) if limit is None else {}
    semantic_delegate = configured_semantic_provider()
    if semantic_delegate is None:
        raise ScanError("Frozen Qwen semantic provider is disabled")
    qwen_warmup = warm_semantic_provider(semantic_delegate)
    cisco_policy = load_policy(CISCO_POLICY_PATH)
    aegis_policy = load_policy(AEGIS_POLICY_PATH)
    shards = run_root / "scan_shards"
    shards.mkdir(exist_ok=True)
    pending: list[dict[str, Any]] = []
    for row in rows:
        shard = shards / f"{row['case_id']}.json"
        if shard.is_file():
            existing = load_json(shard)
            if existing.get("skill_text_sha256") != row["skill_text_sha256"]:
                raise ScanError(f"Resume shard identity drifted: {row['case_id']}")
        else:
            pending.append(row)

    completed_count = len(rows) - len(pending)
    lock = threading.Lock()
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 8))) as executor:
        futures = {
            executor.submit(
                scan_case,
                row,
                predictions[row["case_id"]],
                data_root / split_name,
                cisco_index.get(str(row["case_id"])),
                run_root,
                semantic_delegate,
                cisco_policy,
                aegis_policy,
            ): row
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
                    "qwen_routed": False,
                    "qwen_calls": 0,
                    "qwen_failures": 0,
                    "lightweight_model_review": False,
                    "exception_type": type(exc).__name__,
                }
            write_json(shards / f"{row['case_id']}.json", result)
            with lock:
                completed_count += 1
                if completed_count % 20 == 0 or completed_count == len(rows):
                    print(f"progress={completed_count}/{len(rows)}", flush=True)

    results = [load_json(shards / f"{row['case_id']}.json") for row in rows]
    result_path = run_root / "scan_results.label_blind.jsonl"
    write_jsonl(result_path, results)
    after = verify_scan_inputs(data_root, (split_name,))["splits"][split_name]["scan_input_tree_sha256"]
    if after != identity["input_tree_sha256"]:
        raise ScanError("Static scan changed the frozen input tree")
    manifest.update(
        {
            "status": "scan_complete_labels_not_joined",
            "scan_completed_at": now_iso(),
            "scan_duration_ms_this_invocation": round((time.perf_counter() - started) * 1000),
            "results_sha256": sha256_file(result_path),
            "input_tree_sha256_after": after,
            "input_tree_unchanged": True,
            "unknown_by_system": {
                name: sum(row["systems"][name]["decision"] == "UNKNOWN" for row in results)
                for name in SYSTEMS
            },
            "qwen_routed_cases": sum(bool(row.get("qwen_routed")) for row in results),
            "qwen_calls": sum(int(row.get("qwen_calls") or 0) for row in results),
            "qwen_failures": sum(int(row.get("qwen_failures") or 0) for row in results),
            "lightweight_model_review_cases": sum(
                bool(row.get("lightweight_model_review")) for row in results
            ),
            "ground_truth_opened": False,
            "qwen_warmup": qwen_warmup,
        }
    )
    write_json(run_manifest_path, manifest)
    return manifest


def route_preflight(data_root: Path, split_name: str, max_hits: int) -> dict[str, Any]:
    verification = verify_scan_inputs(data_root, (split_name,))
    split_root = data_root / split_name
    rows = load_jsonl(split_root / "scan_manifest.jsonl")
    hits: list[str] = []
    checked = 0
    for row in rows:
        if not row.get("scan_ready"):
            continue
        checked += 1
        findings, _ = analyze_skill_semantics(
            split_root / str(row["local_path"]), provider=None
        )
        if any(
            item.get("rule_id") == "AEGIS_SEMANTIC_AMBIGUOUS_CONTROL_LANGUAGE"
            for item in findings
        ):
            hits.append(str(row["case_id"]))
            if len(hits) >= max_hits:
                break
    return {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "status": "label_blind_qwen_route_preflight",
        "split": split_name,
        "checked_ready_cases": checked,
        "qwen_route_case_ids": hits,
        "input_tree_sha256": verification["splits"][split_name]["scan_input_tree_sha256"],
        "ground_truth_opened": False,
    }


def qwen_smoke(data_root: Path, output_root: Path) -> dict[str, Any]:
    verification = verify_scan_inputs(data_root, ("train",))
    split_root = data_root / "train"
    rows = {row["case_id"]: row for row in load_jsonl(split_root / "scan_manifest.jsonl")}
    case_ids = [
        line.strip()
        for line in QWEN_SMOKE_CASES_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(case_ids) != 10 or len(set(case_ids)) != 10:
        raise ScanError("Qwen smoke case list must contain ten unique IDs")
    before = verification["splits"]["train"]["scan_input_tree_sha256"]
    provider = configured_semantic_provider()
    if provider is None:
        raise ScanError("Frozen Qwen semantic provider is disabled")
    model_identity = ollama_identity()
    warmup = warm_semantic_provider(provider)
    results: list[dict[str, Any]] = []
    started = time.perf_counter()
    for index, case_id in enumerate(case_ids, start=1):
        row = rows.get(case_id)
        if row is None or not row.get("scan_ready"):
            raise ScanError(f"Frozen Qwen smoke case is unavailable: {case_id}")
        case_root = split_root / str(row["local_path"])
        deterministic, _ = analyze_skill_semantics(case_root, provider=None)
        if not any(
            item.get("rule_id") == "AEGIS_SEMANTIC_AMBIGUOUS_CONTROL_LANGUAGE"
            for item in deterministic
        ):
            raise ScanError(f"Frozen case no longer routes to Qwen: {case_id}")
        per_case = PerCaseProvider(provider)
        with_qwen, _ = analyze_skill_semantics(case_root, provider=per_case)
        results.append(
            {
                "case_id": case_id,
                "skill_text_sha256": row["skill_text_sha256"],
                "deterministic_findings": sanitized_findings(deterministic),
                "qwen_findings": sanitized_findings(with_qwen),
                "qwen_calls": per_case.calls,
                "qwen_failures": per_case.failures,
                "qwen_error_codes": per_case.error_codes,
                "severity_changed": [item.get("severity") for item in deterministic]
                != [item.get("severity") for item in with_qwen],
            }
        )
        print(f"qwen_smoke={index}/{len(case_ids)} case_id={case_id}", flush=True)
    after = verify_scan_inputs(data_root, ("train",))["splits"]["train"]["scan_input_tree_sha256"]
    if before != after:
        raise ScanError("Qwen smoke changed the frozen train input tree")
    report = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "status": "passed"
        if sum(item["qwen_failures"] for item in results) == 0
        and sum(item["qwen_calls"] for item in results) == len(results)
        else "failed",
        "completed_at": now_iso(),
        "case_ids_sha256": sha256_file(QWEN_SMOKE_CASES_PATH),
        "cases": len(results),
        "qwen_calls": sum(item["qwen_calls"] for item in results),
        "qwen_failures": sum(item["qwen_failures"] for item in results),
        "severity_changed_cases": sum(bool(item["severity_changed"]) for item in results),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "ollama": model_identity,
        "warmup": warmup,
        "input_tree_sha256_before": before,
        "input_tree_sha256_after": after,
        "input_tree_unchanged": True,
        "ground_truth_opened": False,
        "results": results,
    }
    report_path = output_root / "qwen_route_smoke" / "report_v2.json"
    if report_path.exists():
        raise ScanError("Qwen smoke report already exists; refusing to overwrite")
    write_json(report_path, report)
    return report


def binary_decision_metrics(rows: list[dict[str, Any]], system: str) -> dict[str, Any]:
    from collections import Counter

    malicious = [row for row in rows if row["label"] == "1"]
    benign = [row for row in rows if row["label"] == "0"]
    decisions = Counter(row["systems"][system]["decision"] for row in rows)
    tp = sum(row["label"] == "1" and row["systems"][system]["decision"] == "BLOCK" for row in rows)
    fp = sum(row["label"] == "0" and row["systems"][system]["decision"] == "BLOCK" for row in rows)
    fn = len(malicious) - tp
    tn = len(benign) - fp
    tpr = tp / len(malicious) if malicious else None
    tnr = tn / len(benign) if benign else None
    precision_pos = tp / (tp + fp) if tp + fp else 0.0
    precision_neg = tn / (tn + fn) if tn + fn else 0.0
    f1_pos = (
        2 * precision_pos * tpr / (precision_pos + tpr)
        if tpr is not None and precision_pos + tpr
        else 0.0
    )
    f1_neg = (
        2 * precision_neg * tnr / (precision_neg + tnr)
        if tnr is not None and precision_neg + tnr
        else 0.0
    )
    return {
        "cases": len(rows),
        "decision_counts": dict(sorted(decisions.items())),
        "malicious_non_allow_recall": (
            sum(row["systems"][system]["decision"] != "ALLOW" for row in malicious) / len(malicious)
            if malicious
            else None
        ),
        "malicious_block_rate": tpr,
        "benign_allow_rate": (
            sum(row["systems"][system]["decision"] == "ALLOW" for row in benign) / len(benign)
            if benign
            else None
        ),
        "benign_block_rate": fp / len(benign) if benign else None,
        "review_rate": decisions["REVIEW"] / len(rows) if rows else None,
        "unknown_rate": decisions["UNKNOWN"] / len(rows) if rows else None,
        "macro_f1_binary_block": (f1_pos + f1_neg) / 2 if malicious and benign else None,
        "balanced_accuracy_binary_block": ((tpr or 0.0) + (tnr or 0.0)) / 2
        if malicious and benign
        else None,
        "confusion_binary_block": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    }


def bootstrap_paired_delta(
    left: list[bool], right: list[bool], *, seed: int, rounds: int = 10_000
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
        "ci95": [
            samples[math.floor(0.025 * rounds)],
            samples[min(rounds - 1, math.ceil(0.975 * rounds) - 1)],
        ],
        "rounds": rounds,
    }


def mcnemar_exact(left: list[bool], right: list[bool]) -> dict[str, Any]:
    left_only = sum(l and not r for l, r in zip(left, right))
    right_only = sum(r and not l for l, r in zip(left, right))
    discordant = left_only + right_only
    if discordant == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, index) for index in range(min(left_only, right_only) + 1))
        p_value = min(1.0, 2.0 * tail / (2**discordant))
    return {
        "left_success_right_failure": left_only,
        "left_failure_right_success": right_only,
        "discordant": discordant,
        "two_sided_exact_p": p_value,
    }


def paired_comparison(rows: list[dict[str, Any]], left: str, right: str) -> dict[str, Any]:
    malicious = [row for row in rows if row["label"] == "1"]
    benign = [row for row in rows if row["label"] == "0"]
    definitions = {
        "malicious_non_allow_recall_delta": (
            [row["systems"][left]["decision"] != "ALLOW" for row in malicious],
            [row["systems"][right]["decision"] != "ALLOW" for row in malicious],
            20260905,
        ),
        "benign_allow_rate_delta": (
            [row["systems"][left]["decision"] == "ALLOW" for row in benign],
            [row["systems"][right]["decision"] == "ALLOW" for row in benign],
            20260906,
        ),
        "benign_block_rate_delta": (
            [row["systems"][left]["decision"] == "BLOCK" for row in benign],
            [row["systems"][right]["decision"] == "BLOCK" for row in benign],
            20260907,
        ),
    }
    result: dict[str, Any] = {"left": left, "right": right}
    for name, (left_values, right_values, seed) in definitions.items():
        result[name] = {
            **bootstrap_paired_delta(left_values, right_values, seed=seed),
            "mcnemar": mcnemar_exact(left_values, right_values),
        }
    return result


def _fmt(value: float | None, digits: int = 1) -> str:
    return "N/A" if value is None else f"{value:.{digits}%}"


def write_e01_report(path: Path, report: dict[str, Any]) -> None:
    names = {
        "S0": "Cisco only",
        "S1": "Cisco + Aegis确定性",
        "S2": "S1 + 能力一致性",
        "S3": "S1 + 确定性语义",
        "S4": "S1 + 能力 + 语义 + Qwen",
        "S5": "S4 + 轻量模型",
        "S6": "S5关闭Qwen",
    }
    lines = [
        "# M15 E01 静态组件对照与消融正式结果",
        "",
        f"- validation：{report['cases']} 条（恶意 {report['label_counts']['1']}，良性 {report['label_counts']['0']}）。",
        "- 扫描完成并锁定哈希后才连接标签；本回执是唯一一次完成评测。",
        "- 9 条文本被主机内容防护阻止物化，其余 Cisco 未索引案例同样按 UNKNOWN 失败关闭。",
        "",
        "## 总体指标",
        "",
        "| 系统 | 恶意非放行召回 | 恶意BLOCK | 良性ALLOW | 良性BLOCK | REVIEW | UNKNOWN | BLOCK宏F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for system in SYSTEMS:
        item = report["systems"][system]
        lines.append(
            f"| {system} {names[system]} | {_fmt(item['malicious_non_allow_recall'])} | "
            f"{_fmt(item['malicious_block_rate'])} | {_fmt(item['benign_allow_rate'])} | "
            f"{_fmt(item['benign_block_rate'])} | {_fmt(item['review_rate'])} | "
            f"{_fmt(item['unknown_rate'])} | {item['macro_f1_binary_block']:.3f} |"
        )
    comparison = report["paired_comparisons"]["S5_vs_S4"]
    acceptance = report["acceptance"]
    lines.extend(
        [
            "",
            "## 主接受门：S5 对 S4",
            "",
            f"- 恶意非放行召回变化：{comparison['malicious_non_allow_recall_delta']['estimate']:+.1%}，"
            f"95% CI [{comparison['malicious_non_allow_recall_delta']['ci95'][0]:+.1%}, "
            f"{comparison['malicious_non_allow_recall_delta']['ci95'][1]:+.1%}]。",
            f"- 良性自动放行率变化：{comparison['benign_allow_rate_delta']['estimate']:+.1%}。",
            f"- 良性直接阻断率变化：{comparison['benign_block_rate_delta']['estimate']:+.1%}。",
            f"- 接受门：**{'通过' if acceptance['passed'] else '不通过'}**。",
            "",
            "## 组件结论",
            "",
            f"- 能力一致性增量案例：{report['transition_counts']['S1_to_S2_changed']}。",
            f"- 确定性语义增量案例：{report['transition_counts']['S1_to_S3_changed']}。",
            f"- 轻量模型改变最终决策：{report['transition_counts']['S4_to_S5_changed']}。",
            f"- 相同轻量模型条件下 Qwen 改变最终决策：{report['transition_counts']['S6_to_S5_changed']}。",
            "- 逐来源指标、Bootstrap、McNemar、决策迁移和规则误差明细见 `metrics.json`。",
            "",
            "## 结论边界",
            "",
            "本实验使用公开静态 Skill 文本快照，不执行样本代码。来源与标签高度相关；因此总分必须和逐来源结果、良性损失及 UNKNOWN 一起解释。",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def evaluate_validation(data_root: Path, output_root: Path) -> dict[str, Any]:
    run_root = scan_root(output_root, "validation", None)
    receipt_path = run_root / "VALIDATION_EVALUATION_COMPLETE.json"
    metrics_path = run_root / "metrics.json"
    if receipt_path.is_file():
        receipt = load_json(receipt_path)
        if (
            receipt.get("experiment_id") != EXPERIMENT_ID
            or receipt.get("metrics_sha256") != sha256_file(metrics_path)
            or receipt.get("completed_evaluation_runs") != 1
        ):
            raise ScanError("Existing validation evaluation receipt drifted")
        return load_json(metrics_path)

    verification = verify_scan_inputs(data_root, ("validation",))
    manifest = load_json(run_root / "run_manifest.json")
    result_path = run_root / "scan_results.label_blind.jsonl"
    if manifest.get("status") != "scan_complete_labels_not_joined":
        raise ScanError("Validation label-blind scan is incomplete")
    if manifest.get("ground_truth_opened") is not False:
        raise ScanError("Validation scan label firewall receipt is invalid")
    if sha256_file(result_path) != manifest.get("results_sha256"):
        raise ScanError("Validation label-blind results drifted")
    if manifest.get("input_tree_sha256_after") != verification["splits"]["validation"]["scan_input_tree_sha256"]:
        raise ScanError("Validation input tree drifted before label join")
    results = load_jsonl(result_path)
    if len(results) != 835 or any({"label", "source_id", "ground_truth"} & set(row) for row in results):
        raise ScanError("Validation results count or label firewall is invalid")

    label_path = data_root / "validation" / "ground_truth" / "labels.jsonl"
    labels = load_jsonl(label_path)
    label_counts: dict[str, int] = {}
    for row in labels:
        label_counts[str(row["label"])] = label_counts.get(str(row["label"]), 0) + 1
    if len(labels) != 835 or label_counts != {"0": 169, "1": 666}:
        raise ScanError("Validation ground truth identity drifted")
    by_id = {row["case_id"]: row for row in labels}
    if len(by_id) != len(labels):
        raise ScanError("Validation ground truth contains duplicate IDs")
    joined: list[dict[str, Any]] = []
    for result in results:
        truth = by_id.get(result["case_id"])
        if truth is None:
            raise ScanError(f"Validation ground truth missing case: {result['case_id']}")
        joined.append({**result, **truth})

    systems = {system: binary_decision_metrics(joined, system) for system in SYSTEMS}
    comparisons = {
        "S1_vs_S0": paired_comparison(joined, "S0", "S1"),
        "S2_vs_S1": paired_comparison(joined, "S1", "S2"),
        "S3_vs_S1": paired_comparison(joined, "S1", "S3"),
        "S5_vs_S4": paired_comparison(joined, "S4", "S5"),
        "S5_vs_S6": paired_comparison(joined, "S6", "S5"),
    }
    per_source: dict[str, Any] = {}
    for source_id in sorted({row["source_id"] for row in joined}):
        subset = [row for row in joined if row["source_id"] == source_id]
        per_source[source_id] = {
            "label_counts": {
                label: sum(row["label"] == label for row in subset) for label in ("0", "1")
            },
            "systems": {system: binary_decision_metrics(subset, system) for system in SYSTEMS},
        }
    transitions = {
        "S1_to_S2_changed": sum(row["systems"]["S1"]["decision"] != row["systems"]["S2"]["decision"] for row in joined),
        "S1_to_S3_changed": sum(row["systems"]["S1"]["decision"] != row["systems"]["S3"]["decision"] for row in joined),
        "S4_to_S5_changed": sum(row["systems"]["S4"]["decision"] != row["systems"]["S5"]["decision"] for row in joined),
        "S6_to_S5_changed": sum(row["systems"]["S6"]["decision"] != row["systems"]["S5"]["decision"] for row in joined),
    }
    main = comparisons["S5_vs_S4"]
    malicious_delta = main["malicious_non_allow_recall_delta"]
    benign_allow_delta = main["benign_allow_rate_delta"]["estimate"]
    benign_block_delta = main["benign_block_rate_delta"]["estimate"]
    checks = {
        "malicious_gain": bool(
            (malicious_delta["estimate"] or 0.0) >= 0.08
            or (malicious_delta["ci95"][0] is not None and malicious_delta["ci95"][0] > 0)
        ),
        "benign_allow_loss": benign_allow_delta is not None and benign_allow_delta >= -0.05,
        "benign_block_increase": benign_block_delta is not None and benign_block_delta <= 0.01,
        "unknown_not_higher": systems["S5"]["unknown_rate"] <= systems["S4"]["unknown_rate"],
        "input_tree_unchanged": manifest.get("input_tree_unchanged") is True,
        "single_completed_evaluation": True,
    }
    acceptance = {"checks": checks, "passed": all(checks.values())}
    durations = [int(row.get("duration_ms") or 0) for row in joined]
    report = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "status": "evaluation_complete",
        "evaluated_at": now_iso(),
        "cases": len(joined),
        "label_counts": label_counts,
        "systems": systems,
        "paired_comparisons": comparisons,
        "transition_counts": transitions,
        "acceptance": acceptance,
        "per_source": per_source,
        "runtime": {
            "scan_duration_ms": manifest.get("scan_duration_ms_this_invocation"),
            "case_duration_p50_ms": statistics.median(durations),
            "case_duration_p95_ms": sorted(durations)[max(0, math.ceil(0.95 * len(durations)) - 1)],
            "qwen_routed_cases": manifest.get("qwen_routed_cases"),
            "qwen_calls": manifest.get("qwen_calls"),
            "qwen_failures": manifest.get("qwen_failures"),
            "lightweight_model_review_cases": manifest.get("lightweight_model_review_cases"),
        },
        "unknown_reason_counts": {
            reason: sum(
                row["systems"]["S5"]["decision"] == "UNKNOWN"
                and row["systems"]["S5"]["reason_code"] == reason
                for row in joined
            )
            for reason in sorted(
                {
                    row["systems"]["S5"]["reason_code"]
                    for row in joined
                    if row["systems"]["S5"]["decision"] == "UNKNOWN"
                }
            )
        },
        "claim_boundary": "Released static Skill text only; no benchmark script was executed.",
    }
    write_jsonl(run_root / "evaluated_results.jsonl", joined)
    write_json(metrics_path, report)
    report_path = run_root / "REPORT.md"
    write_e01_report(report_path, report)
    receipt = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "status": "complete",
        "completed_at": now_iso(),
        "completed_evaluation_runs": 1,
        "label_sha256": sha256_file(label_path),
        "label_blind_results_sha256": sha256_file(result_path),
        "metrics_sha256": sha256_file(metrics_path),
        "report_sha256": sha256_file(report_path),
        "input_tree_sha256": verification["splits"]["validation"]["scan_input_tree_sha256"],
    }
    write_json(receipt_path, receipt)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run label-blind M15 E01 S0-S6 static scans.")
    parser.add_argument("command", choices=("scan", "route-preflight", "qwen-smoke", "evaluate"))
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--split", choices=("train", "validation"), default="validation")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--max-hits", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "scan":
        result = scan(
            args.data_root.resolve(),
            args.output_root.resolve(),
            args.split,
            args.limit,
            args.workers,
        )
    elif args.command == "route-preflight":
        result = route_preflight(args.data_root.resolve(), args.split, args.max_hits)
    elif args.command == "evaluate":
        result = evaluate_validation(args.data_root.resolve(), args.output_root.resolve())
    else:
        result = qwen_smoke(args.data_root.resolve(), args.output_root.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
