from __future__ import annotations

import argparse
import json
import math
import platform
import random
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.analyzers import (  # noqa: E402
    analyze_command_context,
    analyze_enterprise_controls,
    analyze_filesystem_context,
    analyze_network_context,
    analyze_sensitive_flows,
    analyze_static_coverage,
    analyze_skill_tree,
    analyze_untrusted_exec_flows,
)
from backend.policy import evaluate_findings  # noqa: E402
from tools.datasets.prepare_skilltrustbench import tree_sha256  # noqa: E402
from tools.evaluation.run_skilltrustbench import (  # noqa: E402
    EvaluationError,
    compute_metrics,
    load_json,
    load_jsonl,
    sha256_file,
    write_json,
    write_jsonl,
)


RUN_ID = "2026-08-22-static-audit-regression600-v1"
SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
PARENT_RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
FROZEN_STATIC_COMMIT = "f84927893a6bedcde4afa049a28c04be59316b73"
BOOTSTRAP_SEED = 20260822
BOOTSTRAP_SAMPLES = 10_000
EXPECTED_CASES = 600
EXPECTED_BALANCE = {"normal": 200, "suspicious": 200, "malicious": 200}
DECISION_TO_LABEL = {
    "ALLOW": "normal",
    "REVIEW": "suspicious",
    "BLOCK": "malicious",
    "UNKNOWN": "abstain",
}

SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
PARENT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / PARENT_RUN_ID
BASELINE_ROOT = DEMO_ROOT / "baseline" / "skilltrustbench_v1_0" / "full_cisco_static_v1"
CASES_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full" / "cases"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
REGRESSION_PATH = SPLIT_ROOT / "regression_cases.jsonl"
REGRESSION_IDS_PATH = SPLIT_ROOT / "regression_case_ids.txt"
PARENT_RESULTS_PATH = PARENT_ROOT / "per_case_results.jsonl"

EXPECTED_HASHES = {
    "split_manifest": (
        SPLIT_ROOT / "split_manifest.json",
        "618bbf96ed790304600d888076de91556ba42b316ebd525b38b01549e0c0652b",
    ),
    "split_verification": (
        SPLIT_ROOT / "verification.json",
        "9177d213ac53468b47fbdd6e0778fa0d710a09dfa584cbfa705380b47e4abd2e",
    ),
    "regression_cases": (
        REGRESSION_PATH,
        "8ee8745594cf2d7ef643cf95e61ccd88c420b42c540780dadb7320cbe7c90492",
    ),
    "regression_ids": (
        REGRESSION_IDS_PATH,
        "cd83b4f4251b23701fdd98b6b9d3899777ca41f9d573d4fb502ce3307f0cc07d",
    ),
    "parent_results": (
        PARENT_RESULTS_PATH,
        "15a9ec0cdb3b30d7d55d4a3f67e8a31b9f324f7724c46ede83ec07d5f79cd918",
    ),
    "parent_freeze": (
        BASELINE_ROOT / "freeze_manifest.json",
        "e4ed096b3de5ed25a8397899906524f4f8a257ead380a07f273c661088bf17e4",
    ),
    "metric_contract": (
        BASELINE_ROOT / "json" / "metric_contract.json",
        "d7c6fd64ffde14e50c1cd112a8923857b88dbcf4b1068600d75aa3650c4eb2ac",
    ),
    "policy": (
        DEMO_ROOT / "config" / "admission_policy.yaml",
        "010ca27b327e5098b11d7819563b40a607cac7698ac01019740557b8eaececf5",
    ),
    "aegis_static": (
        DEMO_ROOT / "backend" / "analyzers" / "aegis_static.py",
        "95b026050459a3aa5024d24f2e1487b9139982fb6a675959d10306dd2cb82351",
    ),
    "sensitive_flow": (
        DEMO_ROOT / "backend" / "analyzers" / "sensitive_flow.py",
        "d35cdb49691e2ebc6a2a852d5f2260d7e387e4787067c29d49bd5755e5bf427a",
    ),
    "untrusted_exec_flow": (
        DEMO_ROOT / "backend" / "analyzers" / "untrusted_exec_flow.py",
        "41d39b2d866fc24f2573f5a97fb5954507eb3ff28c0a51d4e0fb6459e5aeec18",
    ),
    "enterprise_controls": (
        DEMO_ROOT / "backend" / "analyzers" / "enterprise_controls.py",
        "1809df21cd15546e65e7d7ece8a6f2b3c79b7bd40c5eb2a833a1b72f84927e1d",
    ),
    "static_coverage": (
        DEMO_ROOT / "backend" / "analyzers" / "static_coverage.py",
        "4a6dfe70d6fe5e3dfeb8399e421b0ad13aa063dd8e6e6a7040c207be87fe704e",
    ),
    "network_context": (
        DEMO_ROOT / "backend" / "analyzers" / "network_context.py",
        "59a0ab095c415bb81c01aae0c8e4baeb9ee4e5ff8a53c24ca4c4be8573facc00",
    ),
    "filesystem_context": (
        DEMO_ROOT / "backend" / "analyzers" / "filesystem_context.py",
        "4a8313178af5231b01cb2868bc63c94f9e1baf8d61022cd3194228a624fecaaa",
    ),
    "command_context": (
        DEMO_ROOT / "backend" / "analyzers" / "command_context.py",
        "3e0673d2e25cba35fd0cfecb03fddf8d56f1cc522773dd73f71ba110915d5a61",
    ),
}

GENERATED_OUTPUTS = {
    "seal_opened.json",
    "per_case_results.jsonl",
    "metrics.json",
    "statistical_tests.json",
    "error_slices.json",
    "rule_summary.json",
    "evaluation_summary.json",
    "run.log",
    "run_manifest.json",
    "verification.json",
    "failure_state.json",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_log(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"{now_iso()} {message}\n")
        output.flush()


def prediction_for_parent(parent: dict[str, Any]) -> str:
    if parent.get("status") != "completed":
        return "abstain"
    decision = str(parent.get("decision") or "UNKNOWN")
    return DECISION_TO_LABEL.get(decision, "abstain")


def compact_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for index, item in enumerate(findings, start=1):
        evidence = str(item.get("evidence") or "")
        evidence_type = evidence.split("=", 1)[0].split(";", 1)[0][:80]
        compact.append({
            "id": str(item.get("id") or f"aegis-finding-{index}"),
            "rule_id": str(item.get("rule_id") or "UNKNOWN_RULE"),
            "category": str(item.get("category") or "unknown"),
            "severity": str(item.get("severity") or "UNKNOWN").upper(),
            "analyzer": str(item.get("analyzer") or "unknown"),
            "location": str(item.get("location") or ""),
            "evidence_type": evidence_type,
        })
    return compact


def metric_record(
    row: dict[str, Any], prediction: str, duration_ms: int
) -> dict[str, Any]:
    return {
        "case_id": row["case_id"],
        "ground_truth": row["ground_truth"],
        "risk_labels": row.get("risk_labels") or [],
        "predicted_label": prediction,
        "duration_ms": max(0, int(duration_ms)),
    }


def strict_macro_f1(rows: list[dict[str, Any]], prediction_key: str) -> float:
    scores: list[float] = []
    for label in ("normal", "suspicious", "malicious"):
        tp = sum(row["ground_truth"] == label and row[prediction_key] == label for row in rows)
        fp = sum(row["ground_truth"] != label and row[prediction_key] == label for row in rows)
        fn = sum(row["ground_truth"] == label and row[prediction_key] != label for row in rows)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        scores.append(
            2 * precision * recall / (precision + recall)
            if precision + recall else 0.0
        )
    return statistics.fmean(scores) if rows else 0.0


def exact_mcnemar(rows: list[dict[str, Any]]) -> dict[str, Any]:
    baseline_only_correct = 0
    enhanced_only_correct = 0
    both_correct = 0
    both_wrong = 0
    for row in rows:
        baseline_correct = row["baseline_predicted_label"] == row["ground_truth"]
        enhanced_correct = row["enhanced_predicted_label"] == row["ground_truth"]
        if baseline_correct and enhanced_correct:
            both_correct += 1
        elif baseline_correct:
            baseline_only_correct += 1
        elif enhanced_correct:
            enhanced_only_correct += 1
        else:
            both_wrong += 1
    discordant = baseline_only_correct + enhanced_only_correct
    if discordant:
        tail = sum(
            math.comb(discordant, value)
            for value in range(min(baseline_only_correct, enhanced_only_correct) + 1)
        ) / (2 ** discordant)
        p_value = min(1.0, 2.0 * tail)
    else:
        p_value = 1.0
    return {
        "test": "two_sided_exact_mcnemar_binomial",
        "both_correct": both_correct,
        "baseline_only_correct": baseline_only_correct,
        "enhanced_only_correct": enhanced_only_correct,
        "both_wrong": both_wrong,
        "discordant_pairs": discordant,
        "p_value": p_value,
    }


def paired_bootstrap(rows: list[dict[str, Any]]) -> dict[str, Any]:
    generator = random.Random(BOOTSTRAP_SEED)
    deltas: list[float] = []
    for _ in range(BOOTSTRAP_SAMPLES):
        sampled = [rows[generator.randrange(len(rows))] for _ in rows]
        deltas.append(
            strict_macro_f1(sampled, "enhanced_predicted_label")
            - strict_macro_f1(sampled, "baseline_predicted_label")
        )
    ordered = sorted(deltas)
    lower = ordered[int((BOOTSTRAP_SAMPLES - 1) * 0.025)]
    upper = ordered[int((BOOTSTRAP_SAMPLES - 1) * 0.975)]
    return {
        "method": "paired_percentile_bootstrap",
        "samples": BOOTSTRAP_SAMPLES,
        "seed": BOOTSTRAP_SEED,
        "confidence_level": 0.95,
        "delta_strict_macro_f1_mean": statistics.fmean(deltas),
        "ci_lower": lower,
        "ci_upper": upper,
    }


def selected_deltas(baseline: dict[str, Any], enhanced: dict[str, Any]) -> dict[str, float]:
    keys = (
        "coverage",
        "failure_rate",
        "strict_macro_f1",
        "covered_macro_f1",
        "malicious_recall",
        "malicious_fnr",
        "non_normal_recall",
        "normal_fpr",
        "supplementary_accuracy",
        "latency_median_ms",
        "latency_p95_ms",
        "latency_max_ms",
    )
    return {key: float(enhanced[key]) - float(baseline[key]) for key in keys}


def classify_verdict(
    integrity: dict[str, Any], deltas: dict[str, float], bootstrap: dict[str, Any]
) -> tuple[str, str]:
    if not integrity["comparable"]:
        return "not_comparable", "修复完整性或执行失败后，使用新的回归集和 run ID 重做评测。"
    macro_delta = deltas["strict_macro_f1"]
    malicious_delta = deltas["malicious_recall"]
    fpr_delta = deltas["normal_fpr"]
    if (
        macro_delta > 0
        and bootstrap["ci_lower"] > 0
        and malicious_delta >= 0
        and fpr_delta <= 0.02
    ):
        return "strongly_supported", "冻结静态审计 v1；下一阶段转入动态审计，不再使用本回归集调规则。"
    if macro_delta < 0 or malicious_delta < 0 or fpr_delta > 0.05:
        return "refuted", "冻结失败结论并开展新一轮错误分析；规则变更后必须另建回归集。"
    if macro_delta > 0 and malicious_delta >= 0:
        return "supported_with_tradeoff", "保留增强结论及权衡说明；不在本回归集上继续调参。"
    return "inconclusive", "记录结果但不作增强性能主张；使用独立新数据补充验证。"


def hash_snapshot() -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for name, (path, expected) in EXPECTED_HASHES.items():
        if not path.is_file():
            raise EvaluationError(f"Required frozen input is missing: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise EvaluationError(f"Frozen input hash mismatch for {name}: {actual} != {expected}")
        snapshot[name] = {"path": str(path), "sha256": actual, "bytes": path.stat().st_size}
    return snapshot


def synthetic_self_test() -> dict[str, Any]:
    rows = [
        {"case_id": "n", "ground_truth": "normal", "risk_labels": [], "predicted_label": "normal", "duration_ms": 1},
        {"case_id": "s", "ground_truth": "suspicious", "risk_labels": [], "predicted_label": "suspicious", "duration_ms": 2},
        {"case_id": "m", "ground_truth": "malicious", "risk_labels": [], "predicted_label": "abstain", "duration_ms": 3},
    ]
    metrics = compute_metrics(rows, "full")
    if not math.isclose(metrics["strict_macro_f1"], 2 / 3, abs_tol=1e-12):
        raise EvaluationError("Synthetic strict macro-F1 self-test failed")
    if not math.isclose(metrics["coverage"], 2 / 3, abs_tol=1e-12):
        raise EvaluationError("Synthetic coverage self-test failed")
    paired = [
        {"ground_truth": "malicious", "baseline_predicted_label": "normal", "enhanced_predicted_label": "malicious"},
        {"ground_truth": "normal", "baseline_predicted_label": "normal", "enhanced_predicted_label": "normal"},
    ]
    test = exact_mcnemar(paired)
    if test["enhanced_only_correct"] != 1 or test["baseline_only_correct"] != 0:
        raise EvaluationError("Synthetic paired-statistics self-test failed")
    return {"status": "passed", "strict_macro_f1": metrics["strict_macro_f1"]}


def preflight(output_dir: Path, require_clean_output: bool = True) -> dict[str, Any]:
    if require_clean_output:
        existing = sorted(name for name in GENERATED_OUTPUTS if (output_dir / name).exists())
        if existing:
            raise EvaluationError(f"Immutable output already contains generated files: {existing}")
    hashes = hash_snapshot()
    split = load_json(SPLIT_ROOT / "split_manifest.json")
    verification = load_json(SPLIT_ROOT / "verification.json")
    if split.get("split_id") != SPLIT_ID or verification.get("status") != "verified":
        raise EvaluationError("Regression split identity or verification status differs")
    if split.get("regression", {}).get("cases") != EXPECTED_CASES:
        raise EvaluationError("Regression split case count differs")
    if split.get("regression", {}).get("selection_uses_parent_scan_outcomes") is not False:
        raise EvaluationError("Regression selection is not independent of parent scan outcomes")
    metric_contract = load_json(BASELINE_ROOT / "json" / "metric_contract.json")
    if metric_contract.get("primary_metric") != "strict_macro_f1":
        raise EvaluationError("Frozen primary metric differs")
    return {
        "status": "passed",
        "run_id": RUN_ID,
        "regression_content_opened": False,
        "hashes": hashes,
        "synthetic_self_test": synthetic_self_test(),
    }


def analyze_case(case_root: Path, cisco_findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    analyzers: list[str] = []
    for function, uses_cisco in (
        (analyze_skill_tree, False),
        (analyze_sensitive_flows, False),
        (analyze_untrusted_exec_flows, False),
        (analyze_enterprise_controls, False),
        (analyze_static_coverage, False),
        (analyze_network_context, True),
        (analyze_filesystem_context, True),
        (analyze_command_context, True),
    ):
        current_findings, current_analyzers = (
            function(case_root, cisco_findings) if uses_cisco else function(case_root)
        )
        findings.extend(current_findings)
        analyzers.extend(current_analyzers)
    return findings, sorted(set(analyzers))


def summarize_rules(results: list[dict[str, Any]]) -> dict[str, Any]:
    rules: dict[str, Counter[str]] = defaultdict(Counter)
    analyzers: Counter[str] = Counter()
    changed_by_rule: Counter[str] = Counter()
    for row in results:
        for finding in row.get("aegis_findings") or []:
            rule_id = finding["rule_id"]
            rules[rule_id][row["ground_truth"]] += 1
            analyzers[finding["analyzer"]] += 1
            if row["baseline_decision"] != row["enhanced_decision"]:
                changed_by_rule[rule_id] += 1
    return {
        "rule_hits": {
            rule_id: {"total": sum(counts.values()), "by_ground_truth": dict(sorted(counts.items()))}
            for rule_id, counts in sorted(rules.items())
        },
        "analyzer_finding_counts": dict(sorted(analyzers.items())),
        "decision_changed_cases_by_present_rule": dict(sorted(changed_by_rule.items())),
    }


def build_error_slices(results: list[dict[str, Any]]) -> dict[str, Any]:
    def ids(system: str, truth: str | None = None, false_positive: bool = False) -> list[str]:
        prediction = f"{system}_predicted_label"
        selected: list[str] = []
        for row in results:
            if truth == "malicious" and row["ground_truth"] == truth and row[prediction] != truth:
                selected.append(row["case_id"])
            elif false_positive and row["ground_truth"] == "normal" and row[prediction] in {"suspicious", "malicious"}:
                selected.append(row["case_id"])
        return selected
    return {
        system: {
            "normal_false_positive_ids": ids(system, false_positive=True),
            "malicious_false_negative_ids": ids(system, truth="malicious"),
            "abstention_ids": [row["case_id"] for row in results if row[f"{system}_predicted_label"] == "abstain"],
        }
        for system in ("baseline", "enhanced")
    }


def evaluate_results(results: list[dict[str, Any]], integrity_failures: list[dict[str, str]]) -> dict[str, Any]:
    baseline_rows = [
        metric_record(row, row["baseline_predicted_label"], row["cisco_duration_ms"])
        for row in results
    ]
    enhanced_rows = [
        metric_record(row, row["enhanced_predicted_label"], row["estimated_total_duration_ms"])
        for row in results
    ]
    baseline = compute_metrics(baseline_rows, "full")
    enhanced = compute_metrics(enhanced_rows, "full")
    deltas = selected_deltas(baseline, enhanced)
    mcnemar = exact_mcnemar(results)
    bootstrap = paired_bootstrap(results)
    balance = Counter(row["ground_truth"] for row in results)
    unique_ids = len({row["case_id"] for row in results})
    enhancement_failures = sum(row["enhancement_status"] == "failed" for row in results)
    tree_mismatches = sum(not row.get("tree_hash_unchanged", True) for row in results)
    comparable = (
        len(results) == EXPECTED_CASES
        and unique_ids == EXPECTED_CASES
        and dict(balance) == EXPECTED_BALANCE
        and not integrity_failures
        and enhancement_failures == 0
        and tree_mismatches == 0
    )
    integrity = {
        "comparable": comparable,
        "cases": len(results),
        "unique_case_ids": unique_ids,
        "ground_truth_balance": dict(sorted(balance.items())),
        "enhancement_failures": enhancement_failures,
        "tree_hash_mismatches": tree_mismatches,
        "integrity_failures": integrity_failures,
    }
    verdict, next_action = classify_verdict(integrity, deltas, bootstrap)
    return {
        "baseline": baseline,
        "enhanced": enhanced,
        "deltas": deltas,
        "integrity": integrity,
        "statistics": {"mcnemar": mcnemar, "paired_bootstrap": bootstrap},
        "claim_verdict": verdict,
        "next_action": next_action,
    }


def verify_outputs(output_dir: Path) -> dict[str, Any]:
    results = load_jsonl(output_dir / "per_case_results.jsonl")
    stored_metrics = load_json(output_dir / "metrics.json")
    recomputed = evaluate_results(results, stored_metrics["integrity"]["integrity_failures"])
    comparable_keys = ("baseline", "enhanced", "deltas", "integrity", "statistics", "claim_verdict")
    equal = all(recomputed[key] == stored_metrics[key] for key in comparable_keys)
    current_hashes = hash_snapshot()
    manifest = load_json(output_dir / "run_manifest.json")
    output_hashes_match = all(
        sha256_file(output_dir / name) == record["sha256"]
        for name, record in manifest["outputs"].items()
    )
    verification = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "verified" if equal and output_hashes_match else "failed",
        "cases": len(results),
        "metrics_recomputed_equal": equal,
        "output_hashes_match": output_hashes_match,
        "frozen_inputs_match": all(
            current_hashes[name]["sha256"] == record["sha256"]
            for name, record in manifest["frozen_inputs"].items()
        ),
        "raw_sample_text_retained": False,
    }
    write_json(output_dir / "verification.json", verification)
    if verification["status"] != "verified" or not verification["frozen_inputs_match"]:
        raise EvaluationError("Output verification failed")
    return verification


def run(output_dir: Path) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    preflight_record = preflight(output_dir)
    log_path = output_dir / "run.log"
    started_at = now_iso()
    started = time.perf_counter()
    append_log(log_path, f"run_start id={RUN_ID} regression_opened=0")

    seal_record = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "opened_at": now_iso(),
        "reason": "authorized one-time frozen static-audit regression evaluation",
        "regression_cases_sha256": EXPECTED_HASHES["regression_cases"][1],
        "rules_locked": True,
    }
    write_json(output_dir / "seal_opened.json", seal_record)
    append_log(log_path, "seal_opened regression_content_read_authorized=1")

    regression = load_jsonl(REGRESSION_PATH)
    regression_ids = REGRESSION_IDS_PATH.read_text(encoding="utf-8").splitlines()
    if len(regression) != EXPECTED_CASES:
        raise EvaluationError(f"Expected {EXPECTED_CASES} regression cases, got {len(regression)}")
    if [str(row["case_id"]) for row in regression] != regression_ids:
        raise EvaluationError("Regression JSONL order differs from frozen ID list")
    balance = Counter(str(row["ground_truth"]) for row in regression)
    if dict(balance) != EXPECTED_BALANCE:
        raise EvaluationError(f"Regression ground-truth balance differs: {dict(balance)}")

    parent_rows = load_jsonl(PARENT_RESULTS_PATH)
    parent_map = {str(row["case_id"]): row for row in parent_rows}
    integrity_failures: list[dict[str, str]] = []
    results: list[dict[str, Any]] = []

    for index, regression_row in enumerate(regression, start=1):
        case_id = str(regression_row["case_id"])
        parent = parent_map.get(case_id)
        if parent is None:
            raise EvaluationError(f"Frozen parent result missing: {case_id}")
        if (
            str(parent.get("ground_truth")) != str(regression_row["ground_truth"])
            or str(parent.get("case_tree_sha256_before")) != str(regression_row["case_tree_sha256"])
        ):
            integrity_failures.append({"case_id": case_id, "reason": "parent_label_or_hash_mismatch"})

        baseline_decision = str(parent.get("decision") or "UNKNOWN")
        baseline_prediction = prediction_for_parent(parent)
        cisco_duration_ms = max(0, int(parent.get("duration_ms") or 0))
        enhanced_decision = baseline_decision if parent.get("status") == "completed" else "UNKNOWN"
        enhanced_prediction = baseline_prediction
        enhancement_status = "not_run_parent_abstention"
        enhancement_error: str | None = None
        aegis_duration_ms = 0
        aegis_findings: list[dict[str, Any]] = []
        aegis_analyzers: list[str] = []
        policy_trace: dict[str, Any] | None = None
        before_hash: str | None = None
        after_hash: str | None = None
        expected_hash = str(regression_row["case_tree_sha256"])

        if parent.get("status") == "completed":
            case_root = (CASES_ROOT / case_id).resolve()
            try:
                if case_root.parent != CASES_ROOT.resolve() or not case_root.is_dir():
                    raise EvaluationError("case directory missing or outside dataset root")
                before_hash = tree_sha256(case_root)
                if before_hash != expected_hash:
                    raise EvaluationError("case tree hash differs before analysis")
                case_started = time.perf_counter()
                raw_aegis_findings, aegis_analyzers = analyze_case(
                    case_root, list(parent.get("finding_index") or [])
                )
                aegis_duration_ms = max(1, round((time.perf_counter() - case_started) * 1000))
                evaluation = evaluate_findings(
                    list(parent.get("finding_index") or []) + raw_aegis_findings
                )
                after_hash = tree_sha256(case_root)
                if after_hash != expected_hash:
                    raise EvaluationError("case tree hash differs after analysis")
                enhanced_decision = evaluation.decision.value
                enhanced_prediction = DECISION_TO_LABEL.get(enhanced_decision, "abstain")
                policy_trace = evaluation.trace.model_dump(mode="json")
                aegis_findings = compact_findings(raw_aegis_findings)
                enhancement_status = "completed"
            except Exception as exc:  # continue to preserve a complete failure accounting
                enhancement_status = "failed"
                enhancement_error = f"{type(exc).__name__}: {exc}"
                enhanced_decision = "UNKNOWN"
                enhanced_prediction = "abstain"
                after_hash = tree_sha256(case_root) if case_root.is_dir() else None
                integrity_failures.append({"case_id": case_id, "reason": enhancement_error})

        result = {
            "schema_version": "1.0",
            "run_id": RUN_ID,
            "case_id": case_id,
            "ground_truth": str(regression_row["ground_truth"]),
            "risk_labels": regression_row.get("risk_labels") or [],
            "parent_status": str(parent.get("status")),
            "baseline_decision": baseline_decision,
            "baseline_predicted_label": baseline_prediction,
            "enhanced_decision": enhanced_decision,
            "enhanced_predicted_label": enhanced_prediction,
            "decision_changed": baseline_decision != enhanced_decision,
            "correctness_changed": (baseline_prediction == regression_row["ground_truth"]) != (enhanced_prediction == regression_row["ground_truth"]),
            "enhancement_status": enhancement_status,
            "enhancement_error": enhancement_error,
            "aegis_findings": aegis_findings,
            "aegis_analyzers": aegis_analyzers,
            "enhanced_policy_trace": policy_trace,
            "cisco_duration_ms": cisco_duration_ms,
            "aegis_incremental_duration_ms": aegis_duration_ms,
            "estimated_total_duration_ms": cisco_duration_ms + aegis_duration_ms,
            "case_tree_sha256_expected": expected_hash,
            "case_tree_sha256_before": before_hash,
            "case_tree_sha256_after": after_hash,
            "tree_hash_unchanged": before_hash == after_hash == expected_hash if before_hash is not None else True,
            "raw_text_retained": False,
        }
        results.append(result)
        if index % 25 == 0 or index == EXPECTED_CASES:
            append_log(
                log_path,
                f"progress cases={index}/{EXPECTED_CASES} enhancement_failures="
                f"{sum(row['enhancement_status'] == 'failed' for row in results)}",
            )
            print(f"[{index}/{EXPECTED_CASES}] completed", flush=True)

    metrics = evaluate_results(results, integrity_failures)
    write_jsonl(output_dir / "per_case_results.jsonl", results)
    write_json(output_dir / "metrics.json", metrics)
    write_json(output_dir / "statistical_tests.json", metrics["statistics"])
    write_json(output_dir / "error_slices.json", build_error_slices(results))
    write_json(output_dir / "rule_summary.json", summarize_rules(results))
    evaluation_summary = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "claim_verdict": metrics["claim_verdict"],
        "primary_metric": "strict_macro_f1",
        "baseline_strict_macro_f1": metrics["baseline"]["strict_macro_f1"],
        "enhanced_strict_macro_f1": metrics["enhanced"]["strict_macro_f1"],
        "delta_strict_macro_f1": metrics["deltas"]["strict_macro_f1"],
        "bootstrap_95_ci": [
            metrics["statistics"]["paired_bootstrap"]["ci_lower"],
            metrics["statistics"]["paired_bootstrap"]["ci_upper"],
        ],
        "malicious_recall_delta": metrics["deltas"]["malicious_recall"],
        "normal_fpr_delta": metrics["deltas"]["normal_fpr"],
        "next_action": metrics["next_action"],
        "claim_boundary": "Sealed engineering regression evidence, not an independent external benchmark.",
    }
    write_json(output_dir / "evaluation_summary.json", evaluation_summary)
    elapsed_seconds = round(time.perf_counter() - started, 3)
    append_log(
        log_path,
        f"run_end status=completed verdict={metrics['claim_verdict']} elapsed_seconds={elapsed_seconds}",
    )

    output_names = (
        "seal_opened.json",
        "per_case_results.jsonl",
        "metrics.json",
        "statistical_tests.json",
        "error_slices.json",
        "rule_summary.json",
        "evaluation_summary.json",
        "run.log",
    )
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "completed",
        "experiment_tier": "sealed_engineering_regression",
        "started_at": started_at,
        "completed_at": now_iso(),
        "elapsed_seconds": elapsed_seconds,
        "command": [sys.executable, *sys.argv],
        "frozen_static_commit": FROZEN_STATIC_COMMIT,
        "frozen_inputs": preflight_record["hashes"],
        "dataset": {
            "split_id": SPLIT_ID,
            "cases": len(results),
            "seal_opened_at": seal_record["opened_at"],
            "selection_uses_parent_scan_outcomes": False,
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "sample_execution": False,
            "sample_import": False,
            "sample_install": False,
            "network_fetch": False,
            "raw_sample_text_retained": False,
        },
        "latency_semantics": {
            "cisco_duration_ms": "frozen parent measurement",
            "aegis_incremental_duration_ms": "measured in this run",
            "estimated_total_duration_ms": "sum; estimated sequential total, not a fresh Cisco end-to-end measurement",
        },
        "outputs": {
            name: {"sha256": sha256_file(output_dir / name), "bytes": (output_dir / name).stat().st_size}
            for name in output_names
        },
        "claim_boundary": "Engineering regression comparison on a held-out split of previously used SkillTrustBench v1.0.",
    }
    write_json(output_dir / "run_manifest.json", manifest)
    verification = verify_outputs(output_dir)
    return {
        "run_id": RUN_ID,
        "status": "completed",
        "claim_verdict": metrics["claim_verdict"],
        "cases": len(results),
        "metrics": metrics,
        "verification": verification,
        "output_dir": str(output_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the one-time frozen 600-case static-audit regression")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    try:
        if args.preflight_only:
            payload = preflight(args.output_dir.resolve())
        elif args.verify_existing:
            payload = verify_outputs(args.output_dir.resolve())
        else:
            payload = run(args.output_dir)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        if not args.preflight_only and not args.verify_existing:
            args.output_dir.resolve().mkdir(parents=True, exist_ok=True)
            write_json(args.output_dir.resolve() / "failure_state.json", {
                "run_id": RUN_ID,
                "status": "failed",
                "failed_at": now_iso(),
                "error_type": type(exc).__name__,
                "error": str(exc),
                "results_must_not_be_overwritten": True,
            })
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
