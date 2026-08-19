from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from tools.evaluation.run_skilltrustbench import (  # noqa: E402
    EvaluationError,
    load_json,
    load_jsonl,
    sha256_file,
    write_json,
    write_jsonl,
)
from tools.evaluation.verify_skilltrustbench_run import verify_run  # noqa: E402


RUN_ID = "2026-08-14-skilltrustbench-full-cisco-parallel-v1"
SPLIT_ID = "2026-08-15-skilltrustbench-dev120-regression600-v1"
BASELINE_ID = "skilltrustbench-v1.0-full5520-cisco-static-v1"
FROZEN_AT = "2026-08-15"
DEVELOPMENT_SEED = "aegis-chain-skilltrustbench-development-v1"
REGRESSION_SEED = "aegis-chain-skilltrustbench-regression-v1"

DATA_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full"
RUN_ROOT = DEMO_ROOT / "artifacts" / "analysis" / RUN_ID
SPLIT_ROOT = DEMO_ROOT / "artifacts" / "analysis" / SPLIT_ID
BASELINE_ROOT = DEMO_ROOT / "baseline" / "skilltrustbench_v1_0" / "full_cisco_static_v1"

DEVELOPMENT_GROUPS = {
    "miss_wild_real_world": 24,
    "miss_T06_persistence": 12,
    "miss_T09_insecure_coding": 12,
    "miss_T05_privilege_boundary": 12,
    "fp_network_context": 16,
    "fp_filesystem_context": 8,
    "fp_command_context": 6,
    "fp_file_integrity": 4,
    "fp_secret_pattern": 4,
    "fp_social_or_manifest": 2,
    "control_normal_true_negative": 10,
    "control_suspicious_correct": 5,
    "control_malicious_correct": 5,
}

FALSE_POSITIVE_RULE_GROUPS = {
    "fp_network_context": {
        "TOOL_ABUSE_UNDECLARED_NETWORK",
        "DATA_EXFIL_NETWORK_REQUESTS",
    },
    "fp_filesystem_context": {"DATA_EXFIL_JS_FS_ACCESS"},
    "fp_command_context": {
        "COMMAND_INJECTION_JS_CHILD_PROCESS",
        "COMMAND_INJECTION_EVAL",
        "YARA_command_injection_generic",
        "YARA_sql_injection_generic",
    },
    "fp_file_integrity": {"FILE_MAGIC_MISMATCH"},
    "fp_secret_pattern": {"SECRET_GITHUB_TOKEN", "SECRET_STRIPE_KEY"},
    "fp_social_or_manifest": {
        "SOCIAL_ENG_MISLEADING_DESC",
        "MANIFEST_DESCRIPTION_TOO_LONG",
    },
}


def stable_rank(case_id: str, seed: str) -> str:
    return hashlib.sha256(f"{seed}:{case_id}".encode("utf-8")).hexdigest()


def identity(path: Path, *, relative_to: Path = DEMO_ROOT) -> dict[str, Any]:
    resolved = path.resolve()
    try:
        display_path = resolved.relative_to(relative_to.resolve()).as_posix()
    except ValueError:
        display_path = str(resolved)
    return {
        "path": display_path,
        "bytes": resolved.stat().st_size,
        "sha256": sha256_file(resolved),
    }


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        output.write(text)
    os.replace(temporary, path)


def ids_text(records: Iterable[dict[str, Any]], key: str = "case_id") -> str:
    return "".join(f"{row[key]}\n" for row in records)


def rule_ids(result: dict[str, Any]) -> list[str]:
    return sorted({
        str(finding.get("rule_id"))
        for finding in result.get("finding_index", [])
        if finding.get("rule_id")
    })


def take_group(
    candidates: Iterable[dict[str, Any]],
    count: int,
    group: str,
    selected_ids: set[str],
    *,
    predicate: Callable[[dict[str, Any]], bool] | None = None,
) -> list[tuple[dict[str, Any], str]]:
    eligible = [
        row for row in candidates
        if str(row["case_id"]) not in selected_ids and (predicate is None or predicate(row))
    ]
    eligible.sort(key=lambda row: (stable_rank(str(row["case_id"]), DEVELOPMENT_SEED), str(row["case_id"])))
    if len(eligible) < count:
        raise EvaluationError(f"Development group {group} has only {len(eligible)} eligible cases; need {count}")
    chosen = eligible[:count]
    selected_ids.update(str(row["case_id"]) for row in chosen)
    return [(row, group) for row in chosen]


def validate_parent(
    manifest_rows: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    if len(manifest_rows) != 5_520 or len(results) != 5_520:
        raise EvaluationError(
            f"Expected the frozen 5,520-case parent; manifest={len(manifest_rows)}, results={len(results)}"
        )
    manifest_by_id = {str(row["id"]): row for row in manifest_rows}
    result_by_id = {str(row["case_id"]): row for row in results}
    if len(manifest_by_id) != len(manifest_rows) or len(result_by_id) != len(results):
        raise EvaluationError("Parent manifest or result contains duplicate case IDs")
    if set(manifest_by_id) != set(result_by_id):
        raise EvaluationError("Parent manifest and result case-ID sets differ")
    for case_id, source in manifest_by_id.items():
        result = result_by_id[case_id]
        expected_hash = source.get("case_tree_sha256")
        if result.get("ground_truth") != source.get("judgment"):
            raise EvaluationError(f"Ground truth differs for {case_id}")
        if result.get("case_tree_sha256_before") != expected_hash:
            raise EvaluationError(f"Before-scan case hash differs for {case_id}")
        if result.get("case_tree_sha256_after") != expected_hash:
            raise EvaluationError(f"After-scan case hash differs for {case_id}")
    return manifest_by_id, result_by_id


def join_rows(
    manifest_by_id: dict[str, dict[str, Any]],
    result_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_id in sorted(manifest_by_id):
        source = manifest_by_id[case_id]
        result = result_by_id[case_id]
        rows.append({
            "case_id": case_id,
            "ground_truth": str(source["judgment"]),
            "risk_labels": [str(value) for value in source.get("risk_labels", [])],
            "source": str(source.get("source")),
            "base_category": str(source.get("base_category")),
            "primary_pattern": source.get("primary_pattern"),
            "attack_patterns": [str(value) for value in source.get("attack_pattern", [])],
            "case_tree_sha256": str(source["case_tree_sha256"]),
            "scanner_eligible": source.get("scanner_eligible") is not False,
            "status": str(result.get("status")),
            "decision": str(result.get("decision")),
            "predicted_label": str(result.get("predicted_label")),
            "matched_rule_ids": rule_ids(result),
            "finding_summary": result.get("summary", {}),
        })
    return rows


def build_development(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected_ids: set[str] = set()
    selections: list[tuple[dict[str, Any], str]] = []
    completed = [row for row in rows if row["status"] == "completed"]
    misses = [
        row for row in completed
        if row["ground_truth"] in {"suspicious", "malicious"} and row["decision"] == "ALLOW"
    ]
    selections += take_group(
        misses,
        DEVELOPMENT_GROUPS["miss_wild_real_world"],
        "miss_wild_real_world",
        selected_ids,
        predicate=lambda row: row["base_category"] == "wild_real_world",
    )
    selections += take_group(
        misses,
        DEVELOPMENT_GROUPS["miss_T06_persistence"],
        "miss_T06_persistence",
        selected_ids,
        predicate=lambda row: "T06" in row["risk_labels"],
    )
    selections += take_group(
        misses,
        DEVELOPMENT_GROUPS["miss_T09_insecure_coding"],
        "miss_T09_insecure_coding",
        selected_ids,
        predicate=lambda row: "T09" in row["risk_labels"],
    )
    selections += take_group(
        misses,
        DEVELOPMENT_GROUPS["miss_T05_privilege_boundary"],
        "miss_T05_privilege_boundary",
        selected_ids,
        predicate=lambda row: "T05" in row["risk_labels"],
    )

    false_positives = [
        row for row in completed
        if row["ground_truth"] == "normal" and row["decision"] in {"REVIEW", "BLOCK"}
    ]
    for group, target_rules in FALSE_POSITIVE_RULE_GROUPS.items():
        selections += take_group(
            false_positives,
            DEVELOPMENT_GROUPS[group],
            group,
            selected_ids,
            predicate=lambda row, rules=target_rules: bool(set(row["matched_rule_ids"]) & rules),
        )

    true_normal = [
        row for row in completed
        if row["ground_truth"] == "normal" and row["decision"] == "ALLOW"
    ]
    correct_suspicious = [
        row for row in completed
        if row["ground_truth"] == "suspicious" and row["decision"] == "REVIEW"
    ]
    correct_malicious = [
        row for row in completed
        if row["ground_truth"] == "malicious" and row["decision"] == "BLOCK"
    ]
    selections += take_group(
        true_normal,
        DEVELOPMENT_GROUPS["control_normal_true_negative"],
        "control_normal_true_negative",
        selected_ids,
    )
    selections += take_group(
        correct_suspicious,
        DEVELOPMENT_GROUPS["control_suspicious_correct"],
        "control_suspicious_correct",
        selected_ids,
    )
    selections += take_group(
        correct_malicious,
        DEVELOPMENT_GROUPS["control_malicious_correct"],
        "control_malicious_correct",
        selected_ids,
    )

    development: list[dict[str, Any]] = []
    for row, group in selections:
        development.append({
            "schema_version": "1.0",
            "split_id": SPLIT_ID,
            "case_id": row["case_id"],
            "ground_truth": row["ground_truth"],
            "risk_labels": row["risk_labels"],
            "source": row["source"],
            "base_category": row["base_category"],
            "primary_pattern": row["primary_pattern"],
            "attack_patterns": row["attack_patterns"],
            "case_tree_sha256": row["case_tree_sha256"],
            "selection_group": group,
            "selection_rank": stable_rank(row["case_id"], DEVELOPMENT_SEED),
            "baseline_status": row["status"],
            "baseline_decision": row["decision"],
            "baseline_predicted_label": row["predicted_label"],
            "baseline_matched_rule_ids": row["matched_rule_ids"],
            "baseline_finding_summary": row["finding_summary"],
            "content_inspection_status": "authorized_read_only_pending",
        })
    if len(development) != 120 or len({row["case_id"] for row in development}) != 120:
        raise EvaluationError("Development selection is not exactly 120 unique cases")
    return development


def build_regression(
    manifest_rows: list[dict[str, Any]],
    excluded_ids: set[str],
) -> list[dict[str, Any]]:
    regression: list[dict[str, Any]] = []
    for label in ("normal", "suspicious", "malicious"):
        candidates = [
            row for row in manifest_rows
            if str(row["id"]) not in excluded_ids and str(row["judgment"]) == label
        ]
        candidates.sort(key=lambda row: (
            stable_rank(str(row["id"]), REGRESSION_SEED),
            str(row["id"]),
        ))
        if len(candidates) < 200:
            raise EvaluationError(f"Regression label {label} has only {len(candidates)} candidates")
        for row in candidates[:200]:
            regression.append({
                "schema_version": "1.0",
                "split_id": SPLIT_ID,
                "case_id": str(row["id"]),
                "ground_truth": label,
                "risk_labels": [str(value) for value in row.get("risk_labels", [])],
                "case_tree_sha256": str(row["case_tree_sha256"]),
                "selection_rank": stable_rank(str(row["id"]), REGRESSION_SEED),
                "content_inspection_status": "sealed_not_inspected",
                "allowed_fields": [
                    "case_id", "ground_truth", "risk_labels", "case_tree_sha256", "selection_rank"
                ],
            })
    regression.sort(key=lambda row: (row["ground_truth"], row["selection_rank"], row["case_id"]))
    if len(regression) != 600 or len({row["case_id"] for row in regression}) != 600:
        raise EvaluationError("Regression selection is not exactly 600 unique cases")
    return regression


def metric_contract(metrics: dict[str, Any]) -> dict[str, Any]:
    parent_contract = load_json(DEMO_ROOT / "baseline" / "skilltrustbench_v1_0" / "json" / "metric_contract.json")
    return {
        "schema_version": "1.0",
        "contract_id": "skilltrustbench-v1.0-full5520-cisco-static-metrics-v1",
        "baseline_id": BASELINE_ID,
        "status": "frozen_post_run_from_preexisting_metric_definitions",
        "task": parent_contract["task"],
        "primary_metric": parent_contract["primary_metric"],
        "dataset": {
            "repository": "cuhk-zhuque/SkillTrustBench",
            "content_revision": "762d5388b3a047b26df9679582af868a0e5b2c8f",
            "split": "full_dataset_v1.0",
            "cases": 5_520,
            "case_ids_sha256": "99ed464424ef589d76d28f5762fd88dc0b62bd96dc88dfcd9a5b867add9ab4a1",
            "source_manifest_sha256": "3a061cda6145151fbac0cbabfab7ee16e7ca60d50659eb45c73807dd037ba6ac",
        },
        "prediction_mapping": parent_contract["prediction_mapping"],
        "abstention_policy": parent_contract["abstention_policy"],
        "operational_gate": parent_contract["operational_gate"],
        "metrics": parent_contract["metrics"],
        "observed_values": {
            key: metrics[key]
            for key in (
                "coverage", "failure_rate", "strict_macro_f1", "covered_macro_f1",
                "malicious_recall", "malicious_fnr", "non_normal_recall", "normal_fpr",
                "per_risk_label_recall", "latency_median_ms", "latency_p95_ms", "latency_max_ms",
            )
        },
        "required_outputs": parent_contract["required_outputs"] + ["verification.json"],
        "known_deviations": [
            "Metric definitions were frozen before scanning in the pilot contract, but the full-dataset scope record is frozen after the completed run.",
            "The full run is therefore a verified engineering baseline, not a preregistered blind test.",
            "148 cases abstained because of endpoint protection, platform path incompatibility, or scanner runtime errors.",
        ],
        "claim_boundaries": [
            "This full-dataset result may be reported as the frozen Cisco static baseline.",
            "The same 5,520 cases must not be repeatedly tuned and then presented as an unbiased final evaluation.",
            "The sealed regression split is for engineering regression detection, not a new independent benchmark.",
            "Covered-only metrics may not be reported without strict metrics, coverage, and abstention counts.",
            "Operational not-auto-allow rate may not be presented as detection accuracy.",
        ],
    }


def verify_existing_freeze(freeze_path: Path, digest_path: Path) -> dict[str, Any]:
    if not freeze_path.is_file() or not digest_path.is_file():
        raise EvaluationError("Frozen baseline is incomplete: freeze manifest and digest must both exist")
    digest_parts = digest_path.read_text(encoding="utf-8").strip().split()
    if len(digest_parts) != 2 or digest_parts[1] != freeze_path.name:
        raise EvaluationError("Frozen baseline digest file has an unexpected format")
    if sha256_file(freeze_path) != digest_parts[0]:
        raise EvaluationError("Frozen baseline manifest SHA-256 differs from FREEZE_SHA256.txt")
    frozen = load_json(freeze_path)
    if frozen.get("baseline_id") != BASELINE_ID or frozen.get("parent_run_id") != RUN_ID:
        raise EvaluationError("Frozen baseline identity differs")
    artifacts = frozen.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise EvaluationError("Frozen baseline has no source-artifact identities")
    for item in artifacts:
        declared = Path(str(item.get("path")))
        path = declared if declared.is_absolute() else DEMO_ROOT / declared
        if not path.is_file():
            raise EvaluationError(f"Frozen baseline artifact is missing: {item.get('path')}")
        if path.stat().st_size != item.get("bytes"):
            raise EvaluationError(f"Frozen baseline artifact byte size differs: {item.get('path')}")
        if sha256_file(path) != item.get("sha256"):
            raise EvaluationError(f"Frozen baseline artifact SHA-256 differs: {item.get('path')}")
    return frozen


def freeze_baseline(metrics: dict[str, Any], verified: dict[str, Any]) -> dict[str, Any]:
    contract = metric_contract(metrics)
    contract_path = BASELINE_ROOT / "json" / "metric_contract.json"
    acceptance_path = BASELINE_ROOT / "local_acceptance.json"
    provenance_path = BASELINE_ROOT / "provenance.json"
    baseline_readme_path = BASELINE_ROOT / "BASELINE.md"
    freeze_path = BASELINE_ROOT / "freeze_manifest.json"
    digest_path = BASELINE_ROOT / "FREEZE_SHA256.txt"

    if freeze_path.exists() or digest_path.exists():
        return verify_existing_freeze(freeze_path, digest_path)

    write_json(contract_path, contract)
    write_json(acceptance_path, {
        "schema_version": "1.0",
        "baseline_id": BASELINE_ID,
        "decision": "accepted_with_caveats",
        "comparison_ready": True,
        "performance_measured": True,
        "accepted_at": FROZEN_AT,
        "verification_status": verified["status"],
        "reasons": [
            "All 5,520 cases reached a terminal result and all completed sample tree hashes were unchanged.",
            "Metrics, confusion matrix, and error slices were independently recomputed from per-case results.",
            "All declared run outputs passed byte-size and SHA-256 verification.",
            "The scanner, policy, dataset revision, mapping, and abstention rules are explicit.",
        ],
        "caveats": contract["known_deviations"],
        "acceptance_method": "Local evidence record because the quest artifact confirmation service is unavailable in this workspace.",
    })
    write_json(provenance_path, {
        "schema_version": "1.0",
        "baseline_id": BASELINE_ID,
        "baseline_kind": "verified_local_full_dataset_static_scan",
        "frozen_at": FROZEN_AT,
        "parent_run_id": RUN_ID,
        "dataset": contract["dataset"],
        "scanner": load_json(RUN_ROOT / "run_manifest.json")["scanner"],
        "policy": load_json(RUN_ROOT / "run_manifest.json")["policy"],
        "evaluation_path": "tools/evaluation/run_skilltrustbench.py --mode full --workers 4",
        "evidence_root": str(RUN_ROOT.resolve()),
    })
    write_text_atomic(baseline_readme_path, f"""# SkillTrustBench v1.0 全量 Cisco 静态基线\n\n状态：`comparison_ready / accepted_with_caveats`\n\n本目录冻结 `{RUN_ID}` 的 5,520 条全量结果。冻结后不得修改原始运行目录；后续规则和语义增强只在开发集上设计，并用封存回归集检查工程退化。\n\n## 核心结果\n\n- coverage：{metrics['coverage']:.2%}\n- strict macro F1：{metrics['strict_macro_f1']:.4f}\n- malicious recall：{metrics['malicious_recall']:.2%}\n- non-normal recall：{metrics['non_normal_recall']:.2%}\n- normal FPR：{metrics['normal_fpr']:.2%}\n- abstention：{metrics['abstention_count']} / 5,520\n\n## 边界\n\n这是一份经过独立复算和哈希核验的工程基线，但并非预注册盲测。完整数据已经参与误差分析，因此后续不能把同一 5,520 条上的调优结果称为无偏最终成绩。\n\n`freeze_manifest.json` 固定证据文件身份，`FREEZE_SHA256.txt` 固定冻结清单自身身份，`json/metric_contract.json` 固定比较口径。\n""")

    evidence_files = [
        RUN_ROOT / name for name in (
            "run_manifest.json", "per_case_results.jsonl", "metrics.json",
            "confusion_matrix.json", "false_positive_cases.jsonl",
            "false_negative_cases.jsonl", "classification_errors.jsonl",
            "evaluation_summary.json", "run.log", "verification.json",
        )
    ]
    evidence_files += [
        DEMO_ROOT / "docs" / "M2_SKILLTRUSTBENCH_FULL_REPORT.md",
        DATA_ROOT / "full_manifest.jsonl",
        DATA_ROOT / "full_case_ids.txt",
        DATA_ROOT / "intake_manifest.json",
        DEMO_ROOT / "tools" / "evaluation" / "run_skilltrustbench.py",
        DEMO_ROOT / "tools" / "evaluation" / "verify_skilltrustbench_run.py",
        DEMO_ROOT / "config" / "admission_policy.yaml",
        contract_path,
        acceptance_path,
        provenance_path,
        baseline_readme_path,
    ]
    missing = [str(path) for path in evidence_files if not path.is_file()]
    if missing:
        raise EvaluationError(f"Cannot freeze baseline; evidence files are missing: {missing}")
    freeze = {
        "schema_version": "1.0",
        "baseline_id": BASELINE_ID,
        "frozen_at": FROZEN_AT,
        "status": "locally_frozen_and_verified",
        "parent_run_id": RUN_ID,
        "run_verification": verified,
        "source_artifacts": [identity(path) for path in evidence_files],
        "immutability_rule": "Any byte or SHA-256 change invalidates this frozen baseline identity.",
    }
    write_json(freeze_path, freeze)
    freeze_digest = sha256_file(freeze_path)
    write_text_atomic(digest_path, f"{freeze_digest}  freeze_manifest.json\n")
    return freeze


def verify_splits(
    development: list[dict[str, Any]],
    regression: list[dict[str, Any]],
    manifest_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    dev_ids = {row["case_id"] for row in development}
    regression_ids = {row["case_id"] for row in regression}
    overlap = sorted(dev_ids & regression_ids)
    if overlap:
        raise EvaluationError(f"Development/regression overlap: {overlap[:10]}")
    for row in development + regression:
        source = manifest_by_id[row["case_id"]]
        if row["ground_truth"] != source["judgment"]:
            raise EvaluationError(f"Split label differs from source: {row['case_id']}")
        if row["case_tree_sha256"] != source["case_tree_sha256"]:
            raise EvaluationError(f"Split case hash differs from source: {row['case_id']}")
    regression_counts = dict(sorted(Counter(row["ground_truth"] for row in regression).items()))
    if regression_counts != {"malicious": 200, "normal": 200, "suspicious": 200}:
        raise EvaluationError(f"Regression labels are not balanced: {regression_counts}")
    development_groups = dict(sorted(Counter(row["selection_group"] for row in development).items()))
    if development_groups != dict(sorted(DEVELOPMENT_GROUPS.items())):
        raise EvaluationError(f"Development group counts differ: {development_groups}")
    return {
        "status": "verified",
        "split_id": SPLIT_ID,
        "parent_run_id": RUN_ID,
        "development_cases": len(development),
        "regression_cases": len(regression),
        "development_unique_ids": len(dev_ids),
        "regression_unique_ids": len(regression_ids),
        "overlap_cases": len(overlap),
        "development_groups": development_groups,
        "development_ground_truth": dict(sorted(Counter(row["ground_truth"] for row in development).items())),
        "regression_ground_truth": regression_counts,
        "source_label_and_hash_checks": len(development) + len(regression),
        "regression_content_inspected": False,
        "regression_selection_used_parent_scan_outcomes": False,
    }


def build() -> dict[str, Any]:
    verified = verify_run(RUN_ROOT)
    manifest_rows = load_jsonl(DATA_ROOT / "full_manifest.jsonl")
    results = load_jsonl(RUN_ROOT / "per_case_results.jsonl")
    manifest_by_id, result_by_id = validate_parent(manifest_rows, results)
    joined = join_rows(manifest_by_id, result_by_id)
    development = build_development(joined)
    development_ids = {row["case_id"] for row in development}
    regression = build_regression(manifest_rows, development_ids)

    SPLIT_ROOT.mkdir(parents=True, exist_ok=True)
    development_path = SPLIT_ROOT / "development_cases.jsonl"
    regression_path = SPLIT_ROOT / "regression_cases.jsonl"
    development_ids_path = SPLIT_ROOT / "development_case_ids.txt"
    regression_ids_path = SPLIT_ROOT / "regression_case_ids.txt"
    write_jsonl(development_path, development)
    write_jsonl(regression_path, regression)
    write_text_atomic(development_ids_path, ids_text(development))
    write_text_atomic(regression_ids_path, ids_text(regression))

    verification = verify_splits(development, regression, manifest_by_id)
    verification_path = SPLIT_ROOT / "verification.json"
    write_json(verification_path, verification)

    metrics = load_json(RUN_ROOT / "metrics.json")
    freeze = freeze_baseline(metrics, verified)
    split_manifest = {
        "schema_version": "1.0",
        "split_id": SPLIT_ID,
        "created_at": FROZEN_AT,
        "parent_baseline_id": BASELINE_ID,
        "parent_run_id": RUN_ID,
        "parent_run_freeze_manifest_sha256": sha256_file(BASELINE_ROOT / "freeze_manifest.json"),
        "purpose": {
            "development": "Visible error-analysis set for rule, evidence-correlation, and semantic-review design.",
            "regression": "Sealed engineering regression set; not an independent final benchmark.",
        },
        "development": {
            "cases": len(development),
            "seed": DEVELOPMENT_SEED,
            "selection_uses_parent_scan_outcomes": True,
            "groups": verification["development_groups"],
            "case_ids_sha256": hashlib.sha256(ids_text(development).encode("utf-8")).hexdigest(),
            "content_policy": "Read-only text inspection allowed; never execute, import, or install sample content.",
        },
        "regression": {
            "cases": len(regression),
            "seed": REGRESSION_SEED,
            "selection": "200 per ground-truth label by SHA-256(seed + ':' + case_id), excluding development IDs.",
            "selection_uses_parent_scan_outcomes": False,
            "case_ids_sha256": hashlib.sha256(ids_text(regression).encode("utf-8")).hexdigest(),
            "content_policy": "Sealed: only ID, labels, case-tree SHA-256, and deterministic rank may be processed.",
        },
        "outputs": {
            path.name: identity(path, relative_to=SPLIT_ROOT)
            for path in (
                development_path, regression_path, development_ids_path,
                regression_ids_path, verification_path,
            )
        },
        "safety": {
            "samples_executed": False,
            "sample_modules_imported": False,
            "sample_dependencies_installed": False,
            "regression_content_inspected": False,
        },
        "verification": verification,
    }
    write_json(SPLIT_ROOT / "split_manifest.json", split_manifest)
    return {
        "baseline": {
            "id": BASELINE_ID,
            "status": freeze["status"],
            "root": str(BASELINE_ROOT),
            "freeze_manifest_sha256": sha256_file(BASELINE_ROOT / "freeze_manifest.json"),
        },
        "split": {
            "id": SPLIT_ID,
            "root": str(SPLIT_ROOT),
            "development_cases": len(development),
            "regression_cases": len(regression),
            "verification": verification,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze the full Cisco baseline and build SkillTrustBench development/regression splits"
    )
    parser.parse_args()
    try:
        result = build()
    except (EvaluationError, OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"freeze/split failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
