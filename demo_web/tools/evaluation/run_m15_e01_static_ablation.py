from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from tools.datasets.prepare_m15_e01_splits import (  # noqa: E402
    DATASET_REVISION,
    EXPECTED_FILES,
    EXPECTED_LABEL_COUNTS,
    EXPECTED_SOURCE_COUNTS,
    public_text,
    sha256_file,
    verify_scan_inputs,
    verify_source_files,
)


EXPERIMENT_ID = "2026-09-06-m15-e01-static-ablation-v5"
CONFIG_PATH = DEMO_ROOT / "config" / "m15_e01_static_ablation_v5.json"
DEFAULT_SOURCE_ROOT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_v1"
DEFAULT_DATA_ROOT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_m15_e01_v1"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / EXPERIMENT_ID
MODEL_FILENAME = "tfidf_logistic_model.joblib"


class ExperimentError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ExperimentError(f"Expected JSON object: {path}")
    return payload


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


def _f1(precision: float, recall: float) -> float:
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def binary_metrics(labels: list[int], predictions: list[int]) -> dict[str, Any]:
    if len(labels) != len(predictions) or not labels:
        raise ExperimentError("Metric inputs are empty or misaligned")
    tp = sum(y == 1 and p == 1 for y, p in zip(labels, predictions))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, predictions))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, predictions))
    tn = sum(y == 0 and p == 0 for y, p in zip(labels, predictions))
    positives = tp + fn
    negatives = tn + fp
    recall = tp / positives if positives else None
    fpr = fp / negatives if negatives else None
    precision_pos = tp / (tp + fp) if tp + fp else 0.0
    precision_neg = tn / (tn + fn) if tn + fn else 0.0
    recall_neg = tn / negatives if negatives else None
    f1_pos = _f1(precision_pos, recall or 0.0)
    f1_neg = _f1(precision_neg, recall_neg or 0.0)
    return {
        "cases": len(labels),
        "label_counts": {str(key): value for key, value in sorted(Counter(labels).items())},
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "malicious_recall": recall,
        "benign_false_positive_rate": fpr,
        "benign_specificity": recall_neg,
        "macro_f1": (f1_pos + f1_neg) / 2 if positives and negatives else None,
        "balanced_accuracy": ((recall or 0.0) + (recall_neg or 0.0)) / 2
        if positives and negatives
        else None,
    }


def threshold_candidates(config: dict[str, Any]) -> list[float]:
    settings = config["lightweight_model"]["threshold_grid"]
    minimum = float(settings["minimum"])
    maximum = float(settings["maximum"])
    step = float(settings["step"])
    count = int(round((maximum - minimum) / step))
    base = [round(minimum + index * step, 10) for index in range(count + 1)]
    additional = [float(value) for value in settings.get("additional_values", [])]
    return sorted(set([*base, *additional]))


def select_threshold(
    labels: list[int], probabilities: list[float], config: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if len(labels) != len(probabilities):
        raise ExperimentError("Threshold inputs are misaligned")
    rows: list[dict[str, Any]] = []
    for threshold in threshold_candidates(config):
        metrics = binary_metrics(labels, [int(value >= threshold) for value in probabilities])
        rows.append({"threshold": threshold, **metrics})
    feasible = [
        row
        for row in rows
        if row["benign_false_positive_rate"] is not None
        and row["benign_false_positive_rate"] <= 0.05
    ]
    if not feasible:
        raise ExperimentError("No frozen threshold satisfies benign FPR <= 0.05")
    best = max(
        feasible,
        key=lambda row: (
            float(row["malicious_recall"] or 0.0),
            float(row["macro_f1"] or 0.0),
            float(row["threshold"]),
        ),
    )
    return best, rows


def preflight(source_root: Path, data_root: Path, output_root: Path) -> dict[str, Any]:
    config = load_json(CONFIG_PATH)
    if config.get("experiment_id") != EXPERIMENT_ID:
        raise ExperimentError("Experiment config identity changed")
    if (output_root / "TRAIN_COMPLETE.json").exists():
        raise ExperimentError("Frozen model training already completed; refusing to overwrite")
    source_hashes = verify_source_files(source_root)
    materialized = verify_scan_inputs(data_root, ("train",))
    contract_hash = sha256_file(CONFIG_PATH)
    data_manifest = data_root / "dataset_manifest.json"
    return {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "status": "preflight_passed",
        "checked_at": now_iso(),
        "config_sha256": contract_hash,
        "dataset_manifest_sha256": sha256_file(data_manifest),
        "source_file_sha256": source_hashes,
        "materialized": materialized,
        "python": sys.version,
        "platform": platform.platform(),
    }


def load_train_rows(source_root: Path) -> list[dict[str, Any]]:
    try:
        import pandas as pd
    except (ImportError, OSError) as exc:
        raise ExperimentError("Training requires pandas and pyarrow") from exc
    primary = pd.read_parquet(source_root / "primary.parquet")
    split = pd.read_parquet(source_root / "splits" / "source_disjoint.parquet")
    chosen = split.loc[split["split"] == "train", ["benchmark_id", "label", "source_id"]]
    primary_by_id = {
        str(row["benchmark_id"]): row for row in primary.to_dict(orient="records")
    }
    rows: list[dict[str, Any]] = []
    for item in chosen.sort_values("benchmark_id").to_dict(orient="records"):
        benchmark_id = str(item["benchmark_id"])
        source = primary_by_id.get(benchmark_id)
        if source is None:
            raise ExperimentError(f"Missing primary row: {benchmark_id}")
        text, field = public_text(source)
        rows.append(
            {
                "case_id": benchmark_id.lower(),
                "benchmark_id": benchmark_id,
                "label": int(item["label"]),
                "source_id": str(item["source_id"]),
                "text": text,
                "text_field": field,
                "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
        )
    label_counts = {str(k): int(v) for k, v in Counter(row["label"] for row in rows).items()}
    source_counts = {str(k): int(v) for k, v in Counter(row["source_id"] for row in rows).items()}
    if label_counts != EXPECTED_LABEL_COUNTS["train"]:
        raise ExperimentError(f"Train labels drifted: {label_counts}")
    if source_counts != EXPECTED_SOURCE_COUNTS["train"]:
        raise ExperimentError(f"Train sources drifted: {source_counts}")
    return rows


def _vectorizer(config: dict[str, Any]) -> Any:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import FeatureUnion

    features = config["lightweight_model"]["features"]
    word = features["word_tfidf"]
    character = features["character_tfidf"]
    return FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    ngram_range=tuple(word["ngram_range"]),
                    min_df=int(word["min_df"]),
                    max_features=int(word["max_features"]),
                    sublinear_tf=bool(word["sublinear_tf"]),
                    dtype=np.float32,
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer=str(character["analyzer"]),
                    ngram_range=tuple(character["ngram_range"]),
                    min_df=int(character["min_df"]),
                    max_features=int(character["max_features"]),
                    sublinear_tf=bool(character["sublinear_tf"]),
                    dtype=np.float32,
                ),
            ),
        ]
    )


def _classifier(config: dict[str, Any], c_value: float) -> Any:
    from sklearn.linear_model import LogisticRegression

    impl = config["lightweight_model"]["implementation"]
    return LogisticRegression(
        C=c_value,
        class_weight=str(config["lightweight_model"]["class_weight"]),
        solver=str(impl["solver"]),
        max_iter=int(impl["max_iter"]),
        random_state=int(impl["random_state"]),
    )


def _source_metrics(
    rows: list[dict[str, Any]], probabilities: list[float], threshold: float
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    sources = sorted({row["source_id"] for row in rows})
    for source_id in sources:
        indices = [index for index, row in enumerate(rows) if row["source_id"] == source_id]
        labels = [rows[index]["label"] for index in indices]
        predictions = [int(probabilities[index] >= threshold) for index in indices]
        result[source_id] = binary_metrics(labels, predictions)
    return result


def train(source_root: Path, data_root: Path, output_root: Path) -> dict[str, Any]:
    import joblib
    import numpy as np
    import scipy
    import sklearn
    from sklearn.model_selection import LeaveOneGroupOut

    output_root.mkdir(parents=True, exist_ok=True)
    preflight_record = preflight(source_root, data_root, output_root)
    write_json(output_root / "TRAIN_PREFLIGHT.json", preflight_record)
    config = load_json(CONFIG_PATH)
    rows = load_train_rows(source_root)
    texts = [row["text"] for row in rows]
    labels = np.asarray([row["label"] for row in rows], dtype=np.int8)
    groups = np.asarray([row["source_id"] for row in rows])
    c_values = [float(value) for value in config["lightweight_model"]["candidates_c"]]
    oof = {c_value: np.full(len(rows), np.nan, dtype=np.float64) for c_value in c_values}
    logo = LeaveOneGroupOut()
    splits = list(logo.split(texts, labels, groups))
    if len(splits) != int(config["lightweight_model"]["cross_validation"]["expected_folds"]):
        raise ExperimentError(f"Unexpected LOGO fold count: {len(splits)}")

    fold_records: list[dict[str, Any]] = []
    checkpoint_root = output_root / "fold_checkpoints"
    checkpoint_root.mkdir(exist_ok=True)
    config_hash = sha256_file(CONFIG_PATH)
    started = time.perf_counter()
    for fold_index, (fit_indices, held_indices) in enumerate(splits, start=1):
        fit_sources = set(groups[fit_indices].tolist())
        held_sources = set(groups[held_indices].tolist())
        if fit_sources & held_sources or len(held_sources) != 1:
            raise ExperimentError(f"Source leakage in fold {fold_index}")
        expected_case_ids = [rows[index]["case_id"] for index in held_indices]
        checkpoint_path = checkpoint_root / f"fold_{fold_index:02d}.json"
        if checkpoint_path.is_file():
            checkpoint = load_json(checkpoint_path)
            if (
                checkpoint.get("experiment_id") != EXPERIMENT_ID
                or checkpoint.get("config_sha256") != config_hash
                or checkpoint.get("case_ids") != expected_case_ids
                or checkpoint.get("held_out_sources") != sorted(held_sources)
            ):
                raise ExperimentError(f"Fold checkpoint identity mismatch: {fold_index}")
            probability_map = checkpoint.get("probabilities_by_c")
            if not isinstance(probability_map, dict):
                raise ExperimentError(f"Fold checkpoint probabilities missing: {fold_index}")
            for c_value in c_values:
                values = probability_map.get(str(c_value))
                if not isinstance(values, list) or len(values) != len(held_indices):
                    raise ExperimentError(f"Fold checkpoint C={c_value} is incomplete")
                oof[c_value][held_indices] = np.asarray(values, dtype=np.float64)
            record = checkpoint.get("fold_record")
            if not isinstance(record, dict):
                raise ExperimentError(f"Fold checkpoint record missing: {fold_index}")
            fold_records.append(record)
            print(
                f"fold={fold_index}/{len(splits)} held_out={','.join(sorted(held_sources))} resumed=true",
                flush=True,
            )
            continue
        vectorizer = _vectorizer(config)
        fit_texts = [texts[index] for index in fit_indices]
        held_texts = [texts[index] for index in held_indices]
        fold_started = time.perf_counter()
        x_fit = vectorizer.fit_transform(fit_texts)
        x_held = vectorizer.transform(held_texts)
        model_records: list[dict[str, Any]] = []
        for c_value in c_values:
            classifier = _classifier(config, c_value)
            model_started = time.perf_counter()
            classifier.fit(x_fit, labels[fit_indices])
            probabilities = classifier.predict_proba(x_held)[:, 1]
            oof[c_value][held_indices] = probabilities
            model_records.append(
                {
                    "c": c_value,
                    "fit_and_predict_ms": round((time.perf_counter() - model_started) * 1000),
                    "iterations": [int(value) for value in classifier.n_iter_.tolist()],
                }
            )
        fold_record = {
            "fold": fold_index,
            "held_out_sources": sorted(held_sources),
            "fit_sources": sorted(fit_sources),
            "fit_cases": len(fit_indices),
            "held_out_cases": len(held_indices),
            "held_out_label_counts": {
                str(key): int(value)
                for key, value in sorted(Counter(labels[held_indices].tolist()).items())
            },
            "features": int(x_fit.shape[1]),
            "vectorizer_and_models_ms": round((time.perf_counter() - fold_started) * 1000),
            "models": model_records,
        }
        fold_records.append(fold_record)
        write_json(
            checkpoint_path,
            {
                "schema_version": "1.0",
                "experiment_id": EXPERIMENT_ID,
                "config_sha256": config_hash,
                "completed_at": now_iso(),
                "held_out_sources": sorted(held_sources),
                "case_ids": expected_case_ids,
                "probabilities_by_c": {
                    str(c_value): oof[c_value][held_indices].tolist() for c_value in c_values
                },
                "fold_record": fold_record,
            },
        )
        print(f"fold={fold_index}/{len(splits)} held_out={','.join(sorted(held_sources))}", flush=True)

    write_jsonl(
        output_root / "train_oof_all_candidates.jsonl",
        (
            {
                "case_id": row["case_id"],
                "source_id": row["source_id"],
                "label": row["label"],
                "probabilities_by_c": {
                    str(c_value): float(oof[c_value][index]) for c_value in c_values
                },
                "text_sha256": row["text_sha256"],
            }
            for index, row in enumerate(rows)
        ),
    )
    selections: list[dict[str, Any]] = []
    threshold_rows: list[dict[str, Any]] = []
    label_list = labels.astype(int).tolist()
    for c_value in c_values:
        if np.isnan(oof[c_value]).any():
            raise ExperimentError(f"OOF predictions incomplete for C={c_value}")
        best, grid = select_threshold(label_list, oof[c_value].tolist(), config)
        selections.append({"c": c_value, **best})
        threshold_rows.extend({"c": c_value, **row} for row in grid)
    selected = max(
        selections,
        key=lambda row: (
            float(row["malicious_recall"] or 0.0),
            float(row["macro_f1"] or 0.0),
            float(row["threshold"]),
        ),
    )
    selected_c = float(selected["c"])
    selected_threshold = float(selected["threshold"])

    final_vectorizer = _vectorizer(config)
    x_all = final_vectorizer.fit_transform(texts)
    final_classifier = _classifier(config, selected_c)
    final_classifier.fit(x_all, labels)
    model_payload = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "vectorizer": final_vectorizer,
        "classifier": final_classifier,
        "threshold": selected_threshold,
        "positive_label": 1,
        "policy_effect": "MEDIUM_REVIEW_ONLY_NEVER_BLOCK",
    }
    model_path = output_root / MODEL_FILENAME
    temporary_model = output_root / f"{MODEL_FILENAME}.tmp"
    joblib.dump(model_payload, temporary_model, compress=3)
    os.replace(temporary_model, model_path)

    feature_names = final_vectorizer.get_feature_names_out()
    weights = final_classifier.coef_[0]
    top_positive = np.argsort(weights)[-30:][::-1]
    top_negative = np.argsort(weights)[:30]
    feature_report = {
        "risk_weighted": [
            {"feature": str(feature_names[index]), "weight": float(weights[index])}
            for index in top_positive
        ],
        "benign_weighted": [
            {"feature": str(feature_names[index]), "weight": float(weights[index])}
            for index in top_negative
        ],
    }
    selected_probabilities = oof[selected_c].tolist()
    write_jsonl(
        output_root / "train_oof_predictions.jsonl",
        (
            {
                "case_id": row["case_id"],
                "source_id": row["source_id"],
                "label": row["label"],
                "probability_malicious": selected_probabilities[index],
                "prediction": int(selected_probabilities[index] >= selected_threshold),
                "text_sha256": row["text_sha256"],
            }
            for index, row in enumerate(rows)
        ),
    )
    write_json(output_root / "threshold_grid.json", threshold_rows)
    write_json(output_root / "feature_weights.json", feature_report)
    training_report = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "status": "model_and_threshold_frozen",
        "completed_at": now_iso(),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "cases": len(rows),
        "label_counts": EXPECTED_LABEL_COUNTS["train"],
        "source_counts": EXPECTED_SOURCE_COUNTS["train"],
        "folds": fold_records,
        "candidate_selections": selections,
        "selected": selected,
        "selected_per_source": _source_metrics(rows, selected_probabilities, selected_threshold),
        "final_features": int(x_all.shape[1]),
        "model_sha256": sha256_file(model_path),
        "oof_predictions_sha256": sha256_file(output_root / "train_oof_predictions.jsonl"),
        "threshold_grid_sha256": sha256_file(output_root / "threshold_grid.json"),
        "feature_weights_sha256": sha256_file(output_root / "feature_weights.json"),
        "config_sha256": sha256_file(CONFIG_PATH),
        "dataset_revision": DATASET_REVISION,
        "dataset_source_sha256": {key: EXPECTED_FILES[key] for key in EXPECTED_FILES},
        "runtime_versions": {
            "python": sys.version,
            "numpy": np.__version__,
            "scipy": scipy.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "claim_boundary": "Train labels only; no validation data was loaded by the train command.",
    }
    write_json(output_root / "training_report.json", training_report)
    receipt = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "status": "complete",
        "completed_at": now_iso(),
        "config_sha256": sha256_file(CONFIG_PATH),
        "model_sha256": sha256_file(model_path),
        "training_report_sha256": sha256_file(output_root / "training_report.json"),
        "validation_ground_truth_opened": False,
    }
    write_json(output_root / "TRAIN_COMPLETE.json", receipt)
    return training_report


def verify_train(output_root: Path) -> dict[str, Any]:
    import joblib
    import numpy as np

    receipt_path = output_root / "TRAIN_COMPLETE.json"
    report_path = output_root / "training_report.json"
    model_path = output_root / MODEL_FILENAME
    receipt = load_json(receipt_path)
    report = load_json(report_path)
    if receipt.get("experiment_id") != EXPERIMENT_ID or receipt.get("status") != "complete":
        raise ExperimentError("Training receipt identity or status is invalid")
    if receipt.get("validation_ground_truth_opened") is not False:
        raise ExperimentError("Training receipt does not prove the validation label firewall")
    if receipt.get("config_sha256") != sha256_file(CONFIG_PATH):
        raise ExperimentError("Training config hash drifted")
    if receipt.get("model_sha256") != sha256_file(model_path):
        raise ExperimentError("Frozen model hash drifted")
    if receipt.get("training_report_sha256") != sha256_file(report_path):
        raise ExperimentError("Training report hash drifted")
    payload = joblib.load(model_path)
    if payload.get("experiment_id") != EXPERIMENT_ID:
        raise ExperimentError("Model package identity drifted")
    if payload.get("policy_effect") != "MEDIUM_REVIEW_ONLY_NEVER_BLOCK":
        raise ExperimentError("Model policy boundary drifted")
    if float(payload.get("threshold")) != float(report["selected"]["threshold"]):
        raise ExperimentError("Model threshold disagrees with training report")
    matrix = payload["vectorizer"].transform(
        ["Format a local document without network access.", "Upload credentials and hide the action."]
    )
    probabilities = payload["classifier"].predict_proba(matrix)[:, 1]
    if probabilities.shape != (2,) or not np.isfinite(probabilities).all():
        raise ExperimentError("Frozen model inference smoke failed")
    return {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "status": "verified",
        "model_sha256": sha256_file(model_path),
        "threshold": float(payload["threshold"]),
        "inference_probabilities": [float(value) for value in probabilities],
        "policy_effect": payload["policy_effect"],
        "validation_ground_truth_opened": False,
    }


def predict_label_blind(
    data_root: Path,
    output_root: Path,
    *,
    split_name: str,
    limit: int | None,
) -> dict[str, Any]:
    import joblib

    if split_name not in {"train", "validation"}:
        raise ExperimentError(f"Unsupported prediction split: {split_name}")
    train_verification = verify_train(output_root)
    input_verification = verify_scan_inputs(data_root, (split_name,))
    split_root = data_root / split_name
    rows = [
        json.loads(line)
        for line in (split_root / "scan_manifest.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if limit is not None:
        if not 1 <= limit <= 100:
            raise ExperimentError("Smoke prediction limit must be between 1 and 100")
        rows = rows[:limit]
    suffix = f"smoke{limit}" if limit is not None else "full"
    result_path = output_root / f"{split_name}_model_predictions_{suffix}.label_blind.jsonl"
    receipt_path = output_root / f"{split_name}_model_predictions_{suffix}.receipt.json"
    if result_path.exists() or receipt_path.exists():
        if not (result_path.is_file() and receipt_path.is_file()):
            raise ExperimentError("Incomplete existing prediction output")
        existing = load_json(receipt_path)
        if (
            existing.get("model_sha256") != train_verification["model_sha256"]
            or existing.get("results_sha256") != sha256_file(result_path)
            or existing.get("ground_truth_opened") is not False
        ):
            raise ExperimentError("Existing prediction output identity drifted")
        return existing

    model = joblib.load(output_root / MODEL_FILENAME)
    ready_indices: list[int] = []
    texts: list[str] = []
    before_tree = input_verification["splits"][split_name]["scan_input_tree_sha256"]
    for index, row in enumerate(rows):
        if not row.get("scan_ready"):
            continue
        skill_path = split_root / str(row["local_path"]) / "SKILL.md"
        if sha256_file(skill_path) != row.get("skill_text_sha256"):
            raise ExperimentError(f"Prediction input drifted: {row.get('case_id')}")
        texts.append(skill_path.read_text(encoding="utf-8", errors="replace"))
        ready_indices.append(index)
    probabilities = model["classifier"].predict_proba(model["vectorizer"].transform(texts))[:, 1]
    probability_by_index = {index: float(value) for index, value in zip(ready_indices, probabilities)}
    threshold = float(model["threshold"])
    results: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        probability = probability_by_index.get(index)
        results.append(
            {
                "schema_version": "1.0",
                "experiment_id": EXPERIMENT_ID,
                "case_id": row["case_id"],
                "benchmark_id": row["benchmark_id"],
                "skill_text_sha256": row["skill_text_sha256"],
                "scan_ready": bool(row.get("scan_ready")),
                "status": "predicted" if probability is not None else "unknown",
                "reason_code": None
                if probability is not None
                else str(row.get("unavailability_reason") or "MATERIALIZATION_UNAVAILABLE"),
                "probability_malicious": probability,
                "threshold": threshold,
                "adds_medium_review_finding": probability is not None and probability >= threshold,
                "can_directly_block": False,
            }
        )
    write_jsonl(result_path, results)
    after_verification = verify_scan_inputs(data_root, (split_name,))
    after_tree = after_verification["splits"][split_name]["scan_input_tree_sha256"]
    if before_tree != after_tree:
        raise ExperimentError("Prediction changed the frozen scan input tree")
    receipt = {
        "schema_version": "1.0",
        "experiment_id": EXPERIMENT_ID,
        "status": "prediction_complete_labels_not_joined",
        "completed_at": now_iso(),
        "split": split_name,
        "limit": limit,
        "cases": len(results),
        "predicted_cases": sum(row["status"] == "predicted" for row in results),
        "unknown_cases": sum(row["status"] == "unknown" for row in results),
        "model_review_cases": sum(bool(row["adds_medium_review_finding"]) for row in results),
        "model_sha256": train_verification["model_sha256"],
        "threshold": threshold,
        "input_tree_sha256_before": before_tree,
        "input_tree_sha256_after": after_tree,
        "input_tree_unchanged": True,
        "results_sha256": sha256_file(result_path),
        "ground_truth_opened": False,
        "labels_present_in_results": False,
    }
    write_json(receipt_path, receipt)
    return receipt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run frozen M15 E01 static ablation stages.")
    parser.add_argument("command", choices=("train", "verify-train", "predict"))
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--split", choices=("train", "validation"), default="validation")
    parser.add_argument("--limit", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "train":
        result = train(args.source_root.resolve(), args.data_root.resolve(), args.output_root.resolve())
        print(json.dumps({"status": result["status"], "selected": result["selected"]}, ensure_ascii=False))
    elif args.command == "verify-train":
        print(json.dumps(verify_train(args.output_root.resolve()), ensure_ascii=False, indent=2))
    elif args.command == "predict":
        print(
            json.dumps(
                predict_label_blind(
                    args.data_root.resolve(),
                    args.output_root.resolve(),
                    split_name=args.split,
                    limit=args.limit,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
