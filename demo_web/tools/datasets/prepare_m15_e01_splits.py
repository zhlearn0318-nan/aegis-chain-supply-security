from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from tools.datasets.prepare_maliciousskillbench_source_disjoint import (
    DATASET_ID,
    DATASET_REVISION,
    EXPECTED_FILES,
    EXPECTED_SPLIT_COUNTS,
    IntakeError,
    now_iso,
    public_text,
    safe_case_id,
    sha256_bytes,
    sha256_file,
    verify_source_files,
    write_json,
    write_jsonl,
)


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
DEFAULT_INPUT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_v1"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "datasets" / "maliciousskillbench_m15_e01_v1"
TARGET_SPLITS = ("train", "validation")
EXPECTED_LABEL_COUNTS = {
    "train": {"0": 1_521, "1": 5_992},
    "validation": {"0": 169, "1": 666},
}
EXPECTED_SOURCE_COUNTS = {
    "train": {
        "SRC001": 3_088,
        "SRC002": 134,
        "SRC004": 31,
        "SRC005": 27,
        "SRC006": 116,
        "SRC008": 3,
        "SRC010": 3_973,
        "SRC013": 141,
    },
    "validation": {
        "SRC001": 330,
        "SRC002": 19,
        "SRC004": 2,
        "SRC005": 3,
        "SRC006": 15,
        "SRC010": 453,
        "SRC013": 13,
    },
}


def _to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if hasattr(value, "tolist"):
        value = value.tolist()
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value]


def _records_by_id(frame: Any) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for raw in frame.to_dict(orient="records"):
        benchmark_id = str(raw.get("benchmark_id") or "")
        if not benchmark_id or benchmark_id in records:
            raise IntakeError(f"Missing or duplicate primary benchmark_id: {benchmark_id!r}")
        records[benchmark_id] = raw
    return records


def load_rows(input_root: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    try:
        import pandas as pd
    except (ImportError, OSError) as exc:
        raise IntakeError(
            "A working pandas+pyarrow environment is required only for benchmark preparation"
        ) from exc

    primary = pd.read_parquet(input_root / "primary.parquet")
    official = pd.read_parquet(input_root / "splits" / "source_disjoint.parquet")
    split_counts = {
        str(key): int(value) for key, value in official["split"].value_counts().items()
    }
    if split_counts != EXPECTED_SPLIT_COUNTS:
        raise IntakeError(f"Official split counts drifted: {split_counts}")

    primary_by_id = _records_by_id(primary)
    result: dict[str, list[dict[str, Any]]] = {}
    seen: set[str] = set()
    for split_name in TARGET_SPLITS:
        selected = official.loc[
            official["split"] == split_name, ["benchmark_id", "label", "source_id"]
        ].copy()
        if selected["benchmark_id"].duplicated().any():
            raise IntakeError(f"Official {split_name} split contains duplicate benchmark IDs")
        label_counts = {
            str(key): int(value) for key, value in selected["label"].value_counts().items()
        }
        source_counts = {
            str(key): int(value) for key, value in selected["source_id"].value_counts().items()
        }
        if label_counts != EXPECTED_LABEL_COUNTS[split_name]:
            raise IntakeError(f"Official {split_name} labels drifted: {label_counts}")
        if source_counts != EXPECTED_SOURCE_COUNTS[split_name]:
            raise IntakeError(f"Official {split_name} sources drifted: {source_counts}")

        rows: list[dict[str, Any]] = []
        for split_row in selected.sort_values("benchmark_id").to_dict(orient="records"):
            benchmark_id = str(split_row["benchmark_id"])
            if benchmark_id in seen:
                raise IntakeError(f"Benchmark ID crosses target splits: {benchmark_id}")
            seen.add(benchmark_id)
            row = primary_by_id.get(benchmark_id)
            if row is None:
                raise IntakeError(f"Split ID is absent from primary.parquet: {benchmark_id}")
            if str(row.get("label")) != str(split_row.get("label")):
                raise IntakeError(f"Label disagreement between official files: {benchmark_id}")
            if str(row.get("source_id")) != str(split_row.get("source_id")):
                raise IntakeError(f"Source disagreement between official files: {benchmark_id}")
            rows.append(row)
        result[split_name] = rows
    return result, split_counts


def tree_sha256(
    root: Path,
    *,
    exclude_prefixes: tuple[str, ...] = ("ground_truth/",),
    exclude_names: tuple[str, ...] = ("intake_manifest.json",),
) -> str:
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda p: p.as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in exclude_names or any(relative.startswith(prefix) for prefix in exclude_prefixes):
            continue
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _materialize_split(split_root: Path, split_name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    cases_root = split_root / "cases"
    labels_root = split_root / "ground_truth"
    cases_root.mkdir(parents=True)
    labels_root.mkdir()
    scan_manifest: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    text_origins: Counter[str] = Counter()
    unavailable_reasons: Counter[str] = Counter()
    total_bytes = 0

    for row in rows:
        benchmark_id = str(row["benchmark_id"])
        case_id = safe_case_id(benchmark_id)
        text, text_field = public_text(row)
        data = text.encode("utf-8")
        text_hash = sha256_bytes(data)
        case_root = cases_root / case_id
        case_root.mkdir()
        skill_path = case_root / "SKILL.md"
        scan_ready = True
        unavailability_reason = None
        try:
            skill_path.write_bytes(data)
            if sha256_file(skill_path) != text_hash:
                raise IntakeError(f"Materialized text verification failed: {benchmark_id}")
        except OSError:
            try:
                skill_path.unlink(missing_ok=True)
            except OSError as exc:
                raise IntakeError(
                    f"Host content filter blocked and retained a sample: {benchmark_id}"
                ) from exc
            scan_ready = False
            unavailability_reason = "HOST_CONTENT_FILTER_BLOCKED"
            unavailable_reasons[unavailability_reason] += 1
            (case_root / "MATERIALIZATION_BLOCKED.txt").write_text(
                "The host content filter prevented exact static-text materialization.\n",
                encoding="utf-8",
                newline="\n",
            )

        total_bytes += len(data)
        text_origins[text_field] += 1
        scan_manifest.append(
            {
                "case_id": case_id,
                "benchmark_id": benchmark_id,
                "local_path": f"cases/{case_id}",
                "skill_text_sha256": text_hash,
                "skill_text_bytes": len(data),
                "text_field": text_field,
                "scan_ready": scan_ready,
                "unavailability_reason": unavailability_reason,
            }
        )
        labels.append(
            {
                "case_id": case_id,
                "benchmark_id": benchmark_id,
                "label": str(row["label"]),
                "source_id": str(row["source_id"]),
                "source_name": str(row.get("source_name") or ""),
                "source_ids": _to_list(row.get("source_ids")),
                "provenance": str(row.get("provenance") or ""),
                "evidence_type": None
                if row.get("evidence_type") is None
                else str(row.get("evidence_type")),
                "structural_family_id": None
                if row.get("structural_family_id") is None
                else str(row.get("structural_family_id")),
                "attack_category_codes": _to_list(row.get("attack_category_codes")),
                "impact_category_codes": _to_list(row.get("impact_category_codes")),
                "release_status": str(row.get("release_status") or ""),
                "text_redacted": bool(row.get("text_redacted")),
                "original_text_withheld": bool(row.get("original_text_withheld")),
                "materialized_skill_text_sha256": text_hash,
            }
        )

    if any("label" in record or "source_id" in record for record in scan_manifest):
        raise IntakeError("Label firewall violation in scan manifest")
    write_jsonl(split_root / "scan_manifest.jsonl", scan_manifest)
    write_jsonl(labels_root / "labels.jsonl", labels)
    (split_root / "case_ids.txt").write_text(
        "".join(f"{row['case_id']}\n" for row in scan_manifest),
        encoding="utf-8",
        newline="\n",
    )

    for record in scan_manifest:
        path = split_root / record["local_path"] / "SKILL.md"
        if record["scan_ready"]:
            if sha256_file(path) != record["skill_text_sha256"]:
                raise IntakeError(f"Final tree verification failed: {record['case_id']}")
        elif path.exists():
            raise IntakeError(f"Blocked text unexpectedly remained: {record['case_id']}")

    intake = {
        "schema_version": "1.0",
        "status": "verified_before_first_scan",
        "prepared_at": now_iso(),
        "dataset_id": DATASET_ID,
        "dataset_revision": DATASET_REVISION,
        "protocol": f"official_source_disjoint_{split_name}_full",
        "cases": len(scan_manifest),
        "label_counts": dict(sorted(Counter(item["label"] for item in labels).items())),
        "source_counts": dict(sorted(Counter(item["source_id"] for item in labels).items())),
        "text_origins": dict(sorted(text_origins.items())),
        "materialized_total_bytes": total_bytes,
        "scan_ready_cases": sum(bool(item["scan_ready"]) for item in scan_manifest),
        "unavailable_cases": sum(not bool(item["scan_ready"]) for item in scan_manifest),
        "unavailability_reasons": dict(sorted(unavailable_reasons.items())),
        "label_firewall": {
            "scan_manifest_contains_labels": False,
            "ground_truth_path": "ground_truth/labels.jsonl",
            "join_after_scan_only": True,
        },
        "safety_boundary": {
            "artifact_kind": "released static Skill text snapshots",
            "executed_during_preparation": False,
            "full_package_code_execution_claimed": False,
        },
    }
    write_json(split_root / "intake_manifest.json", intake)
    intake["scan_input_tree_sha256"] = tree_sha256(split_root)
    write_json(split_root / "intake_manifest.json", intake)
    return intake


def materialize(input_root: Path, output_root: Path) -> dict[str, Any]:
    output_root.parent.mkdir(parents=True, exist_ok=True)
    if output_root.exists():
        raise IntakeError(f"Output already exists; refusing to replace frozen data: {output_root}")
    source_hashes = verify_source_files(input_root)
    rows_by_split, split_counts = load_rows(input_root)

    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        split_manifests = {
            split_name: _materialize_split(staging / split_name, split_name, rows_by_split[split_name])
            for split_name in TARGET_SPLITS
        }
        root_manifest = {
            "schema_version": "1.0",
            "experiment_id": "2026-09-05-m15-e01-static-ablation-v1",
            "status": "frozen",
            "prepared_at": now_iso(),
            "dataset_id": DATASET_ID,
            "dataset_revision": DATASET_REVISION,
            "source_file_sha256": source_hashes,
            "official_split_counts": split_counts,
            "target_splits": {
                name: {
                    "cases": split_manifests[name]["cases"],
                    "scan_ready_cases": split_manifests[name]["scan_ready_cases"],
                    "unavailable_cases": split_manifests[name]["unavailable_cases"],
                    "scan_input_tree_sha256": split_manifests[name]["scan_input_tree_sha256"],
                }
                for name in TARGET_SPLITS
            },
            "label_firewall": "labels are stored only below each split/ground_truth and joined after scan",
            "source_contract_sha256": sha256_file(
                DEMO_ROOT / "config" / "m15_e01_static_ablation_v1.json"
            ),
        }
        write_json(staging / "dataset_manifest.json", root_manifest)
        os.replace(staging, output_root)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return root_manifest


def verify_materialized(output_root: Path) -> dict[str, Any]:
    root_manifest = json.loads((output_root / "dataset_manifest.json").read_text(encoding="utf-8"))
    if root_manifest.get("dataset_revision") != DATASET_REVISION:
        raise IntakeError("Materialized dataset revision does not match the frozen contract")
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "status": "verified",
        "dataset_revision": DATASET_REVISION,
        "splits": {},
    }
    for split_name in TARGET_SPLITS:
        split_root = output_root / split_name
        intake = json.loads((split_root / "intake_manifest.json").read_text(encoding="utf-8"))
        scan_rows = [
            json.loads(line)
            for line in (split_root / "scan_manifest.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        label_rows = [
            json.loads(line)
            for line in (split_root / "ground_truth" / "labels.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        expected_cases = EXPECTED_SPLIT_COUNTS[split_name]
        if len(scan_rows) != expected_cases or len(label_rows) != expected_cases:
            raise IntakeError(f"Materialized {split_name} count mismatch")
        if any("label" in row or "source_id" in row for row in scan_rows):
            raise IntakeError(f"Label firewall violation in {split_name} scan manifest")
        if {row["case_id"] for row in scan_rows} != {row["case_id"] for row in label_rows}:
            raise IntakeError(f"Scan/label case IDs disagree for {split_name}")
        actual_tree_hash = tree_sha256(split_root)
        expected_tree_hash = str(intake.get("scan_input_tree_sha256") or "")
        if actual_tree_hash != expected_tree_hash:
            raise IntakeError(f"Materialized {split_name} tree hash mismatch")
        result["splits"][split_name] = {
            "cases": len(scan_rows),
            "scan_ready_cases": sum(bool(row["scan_ready"]) for row in scan_rows),
            "unavailable_cases": sum(not bool(row["scan_ready"]) for row in scan_rows),
            "scan_manifest_label_keys": 0,
            "case_id_join_exact": True,
            "scan_input_tree_sha256": actual_tree_hash,
        }
    return result


def verify_scan_inputs(
    output_root: Path, split_names: tuple[str, ...] = TARGET_SPLITS
) -> dict[str, Any]:
    """Verify only label-blind scan inputs; never open ground_truth files."""
    root_manifest = json.loads((output_root / "dataset_manifest.json").read_text(encoding="utf-8"))
    if root_manifest.get("dataset_revision") != DATASET_REVISION:
        raise IntakeError("Materialized dataset revision does not match the frozen contract")
    if any(name not in TARGET_SPLITS for name in split_names):
        raise IntakeError(f"Unsupported split requested: {split_names}")
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "status": "label_blind_inputs_verified",
        "dataset_revision": DATASET_REVISION,
        "ground_truth_opened": False,
        "splits": {},
    }
    for split_name in split_names:
        split_root = output_root / split_name
        intake = json.loads((split_root / "intake_manifest.json").read_text(encoding="utf-8"))
        scan_rows = [
            json.loads(line)
            for line in (split_root / "scan_manifest.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        expected_cases = EXPECTED_SPLIT_COUNTS[split_name]
        if len(scan_rows) != expected_cases or len({row.get("case_id") for row in scan_rows}) != expected_cases:
            raise IntakeError(f"Materialized {split_name} scan identity mismatch")
        forbidden = {"label", "ground_truth", "attack_category_codes", "source_id"}
        if any(forbidden & set(row) for row in scan_rows):
            raise IntakeError(f"Label firewall violation in {split_name} scan manifest")
        for row in scan_rows:
            case_root = (split_root / str(row["local_path"])).resolve()
            if split_root.resolve() not in case_root.parents:
                raise IntakeError(f"Case escaped split root: {row.get('case_id')}")
            skill_path = case_root / "SKILL.md"
            if row.get("scan_ready"):
                if (
                    not skill_path.is_file()
                    or skill_path.is_symlink()
                    or sha256_file(skill_path) != row.get("skill_text_sha256")
                ):
                    raise IntakeError(f"Materialized case drifted: {row.get('case_id')}")
            elif skill_path.exists():
                raise IntakeError(f"Unavailable case unexpectedly has scan content: {row.get('case_id')}")
        actual_tree_hash = tree_sha256(split_root)
        if actual_tree_hash != intake.get("scan_input_tree_sha256"):
            raise IntakeError(f"Materialized {split_name} tree hash mismatch")
        result["splits"][split_name] = {
            "cases": len(scan_rows),
            "scan_ready_cases": sum(bool(row["scan_ready"]) for row in scan_rows),
            "unavailable_cases": sum(not bool(row["scan_ready"]) for row in scan_rows),
            "scan_manifest_label_keys": 0,
            "scan_input_tree_sha256": actual_tree_hash,
        }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Materialize frozen train and validation inputs for M15 E01."
    )
    parser.add_argument("--input-root", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify an existing frozen output instead of materializing it.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.verify:
        result = verify_materialized(args.output_root.resolve())
    else:
        result = materialize(args.input_root.resolve(), args.output_root.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
