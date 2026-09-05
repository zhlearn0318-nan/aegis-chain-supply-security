from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from tools.datasets.prepare_skilltrustbench import (  # noqa: E402
    CONTENT_REVISION,
    DATASET_ID,
    IntakeError,
    build_stats,
    sha256_file,
    tree_sha256,
    validate_archive,
    write_json,
)
from tools.datasets.prepare_skilltrustbench_official_subset import (  # noqa: E402
    archive_case_tree_sha256,
    load_jsonl,
    materialize_case,
)


EXPECTED_CASES = 5_520
EXPECTED_COUNTS = {"normal": 1_643, "suspicious": 1_014, "malicious": 2_863}
EXPECTED_IDS_SHA256 = "99ed464424ef589d76d28f5762fd88dc0b62bd96dc88dfcd9a5b867add9ab4a1"
EXPECTED_GROUND_TRUTH_SHA256 = "46009af2edd1119901d4e0a1e139f5bf555c769b28b1a2fe2235051f6a902660"
EXPECTED_ARCHIVE_SHA256 = "e1d8950ef01c3b24fa80e32101844abc8c5ab3a0a38525427e8b16f00a414ae4"


def case_ids_text(records: list[dict[str, Any]]) -> str:
    return "".join(f"{row['id']}\n" for row in records)


def validate_ground_truth(path: Path) -> list[dict[str, Any]]:
    if sha256_file(path) != EXPECTED_GROUND_TRUTH_SHA256:
        raise IntakeError("Full ground-truth SHA-256 differs from the frozen source identity")
    payload = json.loads(path.read_text(encoding="utf-8"))
    records = payload.get("test_cases")
    if not isinstance(records, list):
        raise IntakeError("ground_truth.json does not contain a test_cases list")
    ordered = sorted(records, key=lambda row: str(row.get("id")))
    ids = [str(row.get("id")) for row in ordered]
    if len(ids) != EXPECTED_CASES or len(set(ids)) != EXPECTED_CASES:
        raise IntakeError(f"Full dataset size/uniqueness changed: rows={len(ids)}, unique={len(set(ids))}")
    counts = dict(sorted(Counter(str(row.get("judgment")) for row in ordered).items()))
    if counts != EXPECTED_COUNTS:
        raise IntakeError(f"Full dataset label counts changed: {counts}")
    digest = hashlib.sha256(case_ids_text(ordered).encode("utf-8")).hexdigest()
    if digest != EXPECTED_IDS_SHA256:
        raise IntakeError(f"Full dataset case-list hash changed: {digest}")
    return ordered


def write_record(output, record: dict[str, Any]) -> None:
    output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    output.flush()


def archive_only_record(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    source_record: dict[str, Any],
    cases_root: Path,
    *,
    status: str,
    reason: str,
) -> dict[str, Any]:
    case_id = str(source_record["id"])
    case_root = cases_root / case_id
    residual_files = [path for path in case_root.rglob("*") if path.is_file()] if case_root.exists() else []
    if os.name == "nt" and any(
        not (path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
        for path in residual_files
    ):
        raise IntakeError(f"Archive-only case contains a writable residual file: {case_id}")
    record = {
        key: source_record.get(key)
        for key in (
            "id", "judgment", "risk_labels", "source", "base_category",
            "primary_pattern", "attack_pattern", "skill_path",
        )
    }
    record.update({
        "local_path": f"full/cases/{case_id}",
        "case_tree_sha256": archive_case_tree_sha256(archive, members),
        "case_tree_sha256_method": "archive_bytes_only",
        "scanner_eligible": False,
        "local_read_status": status,
        "local_read_block_reason": reason,
    })
    return record


def verify_checkpoint_prefix(
    prior: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    cases_root: Path,
    archive: zipfile.ZipFile,
    case_members: dict[str, list[zipfile.ZipInfo]],
) -> None:
    expected_ids = [str(row["id"]) for row in selected[:len(prior)]]
    actual_ids = [str(row.get("id")) for row in prior]
    if actual_ids != expected_ids:
        raise IntakeError("Full import checkpoint is not an exact prefix of the frozen ID order")
    for record in prior:
        case_id = str(record["id"])
        if record.get("local_path") != f"full/cases/{case_id}":
            raise IntakeError(f"Full import checkpoint has an unexpected local path: {case_id}")
        if record.get("scanner_eligible") is False:
            archive_hash = archive_case_tree_sha256(archive, case_members[case_id])
            if archive_hash != record.get("case_tree_sha256"):
                raise IntakeError(f"Archive identity changed for blocked full case: {case_id}")
            continue
        case_root = cases_root / case_id
        if not (case_root / "SKILL.md").is_file():
            raise IntakeError(f"Checkpoint case is missing SKILL.md: {case_id}")
        files = [path for path in case_root.rglob("*") if path.is_file()]
        if not files:
            raise IntakeError(f"Checkpoint case contains no files: {case_id}")
        if os.name == "nt" and any(
            not (path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
            for path in files
        ):
            raise IntakeError(f"Checkpoint case contains a writable file: {case_id}")
        if tree_sha256(case_root) != record.get("case_tree_sha256"):
            raise IntakeError(f"Checkpoint case tree hash changed: {case_id}")


def prepare(root: Path) -> dict[str, Any]:
    raw_root = root / "raw"
    ground_truth_path = raw_root / "benchmark_full_v1.0" / "ground_truth.json"
    archive_path = raw_root / "benchmark_full_v1.0.zip"
    for required in (ground_truth_path, archive_path):
        if not required.is_file():
            raise IntakeError(f"Required full-dataset source is missing: {required}")
    if sha256_file(archive_path) != EXPECTED_ARCHIVE_SHA256:
        raise IntakeError("Full archive SHA-256 differs from the frozen source identity")
    selected = validate_ground_truth(ground_truth_path)

    full_root = root / "full"
    cases_root = full_root / "cases"
    full_root.mkdir(parents=True, exist_ok=True)
    cases_root.mkdir(parents=True, exist_ok=True)
    final_manifest_path = full_root / "full_manifest.jsonl"
    checkpoint_path = full_root / "full_manifest.partial.jsonl"

    if final_manifest_path.is_file():
        prior = load_jsonl(final_manifest_path)
        if checkpoint_path.exists():
            raise IntakeError("Both final and partial full manifests exist; refusing ambiguous resume")
        resume_source = "final_manifest"
    elif checkpoint_path.is_file():
        prior = load_jsonl(checkpoint_path)
        resume_source = "partial_checkpoint"
    else:
        prior = []
        resume_source = "new_import"

    with zipfile.ZipFile(archive_path) as archive:
        archive_audit = validate_archive(archive)
        if archive_audit["case_count"] != EXPECTED_CASES:
            raise IntakeError(f"Full archive case count changed: {archive_audit['case_count']}")
        case_members = archive_audit["case_members"]
        missing = [str(row["id"]) for row in selected if str(row["id"]) not in case_members]
        if missing:
            raise IntakeError(f"Full dataset cases are missing from the archive: {missing[:10]}")
        unexpected = sorted(
            path.name
            for path in cases_root.iterdir()
            if path.is_dir() and path.name not in {str(row["id"]) for row in selected}
        )
        if unexpected:
            raise IntakeError(f"Unexpected directories in full dataset root: {unexpected[:10]}")
        verify_checkpoint_prefix(prior, selected, cases_root, archive, case_members)

        if len(prior) < len(selected):
            mode = "a" if prior else "w"
            with checkpoint_path.open(mode, encoding="utf-8", newline="\n") as output:
                for index, row in enumerate(selected[len(prior):], start=len(prior) + 1):
                    case_id = str(row["id"])
                    try:
                        record = materialize_case(archive, case_members[case_id], row, cases_root)
                        record["local_path"] = f"full/cases/{case_id}"
                    except IntakeError as exc:
                        if not str(exc).startswith("Windows-unsafe archive member:"):
                            raise
                        record = archive_only_record(
                            archive,
                            case_members[case_id],
                            row,
                            cases_root,
                            status="blocked_by_platform_path_incompatibility",
                            reason="windows_path_incompatible",
                        )
                    write_record(output, record)
                    prior.append(record)
                    if index % 100 == 0 or index == len(selected):
                        print(f"prepared={index}/{len(selected)}", flush=True)
            os.replace(checkpoint_path, final_manifest_path)
        elif checkpoint_path.is_file():
            os.replace(checkpoint_path, final_manifest_path)

    if len(prior) != EXPECTED_CASES:
        raise IntakeError(f"Full import ended with an incomplete manifest: {len(prior)}")
    ids_text = case_ids_text(prior)
    ids_path = full_root / "full_case_ids.txt"
    ids_path.write_text(ids_text, encoding="utf-8", newline="\n")
    stats = build_stats(prior)
    write_json(full_root / "full_stats.json", stats)

    manifest = {
        "schema_version": "1.0",
        "prepared_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "dataset": DATASET_ID,
        "dataset_content_revision": CONTENT_REVISION,
        "license": "CC BY-NC-SA 4.0",
        "source_identity": {
            "ground_truth_path": "raw/benchmark_full_v1.0/ground_truth.json",
            "ground_truth_sha256": sha256_file(ground_truth_path),
            "archive_path": "raw/benchmark_full_v1.0.zip",
            "archive_sha256": sha256_file(archive_path),
        },
        "full_dataset": {
            "cases": len(prior),
            "label_counts": dict(sorted(Counter(str(row["judgment"]) for row in prior).items())),
            "case_ids_sha256": hashlib.sha256(ids_text.encode("utf-8")).hexdigest(),
            "manifest_path": "full/full_manifest.jsonl",
            "manifest_sha256": sha256_file(final_manifest_path),
            "stats_path": "full/full_stats.json",
            "scanner_eligible_cases": sum(row.get("scanner_eligible") is not False for row in prior),
            "scanner_ineligible_cases": sum(row.get("scanner_eligible") is False for row in prior),
            "scanner_ineligible_reasons": dict(sorted(Counter(
                str(row.get("local_read_status"))
                for row in prior if row.get("scanner_eligible") is False
            ).items())),
            "resume_source": resume_source,
        },
        "archive_audit": {
            key: value for key, value in archive_audit.items() if key != "case_members"
        },
        "stats": stats,
        "safety": {
            "samples_executed": False,
            "sample_modules_imported": False,
            "sample_dependencies_installed": False,
            "cloud_upload_enabled": False,
            "archive_paths_validated": True,
            "symlinks_allowed": False,
            "extracted_cases_only": len(prior),
            "extracted_files_read_only": True,
            "scanner_ineligible_cases_are_abstentions": True,
        },
    }
    write_json(full_root / "intake_manifest.json", manifest)
    return manifest


def default_root() -> Path:
    reproduction_root = Path(__file__).resolve().parents[3]
    return reproduction_root / "datasets" / "skilltrustbench_v1_0"


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely prepare the complete SkillTrustBench v1.0 dataset")
    parser.add_argument("--root", type=Path, default=default_root())
    args = parser.parse_args()
    manifest = prepare(args.root.resolve())
    print(json.dumps({
        "status": "prepared",
        "root": str(args.root.resolve()),
        "full_dataset": manifest["full_dataset"],
        "stats": manifest["stats"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
