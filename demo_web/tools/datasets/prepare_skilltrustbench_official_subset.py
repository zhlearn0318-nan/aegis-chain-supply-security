from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from tools.datasets.prepare_skilltrustbench import (
    CONTENT_REVISION,
    DATASET_ID,
    IntakeError,
    build_stats,
    download_file,
    normalized_member_path,
    sha256_file,
    tree_sha256,
    validate_archive,
    validate_windows_parts,
    write_json,
)


RESULTS_DATASET_ID = "cuhk-zhuque/SkillTrustBench-results"
RESULTS_REVISION = "326ec286d082199cb270b25b8b4fc93c8762281e"
SUBSET_FILE_SHA256 = "dff7621ffcc7a42f1a8ff64c8e47d2fafc1cd332431fd533be88bb684aaa6843"
COMPUTED_CASE_IDS_SHA256 = "903a036e4b7b16ee28e22d5d9db57a00b3764cfe41e43144acad67921e5196c2"
PUBLISHED_CASE_IDS_SHA256 = "903a036e4b7b16ee28e22d5d9db57a00b3764cfe41e43144acad67921e5196c2"
EXPECTED_COUNTS = {"normal": 166, "suspicious": 105, "malicious": 285}
EXPECTED_CASES = 556
RESULTS_BASE_URL = f"https://huggingface.co/datasets/{RESULTS_DATASET_ID}/resolve/{RESULTS_REVISION}"
OFFICIAL_DOWNLOADS = {
    "evaluation_subset_10pct.jsonl": {
        "url": f"{RESULTS_BASE_URL}/data/evaluation_subset_10pct.jsonl?download=true",
        "bytes": 91_015,
        "sha256": SUBSET_FILE_SHA256,
    },
    "leaderboard_results.jsonl": {
        "url": f"{RESULTS_BASE_URL}/data/leaderboard_results.jsonl?download=true",
        "bytes": 11_048,
        "sha256": "41dabfe75cc2e24e8a59b4c2501afb92e3ebc7dfa0b733bbb2c5e888cee6ef92",
    },
    "evaluation_protocol.md": {
        "url": f"{RESULTS_BASE_URL}/evaluation_protocol.md?download=true",
        "bytes": 5_113,
        "sha256": "d24dadead928d691aa1a084f429e47ab169282b00849ac8dff24616f5d6eaa73",
    },
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise IntakeError(f"Expected JSON object at {path}:{line_number}")
        records.append(payload)
    return records


def case_ids_sha256(records: list[dict[str, Any]]) -> str:
    text = "".join(f"{case_id}\n" for case_id in sorted(str(row["id"]) for row in records))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_official_subset(
    subset_path: Path,
    ground_truth_records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    actual_file_hash = sha256_file(subset_path)
    if actual_file_hash != SUBSET_FILE_SHA256:
        raise IntakeError(
            f"Official subset file hash changed: expected {SUBSET_FILE_SHA256}, got {actual_file_hash}"
        )

    subset = load_jsonl(subset_path)
    ids = [str(row.get("id")) for row in subset]
    if len(subset) != EXPECTED_CASES or len(set(ids)) != EXPECTED_CASES:
        raise IntakeError(
            f"Official subset size/uniqueness changed: rows={len(subset)}, unique={len(set(ids))}"
        )
    counts = dict(sorted(Counter(str(row.get("judgment")) for row in subset).items()))
    if counts != EXPECTED_COUNTS:
        raise IntakeError(f"Official subset label counts changed: {counts}")

    computed_hash = case_ids_sha256(subset)
    if computed_hash != COMPUTED_CASE_IDS_SHA256:
        raise IntakeError(
            f"Official subset case-list hash changed: expected {COMPUTED_CASE_IDS_SHA256}, got {computed_hash}"
        )

    truth_by_id = {str(row.get("id")): row for row in ground_truth_records}
    if len(truth_by_id) != len(ground_truth_records):
        raise IntakeError("Ground truth contains duplicate case IDs")
    selected: list[dict[str, Any]] = []
    compared_fields = ("judgment", "risk_labels", "source", "base_category", "skill_path")
    mismatches: list[str] = []
    for subset_row in subset:
        case_id = str(subset_row["id"])
        truth_row = truth_by_id.get(case_id)
        if truth_row is None:
            mismatches.append(f"{case_id}:missing_ground_truth")
            continue
        for field in compared_fields:
            if field in subset_row and subset_row.get(field) != truth_row.get(field):
                mismatches.append(f"{case_id}:{field}")
        selected.append(truth_row)
    if mismatches:
        raise IntakeError(f"Official subset/ground-truth mismatch: {mismatches[:10]}")

    return selected, {
        "cases": len(subset),
        "label_counts": counts,
        "subset_file_sha256": actual_file_hash,
        "computed_sorted_newline_case_ids_sha256": computed_hash,
        "published_subset_case_ids_sha256": PUBLISHED_CASE_IDS_SHA256,
        "published_hash_matches_current_file": computed_hash == PUBLISHED_CASE_IDS_SHA256,
        "ground_truth_mismatch_count": 0,
    }


def verify_published_hash(leaderboard_path: Path) -> dict[str, Any]:
    if not leaderboard_path.is_file():
        raise IntakeError(f"Official leaderboard file is missing: {leaderboard_path}")
    rows = load_jsonl(leaderboard_path)
    scoped = [
        row for row in rows
        if row.get("evaluation_scope") == "fixed_10pct_subset"
        and row.get("subset_path") == "data/evaluation_subset_10pct.jsonl"
    ]
    published = sorted({str(row.get("subset_case_ids_sha256")) for row in scoped})
    if published != [PUBLISHED_CASE_IDS_SHA256]:
        raise IntakeError(f"Published leaderboard subset hash changed: {published}")
    return {
        "file_sha256": sha256_file(leaderboard_path),
        "fixed_subset_rows": len(scoped),
        "published_subset_case_ids_sha256": published[0],
    }


def archive_case_tree_sha256(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
) -> str:
    digest = hashlib.sha256()
    files: list[tuple[Path, zipfile.ZipInfo]] = []
    for info in members:
        path = normalized_member_path(info.filename)
        if info.is_dir() or len(path.parts) < 3:
            continue
        relative = Path(*path.parts[2:])
        files.append((relative, info))
    for relative, info in sorted(files, key=lambda item: item[0]):
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        with archive.open(info) as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def filesystem_tree_hash_with_block_reason(case_root: Path) -> tuple[str | None, str | None]:
    digest = hashlib.sha256()
    for item in sorted(path for path in case_root.rglob("*") if path.is_file()):
        relative = item.relative_to(case_root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        try:
            with item.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            winerror = getattr(exc, "winerror", None)
            return None, f"endpoint_protection_blocked_read:{relative}:winerror={winerror}"
    return digest.hexdigest(), None


def materialize_case(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    record: dict[str, Any],
    cases_root: Path,
) -> dict[str, Any]:
    case_id = str(record["id"])
    expected_skill = f"benchmark_full_v1.0/{case_id}/SKILL.md"
    if not any(info.filename.replace("\\", "/").rstrip("/") == expected_skill for info in members):
        raise IntakeError(f"Official subset case has no SKILL.md: {case_id}")

    case_root = cases_root / case_id
    case_root.mkdir(parents=True, exist_ok=True)
    expected_files: dict[str, int] = {}
    for info in members:
        path = normalized_member_path(info.filename)
        relative_parts = path.parts[2:]
        if not relative_parts:
            continue
        validate_windows_parts(relative_parts, info.filename)
        destination = case_root.joinpath(*relative_parts)
        resolved = destination.resolve()
        if case_root.resolve() not in resolved.parents and resolved != case_root.resolve():
            raise IntakeError(f"Extraction escaped official case root: {info.filename}")
        if info.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        relative = "/".join(relative_parts)
        expected_files[relative] = info.file_size
        if destination.exists():
            if not destination.is_file() or destination.stat().st_size != info.file_size:
                raise IntakeError(f"Existing official case file differs in size/type: {case_id}/{relative}")
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as source, destination.open("wb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        os.chmod(destination, stat.S_IREAD)

    actual_files = {
        path.relative_to(case_root).as_posix(): path.stat().st_size
        for path in case_root.rglob("*")
        if path.is_file()
    }
    if actual_files != expected_files:
        raise IntakeError(f"Official case file inventory differs from archive: {case_id}")
    if any(not (path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY) for path in case_root.rglob("*") if path.is_file()):
        raise IntakeError(f"Official case contains a writable file: {case_id}")

    archive_hash = archive_case_tree_sha256(archive, members)
    filesystem_hash, block_reason = filesystem_tree_hash_with_block_reason(case_root)
    if filesystem_hash is not None and filesystem_hash != archive_hash:
        raise IntakeError(f"Extracted official case tree differs from archive: {case_id}")

    manifest_record = {
        key: record.get(key)
        for key in (
            "id", "judgment", "risk_labels", "source", "base_category",
            "primary_pattern", "attack_pattern", "skill_path",
        )
    }
    manifest_record.update({
        "local_path": f"official_10pct/cases/{case_id}",
        "case_tree_sha256": archive_hash,
        "case_tree_sha256_method": "filesystem_and_archive" if filesystem_hash else "archive_bytes_only",
        "scanner_eligible": filesystem_hash is not None,
        "local_read_status": "verified" if filesystem_hash else "blocked_by_endpoint_protection",
        "local_read_block_reason": block_reason,
    })
    return manifest_record


def prepare_cases(
    archive: zipfile.ZipFile,
    case_members: dict[str, list[zipfile.ZipInfo]],
    selected: list[dict[str, Any]],
    cases_root: Path,
    prior_records: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    cases_root.mkdir(parents=True, exist_ok=True)
    expected_ids = {str(row["id"]) for row in selected}
    unexpected = sorted(path.name for path in cases_root.iterdir() if path.is_dir() and path.name not in expected_ids)
    if unexpected:
        raise IntakeError(f"Unexpected directories in official subset root: {unexpected[:10]}")
    prior_by_id = {str(row.get("id")): row for row in (prior_records or [])}
    if len(prior_by_id) != len(prior_records or []):
        raise IntakeError("Prior official manifest contains duplicate case IDs")
    prepared: list[dict[str, Any]] = []
    for row in selected:
        case_id = str(row["id"])
        prior = prior_by_id.get(case_id)
        if prior and prior.get("scanner_eligible") is False:
            archive_hash = archive_case_tree_sha256(archive, case_members[case_id])
            if archive_hash != prior.get("case_tree_sha256"):
                raise IntakeError(f"Archive identity changed for endpoint-blocked case: {case_id}")
            prepared.append(prior)
            continue
        prepared.append(materialize_case(archive, case_members[case_id], row, cases_root))
    return prepared


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        for record in records:
            output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(temporary, path)


def prepare(root: Path) -> dict[str, Any]:
    official_root = root / "official_10pct"
    downloads: dict[str, Any] = {}
    for filename, source in OFFICIAL_DOWNLOADS.items():
        downloads[filename] = download_file(source["url"], official_root / filename, source)
        downloads[filename]["path"] = f"official_10pct/{filename}"
    subset_path = official_root / "evaluation_subset_10pct.jsonl"
    leaderboard_path = official_root / "leaderboard_results.jsonl"
    protocol_path = official_root / "evaluation_protocol.md"
    ground_truth_path = root / "raw" / "benchmark_full_v1.0" / "ground_truth.json"
    archive_path = root / "raw" / "benchmark_full_v1.0.zip"
    for required in (subset_path, leaderboard_path, protocol_path, ground_truth_path, archive_path):
        if not required.is_file():
            raise IntakeError(f"Required input is missing: {required}")

    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    ground_truth_records = ground_truth.get("test_cases")
    if not isinstance(ground_truth_records, list):
        raise IntakeError("ground_truth.json does not contain a test_cases list")
    selected, subset_audit = validate_official_subset(subset_path, ground_truth_records)
    leaderboard_audit = verify_published_hash(leaderboard_path)

    with zipfile.ZipFile(archive_path) as archive:
        archive_audit = validate_archive(archive)
        missing = [str(row["id"]) for row in selected if str(row["id"]) not in archive_audit["case_members"]]
        if missing:
            raise IntakeError(f"Official subset cases missing from archive: {missing[:10]}")
        cases_root = official_root / "cases"
        existing_count = sum(1 for path in cases_root.iterdir() if path.is_dir()) if cases_root.exists() else 0
        prior_manifest_path = official_root / "official_subset_manifest.jsonl"
        prior_records = load_jsonl(prior_manifest_path) if prior_manifest_path.is_file() else None
        if prior_records and [str(row.get("id")) for row in prior_records] != [str(row["id"]) for row in selected]:
            raise IntakeError("Prior official manifest IDs/order differ from the fixed source file")
        manifest_records = prepare_cases(
            archive, archive_audit["case_members"], selected, cases_root, prior_records
        )
        reused = existing_count == len(selected)

    ids_text = "".join(f"{row['id']}\n" for row in manifest_records)
    ordered_ids_hash = hashlib.sha256(ids_text.encode("utf-8")).hexdigest()
    (official_root / "official_case_ids.txt").write_text(ids_text, encoding="utf-8", newline="\n")
    write_jsonl(official_root / "official_subset_manifest.jsonl", manifest_records)
    stats = build_stats(manifest_records)
    write_json(official_root / "official_subset_stats.json", stats)

    manifest = {
        "schema_version": "1.0",
        "prepared_at": "2026-08-14",
        "dataset": DATASET_ID,
        "dataset_content_revision": CONTENT_REVISION,
        "results_dataset": RESULTS_DATASET_ID,
        "results_revision": RESULTS_REVISION,
        "license": "CC BY-NC-SA 4.0",
        "source_identity": {
            "downloads": downloads,
            "subset_path": "official_10pct/evaluation_subset_10pct.jsonl",
            "subset_file_bytes": subset_path.stat().st_size,
            "subset_file_sha256": sha256_file(subset_path),
            "leaderboard": leaderboard_audit,
            "evaluation_protocol_sha256": sha256_file(protocol_path),
        },
        "official_subset": {
            **subset_audit,
            "ordered_case_ids_sha256": ordered_ids_hash,
            "manifest_path": "official_10pct/official_subset_manifest.jsonl",
            "manifest_sha256": sha256_file(official_root / "official_subset_manifest.jsonl"),
            "stats_path": "official_10pct/official_subset_stats.json",
            "cases_reused": reused,
            "scanner_eligible_cases": sum(bool(row["scanner_eligible"]) for row in manifest_records),
            "endpoint_protection_blocked_cases": sum(not bool(row["scanner_eligible"]) for row in manifest_records),
        },
        "provenance_anomaly": {
            "present": subset_audit["published_hash_matches_current_file"] is False,
            "description": (
                "The leaderboard-published subset_case_ids_sha256 matches the sorted, "
                "newline-delimited IDs in the subset file from the same fixed repository revision."
            ),
        },
        "archive_audit": {
            key: value for key, value in archive_audit.items() if key != "case_members"
        },
        "ground_truth": {
            "cases": len(ground_truth_records),
            "sha256": sha256_file(ground_truth_path),
            "subset_mismatch_count": 0,
        },
        "stats": stats,
        "safety": {
            "samples_executed": False,
            "sample_modules_imported": False,
            "sample_dependencies_installed": False,
            "cloud_upload_enabled": False,
            "archive_paths_validated": True,
            "symlinks_allowed": False,
            "extracted_cases_only": len(manifest_records),
            "extracted_files_read_only": True,
            "endpoint_protection_blocks_are_abstentions": True,
        },
    }
    write_json(official_root / "intake_manifest.json", manifest)
    for path in (subset_path, leaderboard_path, protocol_path):
        os.chmod(path, stat.S_IREAD)
    return manifest


def default_root() -> Path:
    reproduction_root = Path(__file__).resolve().parents[3]
    return reproduction_root / "datasets" / "skilltrustbench_v1_0"


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely prepare the official SkillTrustBench fixed 10% subset")
    parser.add_argument("--root", type=Path, default=default_root())
    args = parser.parse_args()
    manifest = prepare(args.root.resolve())
    print(json.dumps({
        "status": "prepared",
        "root": str(args.root.resolve()),
        "results_revision": manifest["results_revision"],
        "official_subset": manifest["official_subset"],
        "stats": manifest["stats"],
        "provenance_anomaly": manifest["provenance_anomaly"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
