from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


DATASET_ID = "cuhk-zhuque/SkillTrustBench"
DATASET_VERSION = "v1.0-audited-refresh"
CONTENT_REVISION = "762d5388b3a047b26df9679582af868a0e5b2c8f"
PILOT_SEED = "aegis-chain-skilltrustbench-pilot-v1"
PILOT_PER_CLASS = 30
EXPECTED_LABEL_COUNTS = {"normal": 1643, "suspicious": 1014, "malicious": 2863}
EXPECTED_RISK_LABELS = {f"T{index:02d}" for index in range(1, 10)}
MAX_ARCHIVE_MEMBERS = 50_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1_000_000_000
MAX_MEMBER_BYTES = 150_000_000

BASE_URL = f"https://huggingface.co/datasets/{DATASET_ID}/resolve/{CONTENT_REVISION}"
DOWNLOADS = {
    "data/test_cases.jsonl": {
        "url": f"{BASE_URL}/data/test_cases.jsonl?download=true",
        "bytes": 1_304_853,
        "git_blob_sha1": "0e6436b80885d619f1c98b772165c4ac4ba4669b",
    },
    "metadata/case_metadata.jsonl": {
        "url": f"{BASE_URL}/metadata/case_metadata.jsonl?download=true",
        "bytes": 3_115_562,
        "git_blob_sha1": "d12dd4cda28971f49586bdcc754d3e3c89f98cf3",
    },
    "benchmark_full_v1.0/ground_truth.json": {
        "url": f"{BASE_URL}/benchmark_full_v1.0/ground_truth.json?download=true",
        "bytes": 4_439_440,
        "git_blob_sha1": "a50a71dc618e39f3dc08e249dc981c323adac9ed",
    },
    "benchmark_full_v1.0.zip": {
        "url": f"{BASE_URL}/benchmark_full_v1.0.zip?download=true",
        "bytes": 80_230_995,
        "lfs_sha256": "e1d8950ef01c3b24fa80e32101844abc8c5ab3a0a38525427e8b16f00a414ae4",
    },
}

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
WINDOWS_INVALID_CHARS = set('<>:"|?*')


class IntakeError(RuntimeError):
    """Raised when source identity or archive safety cannot be established."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha1_bytes(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def git_blob_sha1_file(path: Path) -> str:
    size = path.stat().st_size
    digest = hashlib.sha1()
    digest.update(f"blob {size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_rank(case_id: str, seed: str = PILOT_SEED) -> str:
    return hashlib.sha256(f"{seed}:{case_id}".encode("utf-8")).hexdigest()


def verify_source_object(target: Path, source: dict[str, Any]) -> dict[str, Any]:
    actual_size = target.stat().st_size
    if actual_size != source["bytes"]:
        raise IntakeError(
            f"Downloaded file size mismatch: {target.name}; expected {source['bytes']}, got {actual_size}"
        )
    actual_sha256 = sha256_file(target)
    if "sha256" in source and actual_sha256 != source["sha256"]:
        raise IntakeError(
            f"Downloaded SHA-256 mismatch: {target.name}; expected {source['sha256']}, got {actual_sha256}"
        )
    if "lfs_sha256" in source and actual_sha256 != source["lfs_sha256"]:
        raise IntakeError(
            f"Downloaded LFS hash mismatch: {target.name}; expected {source['lfs_sha256']}, got {actual_sha256}"
        )
    actual_git_blob = None
    if "git_blob_sha1" in source:
        actual_git_blob = git_blob_sha1_file(target)
        if actual_git_blob != source["git_blob_sha1"]:
            raise IntakeError(
                f"Downloaded Git blob mismatch: {target.name}; expected {source['git_blob_sha1']}, got {actual_git_blob}"
            )
    return {
        "path": str(target),
        "bytes": actual_size,
        "sha256": actual_sha256,
        "git_blob_sha1": actual_git_blob,
        "lfs_sha256": source.get("lfs_sha256"),
    }


def download_file(url: str, target: Path, source: dict[str, Any]) -> dict[str, Any]:
    if target.exists():
        result = verify_source_object(target, source)
        result["reused"] = True
        return result

    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "Aegis-Chain-Dataset-Intake/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=90) as response, partial.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
        result = verify_source_object(partial, source)
        os.replace(partial, target)
    finally:
        if partial.exists():
            partial.unlink()
    result["path"] = str(target)
    result["reused"] = False
    return result


def normalized_member_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise IntakeError(f"Unsafe archive member path: {name!r}")
    if any(not part or part == "." for part in path.parts):
        raise IntakeError(f"Ambiguous archive member path: {name!r}")
    return path


def is_symlink(info: zipfile.ZipInfo) -> bool:
    return (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK


def validate_windows_parts(parts: Iterable[str], original_name: str) -> None:
    for part in parts:
        stem = part.split(".", 1)[0].upper()
        if stem in WINDOWS_RESERVED_NAMES:
            raise IntakeError(f"Windows reserved name in archive member: {original_name!r}")
        if part.endswith((" ", ".")) or any(char in WINDOWS_INVALID_CHARS for char in part):
            raise IntakeError(f"Windows-unsafe archive member: {original_name!r}")


def validate_archive(archive: zipfile.ZipFile) -> dict[str, Any]:
    infos = archive.infolist()
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise IntakeError(f"Archive has too many members: {len(infos)}")
    total_uncompressed = 0
    seen: set[str] = set()
    case_members: dict[str, list[zipfile.ZipInfo]] = {}

    for info in infos:
        path = normalized_member_path(info.filename)
        canonical = path.as_posix().rstrip("/")
        if canonical in seen and not info.is_dir():
            raise IntakeError(f"Duplicate archive member: {canonical}")
        seen.add(canonical)
        if is_symlink(info):
            raise IntakeError(f"Symbolic link is not allowed: {info.filename}")
        if info.file_size > MAX_MEMBER_BYTES:
            raise IntakeError(f"Archive member is too large: {info.filename} ({info.file_size})")
        total_uncompressed += info.file_size
        if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise IntakeError(f"Archive uncompressed size exceeds limit: {total_uncompressed}")

        if len(path.parts) >= 2 and path.parts[0] == "benchmark_full_v1.0" and path.parts[1].startswith("case_"):
            case_members.setdefault(path.parts[1], []).append(info)

    return {
        "members": len(infos),
        "uncompressed_bytes": total_uncompressed,
        "case_count": len(case_members),
        "case_members": case_members,
    }


def select_pilot(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    valid_judgments = set(EXPECTED_LABEL_COUNTS)
    pools = {
        judgment: sorted(
            (record for record in records if record.get("judgment") == judgment),
            key=lambda record: stable_rank(str(record["id"])),
        )
        for judgment in valid_judgments
    }
    for judgment, pool in pools.items():
        if len(pool) < PILOT_PER_CLASS:
            raise IntakeError(f"Not enough {judgment} records for pilot: {len(pool)}")

    selected: dict[str, list[dict[str, Any]]] = {judgment: [] for judgment in valid_judgments}
    selected_ids: set[str] = set()
    uncovered = set(EXPECTED_RISK_LABELS)

    while uncovered:
        choices: list[tuple[int, str, str, dict[str, Any]]] = []
        for judgment in ("suspicious", "malicious"):
            if len(selected[judgment]) >= PILOT_PER_CLASS:
                continue
            for record in pools[judgment]:
                if record["id"] in selected_ids:
                    continue
                gain = len(set(record.get("risk_labels") or []) & uncovered)
                if gain:
                    choices.append((-gain, stable_rank(str(record["id"])), judgment, record))
        if not choices:
            break
        _, _, judgment, chosen = min(choices, key=lambda item: (item[0], item[1]))
        selected[judgment].append(chosen)
        selected_ids.add(str(chosen["id"]))
        uncovered -= set(chosen.get("risk_labels") or [])

    if uncovered:
        raise IntakeError(f"Pilot cannot cover risk labels: {sorted(uncovered)}")

    for judgment in ("normal", "suspicious", "malicious"):
        for record in pools[judgment]:
            if len(selected[judgment]) >= PILOT_PER_CLASS:
                break
            if record["id"] not in selected_ids:
                selected[judgment].append(record)
                selected_ids.add(str(record["id"]))

    return [
        record
        for judgment in ("normal", "suspicious", "malicious")
        for record in selected[judgment]
    ]


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path for path in root.rglob("*") if path.is_file()):
        digest.update(item.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        with item.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def extract_selected_cases(
    archive: zipfile.ZipFile,
    case_members: dict[str, list[zipfile.ZipInfo]],
    selected: list[dict[str, Any]],
    cases_root: Path,
    *,
    local_prefix: str = "pilot/cases",
) -> list[dict[str, Any]]:
    if cases_root.exists() and any(cases_root.iterdir()):
        raise IntakeError(f"Selected cases directory is not empty: {cases_root}")
    cases_root.mkdir(parents=True, exist_ok=True)

    manifest_records: list[dict[str, Any]] = []
    for record in selected:
        case_id = str(record["id"])
        members = case_members.get(case_id, [])
        expected_skill = f"benchmark_full_v1.0/{case_id}/SKILL.md"
        if not any(info.filename.replace("\\", "/").rstrip("/") == expected_skill for info in members):
            raise IntakeError(f"Selected case has no SKILL.md: {case_id}")

        case_root = cases_root / case_id
        case_root.mkdir(parents=True, exist_ok=False)
        for info in members:
            path = normalized_member_path(info.filename)
            relative_parts = path.parts[2:]
            if not relative_parts:
                continue
            validate_windows_parts(relative_parts, info.filename)
            destination = case_root.joinpath(*relative_parts)
            resolved = destination.resolve()
            if case_root.resolve() not in resolved.parents and resolved != case_root.resolve():
                raise IntakeError(f"Extraction escaped case root: {info.filename}")
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            os.chmod(destination, stat.S_IREAD)

        manifest_record = {
            key: record.get(key)
            for key in (
                "id", "judgment", "risk_labels", "source", "base_category",
                "primary_pattern", "attack_pattern", "skill_path",
            )
        }
        manifest_record["local_path"] = f"{local_prefix}/{case_id}"
        manifest_record["case_tree_sha256"] = tree_sha256(case_root)
        manifest_records.append(manifest_record)

    return manifest_records


def verify_existing_pilot(
    pilot_root: Path,
    selected: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    manifest_path = pilot_root / "pilot_manifest.jsonl"
    cases_root = pilot_root / "cases"
    if not manifest_path.is_file():
        raise IntakeError("Pilot cases exist but pilot_manifest.jsonl is missing")

    manifest_records = [
        json.loads(line)
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    expected_ids = [str(record["id"]) for record in selected]
    actual_ids = [str(record.get("id")) for record in manifest_records]
    if actual_ids != expected_ids:
        raise IntakeError("Existing pilot IDs do not match the frozen deterministic selection")

    actual_case_dirs = sorted(path.name for path in cases_root.iterdir() if path.is_dir())
    if actual_case_dirs != sorted(expected_ids):
        raise IntakeError("Existing pilot case directories do not match the manifest")

    for record in manifest_records:
        case_root = cases_root / str(record["id"])
        expected_tree_hash = record.get("case_tree_sha256")
        if not expected_tree_hash or tree_sha256(case_root) != expected_tree_hash:
            raise IntakeError(f"Existing pilot tree hash mismatch: {record['id']}")
    return manifest_records


def counter_dict(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def build_stats(records: list[dict[str, Any]]) -> dict[str, Any]:
    risk_values = [label for record in records for label in (record.get("risk_labels") or [])]
    return {
        "cases": len(records),
        "judgment": counter_dict(str(record["judgment"]) for record in records),
        "risk_labels": counter_dict(str(label) for label in risk_values),
        "sources": counter_dict(str(record.get("source")) for record in records),
        "base_categories": counter_dict(str(record.get("base_category")) for record in records),
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def prepare(root: Path) -> dict[str, Any]:
    raw_root = root / "raw"
    pilot_root = root / "pilot"
    downloads: dict[str, Any] = {}
    for relative_path, source in DOWNLOADS.items():
        downloads[relative_path] = download_file(
            source["url"], raw_root / relative_path, source
        )
        downloads[relative_path]["path"] = f"raw/{relative_path}"

    ground_truth_path = raw_root / "benchmark_full_v1.0" / "ground_truth.json"
    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    records = ground_truth.get("test_cases")
    if not isinstance(records, list):
        raise IntakeError("ground_truth.json does not contain a test_cases list")
    actual_counts = counter_dict(str(record.get("judgment")) for record in records)
    if actual_counts != EXPECTED_LABEL_COUNTS:
        raise IntakeError(f"Ground-truth label counts changed: {actual_counts}")
    ids = [str(record.get("id")) for record in records]
    if len(ids) != len(set(ids)):
        raise IntakeError("Duplicate case IDs in ground truth")

    zip_path = raw_root / "benchmark_full_v1.0.zip"
    with zipfile.ZipFile(zip_path) as archive:
        archive_audit = validate_archive(archive)
        if archive_audit["case_count"] != len(records):
            raise IntakeError(
                f"Archive/ground-truth case mismatch: {archive_audit['case_count']} vs {len(records)}"
            )
        selectable = [record for record in records if str(record["id"]) in archive_audit["case_members"]]
        selected = select_pilot(selectable)
        cases_root = pilot_root / "cases"
        if cases_root.exists() and any(cases_root.iterdir()):
            manifest_records = verify_existing_pilot(pilot_root, selected)
        else:
            manifest_records = extract_selected_cases(
                archive, archive_audit["case_members"], selected, cases_root
            )

    pilot_ids_text = "".join(f"{record['id']}\n" for record in manifest_records)
    pilot_ids_sha256 = hashlib.sha256(pilot_ids_text.encode("utf-8")).hexdigest()
    with (pilot_root / "pilot_case_ids.txt").open("w", encoding="utf-8", newline="\n") as output:
        output.write(pilot_ids_text)
    with (pilot_root / "pilot_manifest.jsonl").open("w", encoding="utf-8", newline="\n") as output:
        for record in manifest_records:
            output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    stats = build_stats(manifest_records)
    write_json(pilot_root / "pilot_stats.json", stats)
    manifest = {
        "schema_version": "1.0",
        "dataset": DATASET_ID,
        "dataset_version": DATASET_VERSION,
        "content_revision": CONTENT_REVISION,
        "download_date": "2026-08-10",
        "license": "CC BY-NC-SA 4.0",
        "official_sources": [
            "https://matrix.tencent.com/skilltrustbench/",
            f"https://huggingface.co/datasets/{DATASET_ID}",
        ],
        "pilot": {
            "size": len(manifest_records),
            "per_class": PILOT_PER_CLASS,
            "seed_text": PILOT_SEED,
            "case_ids_sha256": pilot_ids_sha256,
            "manifest_path": "pilot/pilot_manifest.jsonl",
            "stats_path": "pilot/pilot_stats.json",
        },
        "downloads": downloads,
        "archive_audit": {
            key: value for key, value in archive_audit.items() if key != "case_members"
        },
        "ground_truth": {
            "cases": len(records),
            "label_counts": actual_counts,
            "sha256": sha256_file(ground_truth_path),
        },
        "safety": {
            "samples_executed": False,
            "sample_modules_imported": False,
            "sample_dependencies_installed": False,
            "cloud_upload_enabled": False,
            "archive_paths_validated": True,
            "symlinks_allowed": False,
            "extracted_cases_only": len(manifest_records),
        },
        "stats": stats,
    }
    write_json(root / "intake_manifest.json", manifest)
    with (root / "ATTRIBUTION.md").open("w", encoding="utf-8", newline="\n") as output:
        output.write(
            "# SkillTrustBench attribution\n\n"
            "SkillTrustBench v1.0, © Tencent Zhuque Lab, jointly released with "
            "The Chinese University of Hong Kong, Shenzhen.\n\n"
            "Source: https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench\n\n"
            "License: CC BY-NC-SA 4.0 — https://creativecommons.org/licenses/by-nc-sa/4.0/\n\n"
            "Local use: non-commercial security research and Challenge Cup evaluation. "
            "Do not install or execute sample skills.\n"
        )
    for relative_path in DOWNLOADS:
        os.chmod(raw_root / relative_path, stat.S_IREAD)
    return manifest


def default_root() -> Path:
    reproduction_root = Path(__file__).resolve().parents[3]
    return reproduction_root / "datasets" / "skilltrustbench_v1_0"


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely import a fixed SkillTrustBench v1.0 pilot")
    parser.add_argument("--root", type=Path, default=default_root())
    args = parser.parse_args()
    manifest = prepare(args.root.resolve())
    print(json.dumps({
        "status": "prepared",
        "root": str(args.root.resolve()),
        "pilot": manifest["pilot"],
        "stats": manifest["stats"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
