from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRODUCTION_ROOT = DEMO_ROOT.parent
DEFAULT_SOURCE_LOCK = DEMO_ROOT / "baseline" / "third_party_skill_pilot40_v1" / "source_lock.json"
DEFAULT_MASB_ROOT = REPRODUCTION_ROOT / "datasets" / "third_party_baselines" / "malicious_agent_skills_bench"
DEFAULT_REPO_CACHE = REPRODUCTION_ROOT / "datasets" / "third_party_baselines" / "repo_cache"
DEFAULT_SKILLTRUST_ROOT = REPRODUCTION_ROOT / "datasets" / "skilltrustbench_v1_0" / "full"
DEFAULT_SPLIT_ROOT = (
    DEMO_ROOT / "artifacts" / "analysis" / "2026-08-15-skilltrustbench-dev120-regression600-v1"
)
DEFAULT_OUTPUT_ROOT = REPRODUCTION_ROOT / "datasets" / "third_party_skill_pilot40_v1"

MAX_SKILL_FILES = 500
MAX_SKILL_BYTES = 50_000_000
MAX_FILE_BYTES = 10_000_000
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
WINDOWS_INVALID_CHARS = set('<>:"|?*')
GITHUB_ARCHIVE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/archive/", re.IGNORECASE)
EXPECTED_RISK_LABELS = {f"T{index:02d}" for index in range(1, 10)}


class IntakeError(RuntimeError):
    """Raised when a third-party source cannot be imported fail-closed."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(*parts: str) -> str:
    return sha256_bytes("|".join(parts).encode("utf-8"))


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path for path in root.rglob("*") if path.is_file()):
        digest.update(item.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        with item.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def validate_relative_path(value: str) -> PurePosixPath:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise IntakeError(f"Unsafe relative path: {value!r}")
    for part in path.parts:
        if not part or part == ".":
            raise IntakeError(f"Ambiguous relative path: {value!r}")
        if part.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
            raise IntakeError(f"Windows reserved path component: {value!r}")
        if part.endswith((" ", ".")) or any(char in WINDOWS_INVALID_CHARS for char in part):
            raise IntakeError(f"Windows-unsafe path component: {value!r}")
    return path


def repo_cache_name(repository: str) -> str:
    return repository.replace("/", "__").lower()


def run_git(repo_root: Path, *arguments: str) -> bytes:
    completed: subprocess.CompletedProcess[bytes] | None = None
    for attempt in range(4):
        completed = subprocess.run(
            ["git", "-c", "http.sslBackend=openssl", *arguments],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode == 0:
            return completed.stdout
        detail = completed.stderr.decode("utf-8", errors="replace").lower()
        transient = any(marker in detail for marker in (
            "unable to access",
            "tls connect error",
            "ssl/tls connection failed",
            "could not fetch",
        ))
        if not transient or attempt == 3:
            break
        time.sleep(0.5 * (2 ** attempt))
    assert completed is not None
    detail = completed.stderr.decode("utf-8", errors="replace").strip()
    raise IntakeError(f"git {' '.join(arguments)} failed in {repo_root}: {detail}")


def parse_ls_tree(raw: bytes) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise IntakeError("Malformed or non-UTF-8 git tree record") from exc
        rows.append({"mode": mode, "type": object_type, "object_id": object_id, "path": path})
    return rows


def verify_masb_selection(csv_path: Path, source_lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    expected_hash = source_lock["malicious_agent_skills_bench"]["dataset_sha256"]
    actual_hash = sha256_file(csv_path)
    if actual_hash != expected_hash:
        raise IntakeError(f"MaliciousAgentSkillsBench CSV hash mismatch: {actual_hash}")

    seed = str(source_lock["selection_seed"])
    ranked: list[dict[str, Any]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            match = GITHUB_ARCHIVE.match(str(row.get("url", "")))
            if row.get("classification") != "safe" or not match:
                continue
            repository = match.group(1)
            ranked.append({
                **row,
                "repository": repository,
                "candidate_hash": stable_hash(
                    seed,
                    str(row["source"]),
                    str(row["repo"]),
                    str(row["skill_name"]),
                ),
            })
    ranked.sort(key=lambda row: (
        str(row["candidate_hash"]),
        str(row["repository"]).lower(),
        str(row["skill_name"]),
    ))

    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in ranked:
        key = str(row["repository"]).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)

    by_repository = {str(row["repository"]).lower(): (index, row) for index, row in enumerate(unique, 1)}
    verified: dict[str, dict[str, Any]] = {}
    for locked in source_lock["repositories"]:
        repository = str(locked["repository"])
        found = by_repository.get(repository.lower())
        if found is None:
            raise IntakeError(f"Locked repository is absent from deterministic MASB candidates: {repository}")
        index, row = found
        checks = {
            "candidate_index": index,
            "candidate_hash": row["candidate_hash"],
            "skill_name": row["skill_name"],
            "upstream_source": row["source"],
            "upstream_repo_id": row["repo"],
            "upstream_url": row["url"],
        }
        for key, actual in checks.items():
            if str(locked[key]) != str(actual):
                raise IntakeError(
                    f"MASB selection drift for {repository}: {key}={actual!r}, expected {locked[key]!r}"
                )
        verified[repository] = row
    return verified


def contains_binary_marker(data: bytes) -> bool:
    return b"\0" in data[:8192]


def import_git_skill(
    locked: dict[str, Any],
    repo_cache: Path,
    cases_root: Path,
    licenses_root: Path,
) -> dict[str, Any]:
    repository = str(locked["repository"])
    repo_root = repo_cache / repo_cache_name(repository)
    if not (repo_root / ".git").exists():
        raise IntakeError(f"Pinned repository cache is missing: {repository}")
    commit = run_git(repo_root, "rev-parse", "HEAD").decode("ascii").strip()
    if commit != locked["commit"]:
        raise IntakeError(f"Repository commit drift for {repository}: {commit}")

    license_ref = f"{commit}:{locked['license_path']}"
    license_blob = run_git(repo_root, "rev-parse", license_ref).decode("ascii").strip()
    if license_blob != locked["license_git_blob_sha1"]:
        raise IntakeError(f"License blob drift for {repository}: {license_blob}")
    license_bytes = run_git(repo_root, "cat-file", "blob", license_blob)

    skill_path = str(locked["skill_path"]).rstrip("/")
    entries = parse_ls_tree(run_git(repo_root, "ls-tree", "-r", "-z", "--full-tree", commit, "--", skill_path))
    prefix = f"{skill_path}/"
    entries = [entry for entry in entries if entry["path"].startswith(prefix)]
    if not entries:
        raise IntakeError(f"Pinned skill path is empty: {repository}:{skill_path}")
    relative_entries: list[tuple[dict[str, str], PurePosixPath, int]] = []
    total_bytes = 0
    for entry in entries:
        if entry["mode"] == "120000" or entry["type"] != "blob":
            raise IntakeError(f"Links or non-blob objects are not allowed: {repository}:{entry['path']}")
        relative = validate_relative_path(entry["path"][len(prefix):])
        size = int(run_git(repo_root, "cat-file", "-s", entry["object_id"]).decode("ascii").strip())
        if size > MAX_FILE_BYTES:
            raise IntakeError(f"Skill file exceeds {MAX_FILE_BYTES} bytes: {repository}:{entry['path']}")
        total_bytes += size
        relative_entries.append((entry, relative, size))
    if len(relative_entries) > MAX_SKILL_FILES:
        raise IntakeError(f"Skill has too many files: {repository} ({len(relative_entries)})")
    if total_bytes > MAX_SKILL_BYTES:
        raise IntakeError(f"Skill exceeds total byte limit: {repository} ({total_bytes})")
    if not any(relative.as_posix().lower() == "skill.md" for _, relative, _ in relative_entries):
        raise IntakeError(f"Pinned skill has no root SKILL.md: {repository}:{skill_path}")

    case_id = f"masb-{int(locked['candidate_index']):03d}-{locked['skill_name']}"
    case_root = cases_root / case_id
    if case_root.exists():
        raise IntakeError(f"Duplicate output case: {case_id}")
    case_root.mkdir(parents=True)
    file_records: list[dict[str, Any]] = []
    binary_files: list[str] = []
    python_entrypoints: list[str] = []
    for entry, relative, expected_size in relative_entries:
        data = run_git(repo_root, "cat-file", "blob", entry["object_id"])
        if len(data) != expected_size or sha256_bytes(data) == "":
            raise IntakeError(f"Git blob size verification failed: {repository}:{entry['path']}")
        destination = case_root.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        os.chmod(destination, stat.S_IREAD)
        relative_text = relative.as_posix()
        if contains_binary_marker(data):
            binary_files.append(relative_text)
        parts_lower = [part.lower() for part in relative.parts]
        if relative.suffix.lower() == ".py" and "scripts" in parts_lower and not relative.name.startswith("test_"):
            python_entrypoints.append(relative_text)
        file_records.append({
            "path": relative_text,
            "bytes": len(data),
            "sha256": sha256_bytes(data),
            "git_blob_sha1": entry["object_id"],
        })

    license_case_root = licenses_root / case_id
    license_case_root.mkdir(parents=True)
    license_destination = license_case_root / "LICENSE"
    license_destination.write_bytes(license_bytes)
    os.chmod(license_destination, stat.S_IREAD)
    dynamic_pre_static = len(python_entrypoints) == 1 and not binary_files
    return {
        "case_id": case_id,
        "dataset": "MaliciousAgentSkillsBench",
        "source_kind": "real_ecosystem_weak_negative",
        "ground_truth": "weak_safe",
        "metric_eligible": False,
        "dynamic_label_eligible": True,
        "dynamic_candidate_pre_static": dynamic_pre_static,
        "repository": repository,
        "repository_commit": commit,
        "skill_name": locked["skill_name"],
        "skill_path": skill_path,
        "candidate_index": locked["candidate_index"],
        "candidate_hash": locked["candidate_hash"],
        "upstream_source": locked["upstream_source"],
        "upstream_repo_id": locked["upstream_repo_id"],
        "upstream_url": locked["upstream_url"],
        "license_spdx": locked["license_spdx"],
        "license_git_blob_sha1": license_blob,
        "license_sha256": sha256_bytes(license_bytes),
        "local_path": f"cases/{case_id}",
        "case_tree_sha256": tree_sha256(case_root),
        "file_count": len(file_records),
        "total_bytes": total_bytes,
        "binary_files": binary_files,
        "python_entrypoints": sorted(python_entrypoints),
        "files": sorted(file_records, key=lambda row: row["path"]),
    }


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def is_reparse_point(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def copy_verified_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        raise IntakeError(f"Duplicate output directory: {destination.name}")
    destination.mkdir(parents=True)
    for item in sorted(source.rglob("*")):
        if item.is_symlink() or is_reparse_point(item):
            raise IntakeError(f"Link or reparse point in verified source case: {item}")
        relative = item.relative_to(source)
        validate_relative_path(relative.as_posix())
        target = destination / relative
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            if item.stat().st_size > MAX_FILE_BYTES:
                raise IntakeError(f"SkillTrustBench file exceeds limit: {item}")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)
            os.chmod(target, stat.S_IREAD)


def select_skilltrust_cases(
    manifest_rows: list[dict[str, Any]],
    excluded_ids: set[str],
    seed: str,
    counts: dict[str, int],
) -> list[dict[str, Any]]:
    pools = {
        judgment: [
            row for row in manifest_rows
            if row.get("judgment") == judgment and str(row.get("id")) not in excluded_ids
        ]
        for judgment in ("normal", "suspicious", "malicious")
    }
    for judgment, pool in pools.items():
        pool.sort(key=lambda row: (stable_hash(seed, "skilltrustbench", str(row["id"])), str(row["id"])))
        if len(pool) < int(counts[judgment]):
            raise IntakeError(f"Not enough SkillTrustBench {judgment} cases: {len(pool)}")

    selected_by_class: dict[str, list[dict[str, Any]]] = {
        "normal": pools["normal"][: int(counts["normal"])],
        "suspicious": [],
        "malicious": [],
    }
    remaining_quota = {
        "suspicious": int(counts["suspicious"]),
        "malicious": int(counts["malicious"]),
    }
    uncovered = set(EXPECTED_RISK_LABELS)
    selected_ids: set[str] = set()
    while sum(remaining_quota.values()):
        candidates: list[tuple[int, str, str, dict[str, Any]]] = []
        for judgment in ("suspicious", "malicious"):
            if remaining_quota[judgment] <= 0:
                continue
            for row in pools[judgment]:
                case_id = str(row["id"])
                if case_id in selected_ids:
                    continue
                gain = len(set(row.get("risk_labels") or []) & uncovered)
                candidates.append((
                    -gain,
                    stable_hash(seed, "skilltrustbench", case_id),
                    judgment,
                    row,
                ))
        if not candidates:
            raise IntakeError("Could not fill balanced SkillTrustBench non-normal quotas")
        _, _, judgment, chosen = min(candidates, key=lambda item: (item[0], item[1], str(item[3]["id"])))
        selected_by_class[judgment].append(chosen)
        selected_ids.add(str(chosen["id"]))
        remaining_quota[judgment] -= 1
        uncovered -= set(chosen.get("risk_labels") or [])
    if uncovered:
        raise IntakeError(f"The 16-case SkillTrustBench pilot cannot cover: {sorted(uncovered)}")
    return [
        row
        for judgment in ("normal", "suspicious", "malicious")
        for row in selected_by_class[judgment]
    ]


def import_skilltrust_cases(
    source_lock: dict[str, Any],
    skilltrust_root: Path,
    split_root: Path,
    cases_root: Path,
) -> list[dict[str, Any]]:
    config = source_lock["skilltrustbench"]
    manifest_path = skilltrust_root / "full_manifest.jsonl"
    development_path = split_root / "development_case_ids.txt"
    regression_path = split_root / "regression_case_ids.txt"
    expected_hashes = {
        manifest_path: config["full_manifest_sha256"],
        development_path: config["development_ids_sha256"],
        regression_path: config["regression_ids_sha256"],
    }
    for path, expected in expected_hashes.items():
        actual = sha256_file(path)
        if actual != expected:
            raise IntakeError(f"SkillTrustBench source hash mismatch: {path.name}={actual}")
    excluded = {
        line.strip()
        for path in (development_path, regression_path)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    selected = select_skilltrust_cases(
        load_jsonl(manifest_path),
        excluded,
        str(source_lock["selection_seed"]),
        {key: int(value) for key, value in config["selection"].items()},
    )
    records: list[dict[str, Any]] = []
    for row in selected:
        original_id = str(row["id"])
        source_case = skilltrust_root / "cases" / original_id
        expected_tree = str(row["case_tree_sha256"])
        actual_tree = tree_sha256(source_case)
        if actual_tree != expected_tree:
            raise IntakeError(f"SkillTrustBench source tree drift: {original_id}={actual_tree}")
        case_id = f"stb-{original_id}"
        destination = cases_root / case_id
        copy_verified_tree(source_case, destination)
        binary_files = [
            item.relative_to(destination).as_posix()
            for item in destination.rglob("*")
            if item.is_file() and contains_binary_marker(item.read_bytes())
        ]
        python_entrypoints = sorted(
            item.relative_to(destination).as_posix()
            for item in destination.rglob("*.py")
            if "scripts" in [part.lower() for part in item.relative_to(destination).parts]
            and not item.name.startswith("test_")
        )
        judgment = str(row["judgment"])
        records.append({
            "case_id": case_id,
            "dataset": "SkillTrustBench",
            "source_kind": "curated_strong_label",
            "ground_truth": judgment,
            "metric_eligible": True,
            "dynamic_label_eligible": judgment == "normal",
            "dynamic_candidate_pre_static": judgment == "normal" and len(python_entrypoints) == 1 and not binary_files,
            "original_case_id": original_id,
            "risk_labels": row.get("risk_labels", []),
            "base_category": row.get("base_category"),
            "source": row.get("source"),
            "local_path": f"cases/{case_id}",
            "case_tree_sha256": tree_sha256(destination),
            "binary_files": binary_files,
            "python_entrypoints": python_entrypoints,
        })
    return records


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    source_lock_path = args.source_lock.resolve()
    source_lock = json.loads(source_lock_path.read_text(encoding="utf-8"))
    if len(source_lock.get("repositories", [])) != 24:
        raise IntakeError("The source lock must contain exactly 24 real-ecosystem skills")
    masb_csv = args.masb_root.resolve() / source_lock["malicious_agent_skills_bench"]["dataset_file"]
    verify_masb_selection(masb_csv, source_lock)

    output_root = args.output_root.resolve()
    if output_root.exists():
        raise IntakeError(f"Output already exists; refusing to overwrite frozen data: {output_root}")
    staging = output_root.parent / f".{output_root.name}.staging"
    if staging.exists():
        raise IntakeError(f"Staging directory already exists: {staging}")
    cases_root = staging / "cases"
    licenses_root = staging / "licenses"
    cases_root.mkdir(parents=True)
    licenses_root.mkdir(parents=True)
    try:
        masb_records = [
            import_git_skill(locked, args.repo_cache.resolve(), cases_root, licenses_root)
            for locked in source_lock["repositories"]
        ]
        skilltrust_records = import_skilltrust_cases(
            source_lock,
            args.skilltrust_root.resolve(),
            args.split_root.resolve(),
            cases_root,
        )
        records = masb_records + skilltrust_records
        if len(records) != 40 or len({row["case_id"] for row in records}) != 40:
            raise IntakeError("Prepared dataset must contain 40 unique cases")
        write_jsonl(staging / "pilot_manifest.jsonl", records)
        case_ids_text = "".join(f"{row['case_id']}\n" for row in records)
        (staging / "case_ids.txt").write_text(case_ids_text, encoding="utf-8", newline="\n")
        summary = {
            "schema_version": "1.0",
            "baseline_id": source_lock["baseline_id"],
            "selection_seed": source_lock["selection_seed"],
            "source_lock_sha256": sha256_file(source_lock_path),
            "case_ids_sha256": sha256_bytes(case_ids_text.encode("utf-8")),
            "cases": len(records),
            "dataset_counts": dict(Counter(row["dataset"] for row in records)),
            "metric_ground_truth_counts": dict(Counter(
                row["ground_truth"] for row in records if row["metric_eligible"]
            )),
            "weak_negative_cases": sum(row["ground_truth"] == "weak_safe" for row in records),
            "dynamic_candidates_pre_static": sum(bool(row["dynamic_candidate_pre_static"]) for row in records),
            "dynamic_execution_performed": False,
            "label_firewall": "Ground-truth fields are frozen for evaluation and are not scanner inputs.",
        }
        write_json(staging / "intake_manifest.json", summary)
        os.replace(staging, output_root)
        return summary
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare the frozen 40-case third-party Skill pilot.")
    parser.add_argument("--source-lock", type=Path, default=DEFAULT_SOURCE_LOCK)
    parser.add_argument("--masb-root", type=Path, default=DEFAULT_MASB_ROOT)
    parser.add_argument("--repo-cache", type=Path, default=DEFAULT_REPO_CACHE)
    parser.add_argument("--skilltrust-root", type=Path, default=DEFAULT_SKILLTRUST_ROOT)
    parser.add_argument("--split-root", type=Path, default=DEFAULT_SPLIT_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    return parser.parse_args()


def main() -> int:
    try:
        summary = prepare(parse_args())
    except (IntakeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}")
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
