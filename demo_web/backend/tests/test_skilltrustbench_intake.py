from __future__ import annotations

import io
import hashlib
import json
import stat
import zipfile

import pytest

from tools.datasets.prepare_skilltrustbench import (
    IntakeError,
    EXPECTED_RISK_LABELS,
    PILOT_PER_CLASS,
    git_blob_sha1_bytes,
    select_pilot,
    tree_sha256,
    validate_archive,
    verify_source_object,
    verify_existing_pilot,
)
from tools.datasets.prepare_skilltrustbench_official_subset import (
    archive_case_tree_sha256,
    case_ids_sha256,
    prepare_cases,
)


def make_record(case_id: str, judgment: str, risk_labels: list[str]) -> dict:
    return {
        "id": case_id,
        "judgment": judgment,
        "risk_labels": risk_labels,
        "source": "test",
        "base_category": "test",
    }


def test_pilot_selection_is_balanced_deterministic_and_covers_taxonomy() -> None:
    records = []
    for judgment in ("normal", "suspicious", "malicious"):
        for index in range(45):
            labels = []
            if judgment != "normal":
                labels = [f"T{(index % 9) + 1:02d}"]
            records.append(make_record(f"{judgment}-{index:02d}", judgment, labels))

    first = select_pilot(records)
    second = select_pilot(list(reversed(records)))

    assert [row["id"] for row in first] == [row["id"] for row in second]
    assert len(first) == PILOT_PER_CLASS * 3
    assert {judgment: sum(row["judgment"] == judgment for row in first) for judgment in ("normal", "suspicious", "malicious")} == {
        "normal": PILOT_PER_CLASS,
        "suspicious": PILOT_PER_CLASS,
        "malicious": PILOT_PER_CLASS,
    }
    assert {label for row in first for label in row["risk_labels"]} == EXPECTED_RISK_LABELS


def test_archive_validation_rejects_path_traversal() -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("benchmark_full_v1.0/case_00001/SKILL.md", "safe")
        archive.writestr("benchmark_full_v1.0/../../escape.txt", "bad")
    stream.seek(0)

    with zipfile.ZipFile(stream) as archive, pytest.raises(IntakeError, match="Unsafe archive member path"):
        validate_archive(archive)


def test_archive_validation_rejects_symbolic_links() -> None:
    stream = io.BytesIO()
    link = zipfile.ZipInfo("benchmark_full_v1.0/case_00001/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(link, "target")
    stream.seek(0)

    with zipfile.ZipFile(stream) as archive, pytest.raises(IntakeError, match="Symbolic link"):
        validate_archive(archive)


def test_git_blob_identity_includes_header_and_size() -> None:
    assert git_blob_sha1_bytes(b"test\n") == "9daeafb9864cf43055ae93beb0afd6c7d144bfa4"


def test_existing_pilot_is_reused_only_when_ids_and_tree_hashes_match(tmp_path) -> None:
    pilot_root = tmp_path / "pilot"
    case_root = pilot_root / "cases" / "case_00001"
    case_root.mkdir(parents=True)
    (case_root / "SKILL.md").write_text("example", encoding="utf-8")
    manifest_record = {
        "id": "case_00001",
        "judgment": "normal",
        "risk_labels": [],
        "case_tree_sha256": tree_sha256(case_root),
    }
    (pilot_root / "pilot_manifest.jsonl").write_text(
        json.dumps(manifest_record) + "\n", encoding="utf-8"
    )

    verified = verify_existing_pilot(pilot_root, [manifest_record])

    assert verified == [manifest_record]
    (case_root / "SKILL.md").write_text("changed", encoding="utf-8")
    with pytest.raises(IntakeError, match="tree hash mismatch"):
        verify_existing_pilot(pilot_root, [manifest_record])


def test_official_case_id_hash_sorts_ids_and_uses_real_lf_bytes() -> None:
    records = [{"id": "case_00002"}, {"id": "case_00001"}]
    expected = hashlib.sha256(b"case_00001\ncase_00002\n").hexdigest()

    assert case_ids_sha256(records) == expected


def test_generic_source_identity_accepts_fixed_sha256(tmp_path) -> None:
    target = tmp_path / "source.jsonl"
    target.write_bytes(b"fixed source\n")
    source = {
        "bytes": target.stat().st_size,
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    }

    assert verify_source_object(target, source)["sha256"] == source["sha256"]


def test_prior_endpoint_blocked_case_is_not_reextracted(tmp_path) -> None:
    archive_path = tmp_path / "dataset.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("benchmark_full_v1.0/case_00001/SKILL.md", "blocked content")
    selected = [make_record("case_00001", "malicious", ["T01"])]
    with zipfile.ZipFile(archive_path) as archive:
        audit = validate_archive(archive)
        tree_hash = archive_case_tree_sha256(archive, audit["case_members"]["case_00001"])
        prior = [{
            **selected[0],
            "local_path": "official_10pct/cases/case_00001",
            "case_tree_sha256": tree_hash,
            "scanner_eligible": False,
        }]
        records = prepare_cases(
            archive,
            audit["case_members"],
            selected,
            tmp_path / "cases",
            prior,
        )

    assert records == prior
    assert not (tmp_path / "cases" / "case_00001" / "SKILL.md").exists()
