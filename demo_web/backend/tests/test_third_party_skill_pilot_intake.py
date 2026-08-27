from __future__ import annotations

import csv
import hashlib

import pytest

from tools.datasets.prepare_third_party_skill_pilot import (
    IntakeError,
    parse_ls_tree,
    select_skilltrust_cases,
    stable_hash,
    validate_relative_path,
    verify_masb_selection,
)


def test_parse_ls_tree_preserves_mode_object_and_utf8_path() -> None:
    raw = b"100644 blob abc123\tskills/example/SKILL.md\0"

    assert parse_ls_tree(raw) == [{
        "mode": "100644",
        "type": "blob",
        "object_id": "abc123",
        "path": "skills/example/SKILL.md",
    }]


@pytest.mark.parametrize("path", ["../escape", "/absolute", "safe/CON/file.py", "safe/bad?.py"])
def test_validate_relative_path_rejects_unsafe_windows_or_escape_paths(path: str) -> None:
    with pytest.raises(IntakeError):
        validate_relative_path(path)


def test_masb_selection_is_recomputed_instead_of_trusting_lock(tmp_path) -> None:
    csv_path = tmp_path / "skills_dataset.csv"
    rows = [
        {
            "source": "source-a",
            "repo": "row-a",
            "skill_name": "skill-a",
            "classification": "safe",
            "url": "https://github.com/example/a/archive/main.zip",
        },
        {
            "source": "source-b",
            "repo": "row-b",
            "skill_name": "skill-b",
            "classification": "safe",
            "url": "https://github.com/example/b/archive/main.zip",
        },
        {
            "source": "source-c",
            "repo": "row-c",
            "skill_name": "skill-c",
            "classification": "malicious",
            "url": "https://github.com/example/c/archive/main.zip",
        },
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    seed = "test-seed"
    ranked = sorted(rows[:2], key=lambda row: stable_hash(seed, row["source"], row["repo"], row["skill_name"]))
    selected = ranked[0]
    selected_repository = selected["url"].split("github.com/", 1)[1].split("/archive/", 1)[0]
    lock = {
        "selection_seed": seed,
        "malicious_agent_skills_bench": {"dataset_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest()},
        "repositories": [{
            "candidate_index": 1,
            "candidate_hash": stable_hash(seed, selected["source"], selected["repo"], selected["skill_name"]),
            "repository": selected_repository,
            "skill_name": selected["skill_name"],
            "upstream_source": selected["source"],
            "upstream_repo_id": selected["repo"],
            "upstream_url": selected["url"],
        }],
    }

    verified = verify_masb_selection(csv_path, lock)

    assert list(verified) == [selected_repository]
    lock["repositories"][0]["candidate_hash"] = "0" * 64
    with pytest.raises(IntakeError, match="selection drift"):
        verify_masb_selection(csv_path, lock)


def test_skilltrust_selection_is_balanced_deterministic_and_excludes_frozen_sets() -> None:
    rows = [
        {
            "id": f"{judgment}-{index:02d}",
            "judgment": judgment,
            "risk_labels": (
                []
                if judgment == "normal"
                else [f"T{(index % 9) + 1:02d}"] + (["T09"] if index == 1 else [])
            ),
        }
        for judgment in ("normal", "suspicious", "malicious")
        for index in range(12)
    ]
    excluded = {"normal-00", "suspicious-00", "malicious-00"}
    counts = {"normal": 8, "suspicious": 4, "malicious": 4}

    first = select_skilltrust_cases(rows, excluded, "20260827", counts)
    second = select_skilltrust_cases(list(reversed(rows)), excluded, "20260827", counts)

    assert [row["id"] for row in first] == [row["id"] for row in second]
    assert all(row["id"] not in excluded for row in first)
    assert {
        judgment: sum(row["judgment"] == judgment for row in first)
        for judgment in counts
    } == counts
    assert {
        label
        for row in first
        for label in row.get("risk_labels", [])
    } == {f"T{index:02d}" for index in range(1, 10)}
