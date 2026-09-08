from __future__ import annotations

import json
from pathlib import Path

from tools.datasets.prepare_m15_e04_robustness_pairs import prepare, tree_sha256


def test_prepare_creates_balanced_hash_locked_pairs(tmp_path: Path) -> None:
    root = tmp_path / "e04"
    lock = prepare(root)
    records = [json.loads(line) for line in (root / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    assert lock["cases"] == 48
    assert len({row["pair_id"] for row in records}) == 24
    assert sum(row["variant"] == "safe_control" for row in records) == 24
    assert sum(row["variant"] == "transformed_risk" for row in records) == 24
    assert {row["runtime"] for row in records} == {"python", "node", "shell"}
    assert all(tree_sha256(root / row["local_path"]) == row["case_tree_sha256"] for row in records)


def test_every_pair_has_one_control_and_one_transformation(tmp_path: Path) -> None:
    root = tmp_path / "e04"
    prepare(root)
    records = [json.loads(line) for line in (root / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    for pair_id in {row["pair_id"] for row in records}:
        pair = [row for row in records if row["pair_id"] == pair_id]
        assert {row["variant"] for row in pair} == {"safe_control", "transformed_risk"}
        assert len({row["factor"] for row in pair}) == 1
        assert len({row["runtime"] for row in pair}) == 1
