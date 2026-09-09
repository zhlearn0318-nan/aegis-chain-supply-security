from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.datasets.prepare_m15_e01_splits import IntakeError, tree_sha256


def test_tree_sha256_is_stable_and_excludes_ground_truth(tmp_path: Path) -> None:
    (tmp_path / "cases" / "a").mkdir(parents=True)
    (tmp_path / "ground_truth").mkdir()
    (tmp_path / "cases" / "a" / "SKILL.md").write_text("safe", encoding="utf-8")
    (tmp_path / "ground_truth" / "labels.jsonl").write_text(
        json.dumps({"label": "0"}), encoding="utf-8"
    )
    before = tree_sha256(tmp_path)
    (tmp_path / "ground_truth" / "labels.jsonl").write_text(
        json.dumps({"label": "1"}), encoding="utf-8"
    )
    assert tree_sha256(tmp_path) == before
    (tmp_path / "cases" / "a" / "SKILL.md").write_text("changed", encoding="utf-8")
    assert tree_sha256(tmp_path) != before


def test_pinned_contract_rejects_an_existing_output(tmp_path: Path) -> None:
    from tools.datasets.prepare_m15_e01_splits import materialize

    output = tmp_path / "already-frozen"
    output.mkdir()
    with pytest.raises(IntakeError, match="refusing to replace"):
        materialize(tmp_path / "input", output)


def test_label_blind_verifier_does_not_require_ground_truth(tmp_path: Path) -> None:
    from tools.datasets.prepare_m15_e01_splits import verify_scan_inputs, write_json, write_jsonl

    root = tmp_path / "data"
    split_root = root / "validation"
    case_root = split_root / "cases" / "case-1"
    case_root.mkdir(parents=True)
    skill = case_root / "SKILL.md"
    skill.write_text("safe", encoding="utf-8")
    row = {
        "case_id": "case-1",
        "benchmark_id": "CASE-1",
        "local_path": "cases/case-1",
        "skill_text_sha256": __import__("hashlib").sha256(b"safe").hexdigest(),
        "skill_text_bytes": 4,
        "text_field": "skill_text",
        "scan_ready": True,
        "unavailability_reason": None,
    }
    write_jsonl(split_root / "scan_manifest.jsonl", [row])
    (split_root / "case_ids.txt").write_text("case-1\n", encoding="utf-8")
    write_json(split_root / "intake_manifest.json", {"scan_input_tree_sha256": tree_sha256(split_root)})
    write_json(root / "dataset_manifest.json", {"dataset_revision": "d4b42ce5766a6e0359c987cf59c1007cb3795a90"})
    import tools.datasets.prepare_m15_e01_splits as module

    original = module.EXPECTED_SPLIT_COUNTS["validation"]
    module.EXPECTED_SPLIT_COUNTS["validation"] = 1
    try:
        result = verify_scan_inputs(root, ("validation",))
    finally:
        module.EXPECTED_SPLIT_COUNTS["validation"] = original
    assert result["ground_truth_opened"] is False
    assert not (split_root / "ground_truth").exists()
