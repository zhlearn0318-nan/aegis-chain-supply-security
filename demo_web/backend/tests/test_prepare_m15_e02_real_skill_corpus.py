from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.datasets.prepare_m15_e02_real_skill_corpus import IntakeError, tree_sha256


def test_tree_hash_excludes_ground_truth_and_intake_manifest(tmp_path: Path) -> None:
    (tmp_path / "cases" / "case-a").mkdir(parents=True)
    (tmp_path / "ground_truth").mkdir()
    (tmp_path / "cases" / "case-a" / "SKILL.md").write_text("safe", encoding="utf-8")
    (tmp_path / "ground_truth" / "labels.jsonl").write_text('{"label": 0}\n', encoding="utf-8")
    (tmp_path / "intake_manifest.json").write_text("{}\n", encoding="utf-8")
    frozen = tree_sha256(tmp_path)
    (tmp_path / "ground_truth" / "labels.jsonl").write_text('{"label": 1}\n', encoding="utf-8")
    (tmp_path / "intake_manifest.json").write_text('{"changed": true}\n', encoding="utf-8")
    assert tree_sha256(tmp_path) == frozen
    (tmp_path / "cases" / "case-a" / "SKILL.md").write_text("changed", encoding="utf-8")
    assert tree_sha256(tmp_path) != frozen


def test_materialize_refuses_existing_output(tmp_path: Path) -> None:
    from tools.datasets.prepare_m15_e02_real_skill_corpus import materialize

    output = tmp_path / "frozen"
    output.mkdir()
    with pytest.raises(IntakeError, match="refusing to replace"):
        materialize(tmp_path / "config.json", output)


def test_verify_scan_inputs_rejects_label_leak(tmp_path: Path) -> None:
    from tools.datasets.prepare_m15_e02_real_skill_corpus import verify_scan_inputs, write_json, write_jsonl

    case_root = tmp_path / "cases" / "case-a"
    case_root.mkdir(parents=True)
    (case_root / "SKILL.md").write_text("safe", encoding="utf-8")
    record = {
        "case_id": "case-a",
        "local_path": "cases/case-a",
        "case_tree_sha256": tree_sha256(case_root),
        "workload_class": "low_permission",
    }
    write_jsonl(tmp_path / "scan_manifest.jsonl", [record] * 40)
    write_json(tmp_path / "intake_manifest.json", {"scan_input_tree_sha256": tree_sha256(tmp_path)})
    with pytest.raises(IntakeError):
        verify_scan_inputs(tmp_path)


def test_config_has_exactly_ten_unique_additions() -> None:
    config = json.loads(
        (Path(__file__).resolve().parents[2] / "config" / "m15_e02_real_skill_corpus_v1.json").read_text(encoding="utf-8")
    )
    case_ids = [row["case_id"] for row in config["additional_skills"]]
    assert len(case_ids) == len(set(case_ids)) == 10
