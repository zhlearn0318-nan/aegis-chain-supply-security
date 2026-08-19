from __future__ import annotations

import hashlib

import pytest

from tools.evaluation.analyze_skilltrustbench_development import choose_route
from tools.evaluation.freeze_skilltrustbench_development import (
    REGRESSION_SEED,
    build_regression,
    identity,
    stable_rank,
    verify_existing_freeze,
)
from tools.evaluation.run_skilltrustbench import EvaluationError, write_json


def test_regression_selection_is_balanced_deterministic_and_excludes_development() -> None:
    manifest = []
    for label in ("normal", "suspicious", "malicious"):
        for index in range(205):
            case_id = f"{label}-{index:03d}"
            manifest.append({
                "id": case_id,
                "judgment": label,
                "risk_labels": ["T09"] if label != "normal" else [],
                "case_tree_sha256": f"{index:064x}"[-64:],
            })
    excluded = {"normal-000", "suspicious-000", "malicious-000"}

    first = build_regression(manifest, excluded)
    second = build_regression(list(reversed(manifest)), excluded)

    assert first == second
    assert len(first) == 600
    assert not ({row["case_id"] for row in first} & excluded)
    assert sum(row["ground_truth"] == "normal" for row in first) == 200
    assert sum(row["ground_truth"] == "suspicious" for row in first) == 200
    assert sum(row["ground_truth"] == "malicious" for row in first) == 200
    assert first[0]["selection_rank"] == stable_rank(first[0]["case_id"], REGRESSION_SEED)
    assert all(row["content_inspection_status"] == "sealed_not_inspected" for row in first)


def test_persistence_miss_routes_to_new_static_rule() -> None:
    row = {
        "selection_group": "miss_T06_persistence",
        "risk_labels": ["T05", "T06"],
        "base_category": "system_admin",
    }

    route, reasons = choose_route(row, {"persistence_startup"}, set())

    assert route == "new_static_rule"
    assert reasons == ["persistence_primitive_visible_in_static_text"]


def test_declared_network_false_positive_routes_to_evidence_correlation() -> None:
    row = {
        "selection_group": "fp_network_context",
        "risk_labels": [],
        "base_category": "scraper",
    }

    route, reasons = choose_route(row, {"network_client"}, {"declares_network"})

    assert route == "evidence_correlation"
    assert reasons == ["network_behavior_is_declared_by_skill"]


def test_wild_miss_without_concrete_feature_routes_to_semantic_review() -> None:
    row = {
        "selection_group": "miss_wild_real_world",
        "risk_labels": ["T03"],
        "base_category": "wild_real_world",
    }

    route, reasons = choose_route(row, set(), set())

    assert route == "semantic_review"
    assert reasons == ["wild_real_world_miss_has_no_high_signal_regex_feature"]


def test_existing_freeze_verifies_artifact_identity_and_detects_drift(tmp_path) -> None:
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}\n", encoding="utf-8")
    freeze_path = tmp_path / "freeze_manifest.json"
    digest_path = tmp_path / "FREEZE_SHA256.txt"
    write_json(freeze_path, {
        "baseline_id": "skilltrustbench-v1.0-full5520-cisco-static-v1",
        "parent_run_id": "2026-08-14-skilltrustbench-full-cisco-parallel-v1",
        "source_artifacts": [identity(evidence)],
    })
    digest = hashlib.sha256(freeze_path.read_bytes()).hexdigest()
    digest_path.write_text(f"{digest}  freeze_manifest.json\n", encoding="utf-8")

    assert verify_existing_freeze(freeze_path, digest_path)["parent_run_id"].endswith("v1")

    evidence.write_text("changed\n", encoding="utf-8")
    with pytest.raises(EvaluationError, match="byte size differs"):
        verify_existing_freeze(freeze_path, digest_path)
