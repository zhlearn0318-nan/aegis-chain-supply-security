from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.dynamic.run_skill_sandbox_regression20 import (
    DEFAULT_SUITE_CONFIG,
    EXPECTED_CASE_IDS,
    EXPECTED_FAMILIES,
    load_regression_suite,
    verify_fixtures,
)


def test_fixed_regression_suite_has_20_hash_locked_cases() -> None:
    suite = load_regression_suite(DEFAULT_SUITE_CONFIG)
    verified = verify_fixtures(suite)
    assert len(verified) == 20
    assert {case["id"] for case, _root in verified} == EXPECTED_CASE_IDS
    assert {case["family"] for case, _root in verified} == EXPECTED_FAMILIES
    assert sum(case["risk_class"] == "benign" for case, _root in verified) == 4
    assert sum(case["risk_class"] == "dangerous" for case, _root in verified) == 12
    assert sum(case["risk_class"] == "review" for case, _root in verified) == 4


def test_regression_suite_rejects_changed_repeat_count(tmp_path: Path) -> None:
    payload = json.loads(DEFAULT_SUITE_CONFIG.read_text(encoding="utf-8"))
    payload["repeats"] = 2
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="seed or repeat count changed"):
        load_regression_suite(changed)


def test_regression_suite_rejects_case_identity_change(tmp_path: Path) -> None:
    payload = json.loads(DEFAULT_SUITE_CONFIG.read_text(encoding="utf-8"))
    payload["cases"][0]["id"] = "replacement_case"
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="identity set changed"):
        load_regression_suite(changed)
