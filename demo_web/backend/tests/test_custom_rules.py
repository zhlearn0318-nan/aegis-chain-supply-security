from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.custom_rules import (
    CustomRuleError,
    analyze_custom_rules,
    delete_custom_rule,
    load_custom_rule_registry,
    save_custom_rule_registry,
    set_custom_rule_enabled,
    upsert_custom_rule,
)


def structured_rule(**overrides):
    value = {
        "id": "CUSTOM_ENTERPRISE_MARKER",
        "name": "政企敏感标记",
        "description": "识别管理员定义的政企敏感字符串。",
        "kind": "structured",
        "scopes": ["skill", "plugin", "mcp"],
        "severity": "HIGH",
        "action": "BLOCK",
        "enabled": True,
        "match": {
            "mode": "contains",
            "value": "INTERNAL_ONLY_MARKER",
            "case_sensitive": False,
            "extensions": [".py", ".json"],
        },
    }
    value.update(overrides)
    return value


def test_registry_crud_is_revisioned_and_atomic(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    saved = save_custom_rule_registry([structured_rule()], path=path, expected_revision=0)
    assert saved["revision"] == 1
    assert json.loads(path.read_text(encoding="utf-8"))["rules"][0]["id"] == "CUSTOM_ENTERPRISE_MARKER"

    disabled = set_custom_rule_enabled(
        "CUSTOM_ENTERPRISE_MARKER", False, path=path, expected_revision=1
    )
    assert disabled["revision"] == 2
    assert disabled["rules"][0]["enabled"] is False

    updated = upsert_custom_rule(
        structured_rule(name="更新后的规则"), path=path, expected_revision=2
    )
    assert updated["revision"] == 3
    assert updated["rules"][0]["name"] == "更新后的规则"

    deleted = delete_custom_rule(
        "CUSTOM_ENTERPRISE_MARKER", path=path, expected_revision=3
    )
    assert deleted["revision"] == 4
    assert deleted["rules"] == []


def test_revision_conflict_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    save_custom_rule_registry([structured_rule()], path=path, expected_revision=0)
    with pytest.raises(CustomRuleError, match="revision conflict"):
        set_custom_rule_enabled(
            "CUSTOM_ENTERPRISE_MARKER", False, path=path, expected_revision=0
        )


def test_structured_rule_generates_real_finding(tmp_path: Path) -> None:
    registry = tmp_path / "rules.json"
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "main.py").write_text("print('internal_only_marker')\n", encoding="utf-8")
    save_custom_rule_registry([structured_rule()], path=registry, expected_revision=0)

    findings, analyzers = analyze_custom_rules(skill, "skill", registry_path=registry)
    assert analyzers == ["aegis-custom-rules-v1"]
    assert [finding["rule_id"] for finding in findings] == ["CUSTOM_ENTERPRISE_MARKER"]
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["location"]["file"] == "main.py"
    assert "INTERNAL_ONLY_MARKER" not in findings[0]["evidence"]


def test_disabled_and_out_of_scope_rules_do_not_match(tmp_path: Path) -> None:
    registry = tmp_path / "rules.json"
    sample = tmp_path / "sample.py"
    sample.write_text("INTERNAL_ONLY_MARKER", encoding="utf-8")
    save_custom_rule_registry(
        [structured_rule(enabled=False, scopes=["plugin"])],
        path=registry,
        expected_revision=0,
    )
    findings, _ = analyze_custom_rules(sample, "skill", registry_path=registry)
    assert findings == []


def test_yara_rule_is_compiled_before_save_and_matches(tmp_path: Path) -> None:
    registry = tmp_path / "rules.json"
    sample = tmp_path / "sample.txt"
    sample.write_text("AEGIS_YARA_DEMO_MARKER", encoding="utf-8")
    yara_rule = {
        "id": "CUSTOM_YARA_DEMO",
        "name": "YARA 演示规则",
        "description": "验证 YARA 规则会真实编译并参与扫描。",
        "kind": "yara",
        "scopes": ["skill"],
        "severity": "MEDIUM",
        "action": "REVIEW",
        "enabled": True,
        "source": 'rule custom_yara_demo { strings: $a = "AEGIS_YARA_DEMO_MARKER" condition: $a }',
    }
    save_custom_rule_registry([yara_rule], path=registry, expected_revision=0)
    findings, _ = analyze_custom_rules(sample, "skill", registry_path=registry)
    assert [finding["rule_id"] for finding in findings] == ["CUSTOM_YARA_DEMO"]


def test_invalid_yara_and_action_mapping_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    with pytest.raises(CustomRuleError, match="incompatible"):
        save_custom_rule_registry(
            [structured_rule(severity="INFO", action="BLOCK")], path=path
        )
    invalid_yara = {
        "id": "CUSTOM_BAD_YARA",
        "name": "错误 YARA",
        "description": "必须在保存前拒绝。",
        "kind": "yara",
        "scopes": ["skill"],
        "severity": "HIGH",
        "action": "BLOCK",
        "enabled": True,
        "source": "rule broken { condition:",
    }
    with pytest.raises(CustomRuleError, match="YARA compilation failed"):
        save_custom_rule_registry([invalid_yara], path=path)


def test_corrupt_registry_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(CustomRuleError, match="unreadable"):
        load_custom_rule_registry(path)
