from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from backend import app as gateway


RULE_ID = re.compile(r"^AEGIS_[A-Z0-9_]+$")


def source_rule_ids() -> set[str]:
    result: set[str] = set()
    root = gateway.DEMO_ROOT / "backend" / "analyzers"
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if RULE_ID.fullmatch(node.value) and not node.value.endswith("_"):
                    result.add(node.value)
    return result


def registry() -> dict:
    path = gateway.DEMO_ROOT / "config" / "aegis_rule_registry.json"
    return json.loads(path.read_text(encoding="utf-8"))


def registry_rule_ids(payload: dict) -> list[str]:
    result: list[str] = []
    for family in payload["families"]:
        rules = family["rules"]
        result.extend(rules if isinstance(rules, list) else rules.keys())
    return result


def test_rule_registry_is_complete_and_has_no_duplicates() -> None:
    payload = registry()
    registered = registry_rule_ids(payload)

    assert payload["schema_version"] == "1.0"
    assert payload["status"] == "development_locked_regression_pending"
    assert len(registered) == len(set(registered))
    assert set(registered) == source_rule_ids()


def test_registry_severities_match_supported_policy_values() -> None:
    supported = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    payload = registry()

    for family in payload["families"]:
        rules = family["rules"]
        if isinstance(rules, list):
            assert family["severity"] in supported
            assert family["decision_effect"] is False
        else:
            for severities in rules.values():
                assert severities
                assert set(severities) <= supported


def test_registry_contains_97_static_rule_ids() -> None:
    assert len(registry_rule_ids(registry())) == 97
