from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from backend.openclaw_install_policy import (
    MAX_FINDINGS,
    SourceTreeLimits,
    SourceTreeRejected,
    evaluate_install_request,
    hash_source_tree,
    normalize_findings_for_openclaw,
)


def make_skill(tmp_path: Path) -> Path:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: install-policy-test\ndescription: local test\n---\n",
        encoding="utf-8",
    )
    return skill


def request_for(skill: Path, **overrides) -> dict:
    payload = {
        "protocolVersion": 1,
        "openclawVersion": "2026.8.1",
        "targetType": "skill",
        "targetName": "install-policy-test",
        "sourcePath": str(skill.resolve()),
        "sourcePathKind": "directory",
        "source": {"kind": "local-path", "mutable": True},
        "origin": {"type": "local"},
        "request": {"kind": "skill-install", "mode": "install"},
    }
    payload.update(overrides)
    return payload


def scan_with(*findings: dict):
    return lambda _path: {"findings": list(findings), "analyzers": ["test"]}


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (None, "allow"),
        ("INFO", "allow"),
        ("LOW", "warn"),
        ("MEDIUM", "warn"),
        ("HIGH", "block"),
        ("CRITICAL", "block"),
        ("UNKNOWN", "block"),
    ],
)
def test_maps_existing_policy_without_changing_decision_semantics(
    tmp_path: Path, severity: str | None, expected: str
) -> None:
    skill = make_skill(tmp_path)
    findings = [] if severity is None else [{"id": "rule-1", "severity": severity}]

    response = evaluate_install_request(request_for(skill), skill_scan=scan_with(*findings))

    assert response["protocolVersion"] == 1
    assert response["decision"] == expected
    assert response["reason"]


@pytest.mark.parametrize(
    ("payload", "rule_id"),
    [
        ([], "AEGIS_POLICY_INVALID_REQUEST"),
        ({}, "AEGIS_POLICY_PROTOCOL_MISMATCH"),
        ({"protocolVersion": 2}, "AEGIS_POLICY_PROTOCOL_MISMATCH"),
    ],
)
def test_invalid_requests_fail_closed(payload, rule_id: str) -> None:
    response = evaluate_install_request(payload)

    assert response["decision"] == "block"
    assert response["findings"][0]["ruleId"] == rule_id


def test_plugin_target_fails_closed_until_v11_support(tmp_path: Path) -> None:
    skill = make_skill(tmp_path)

    response = evaluate_install_request(
        request_for(skill, targetType="plugin"), skill_scan=scan_with()
    )

    assert response["decision"] == "block"
    assert response["findings"][0]["ruleId"] == "AEGIS_POLICY_UNSUPPORTED_TARGET"


@pytest.mark.parametrize(
    "overrides",
    [
        {"sourcePath": "relative/path"},
        {"sourcePath": "Z:\\definitely-missing-aegis-source"},
        {"sourcePathKind": "archive"},
        {"targetType": "unknown"},
    ],
)
def test_invalid_source_or_request_shape_fails_closed(
    tmp_path: Path, overrides: dict
) -> None:
    skill = make_skill(tmp_path)

    response = evaluate_install_request(
        request_for(skill, **overrides), skill_scan=scan_with()
    )

    assert response["decision"] == "block"


def test_scan_timeout_and_failure_fail_closed(tmp_path: Path) -> None:
    skill = make_skill(tmp_path)

    def timeout(_path: Path):
        raise subprocess.TimeoutExpired(["skill-scanner"], 1)

    def failure(_path: Path):
        raise RuntimeError("private scanner detail must not be exposed")

    timeout_response = evaluate_install_request(request_for(skill), skill_scan=timeout)
    failure_response = evaluate_install_request(request_for(skill), skill_scan=failure)

    assert timeout_response["decision"] == "block"
    assert timeout_response["findings"][0]["ruleId"] == "AEGIS_POLICY_SCAN_TIMEOUT"
    assert failure_response["decision"] == "block"
    assert failure_response["findings"][0]["ruleId"] == "AEGIS_POLICY_SCAN_FAILED"
    assert "private scanner detail" not in json.dumps(failure_response, ensure_ascii=False)


def test_source_change_during_scan_fails_closed(tmp_path: Path) -> None:
    skill = make_skill(tmp_path)
    hashes = iter(["before", "after"])

    response = evaluate_install_request(
        request_for(skill),
        skill_scan=scan_with(),
        tree_hasher=lambda _path: next(hashes),
    )

    assert response["decision"] == "block"
    assert response["findings"][0]["ruleId"] == "AEGIS_POLICY_SOURCE_CHANGED"


def test_tree_hash_is_repeatable_and_changes_with_content(tmp_path: Path) -> None:
    skill = make_skill(tmp_path)
    script = skill / "run.py"
    script.write_text("print('safe')\n", encoding="utf-8")

    first = hash_source_tree(skill)
    second = hash_source_tree(skill)
    script.write_text("print('changed')\n", encoding="utf-8")
    changed = hash_source_tree(skill)

    assert first == second
    assert changed != first


def test_tree_hash_enforces_file_and_size_limits(tmp_path: Path) -> None:
    skill = make_skill(tmp_path)
    (skill / "second.txt").write_text("x", encoding="utf-8")

    with pytest.raises(SourceTreeRejected, match="文件数超过上限"):
        hash_source_tree(skill, SourceTreeLimits(max_files=1))
    with pytest.raises(SourceTreeRejected, match="超大文件"):
        hash_source_tree(
            skill,
            SourceTreeLimits(max_files=10, max_total_bytes=100, max_file_bytes=1),
        )


def test_findings_are_bounded_and_do_not_leak_host_absolute_paths(tmp_path: Path) -> None:
    skill = make_skill(tmp_path)
    outside = tmp_path.parent / "secret.txt"
    findings = [
        {
            "id": f"finding-{index}",
            "title": "x" * 2_000,
            "severity": "MEDIUM",
            "location": {"file": str(outside), "line": 3.9},
            "evidence": "e" * 2_000,
        }
        for index in range(MAX_FINDINGS + 5)
    ]

    normalized = normalize_findings_for_openclaw(findings, skill.resolve())

    assert len(normalized) == MAX_FINDINGS
    assert all(len(item["message"]) <= 160 for item in normalized)
    assert all(len(item["evidence"]) <= 200 for item in normalized)
    assert all("file" not in item for item in normalized)
    assert all(item["line"] == 3 for item in normalized)


def test_high_risk_findings_are_prioritized_before_display_limit(tmp_path: Path) -> None:
    skill = make_skill(tmp_path)
    findings = [
        {"id": f"info-{index}", "title": "context", "severity": "INFO"}
        for index in range(MAX_FINDINGS + 2)
    ]
    findings.append({"id": "critical-last", "title": "risk", "severity": "CRITICAL"})

    normalized = normalize_findings_for_openclaw(findings, skill.resolve())

    assert normalized[0]["ruleId"] == "critical-last"
    assert normalized[0]["severity"] == "critical"


def test_legacy_review_mode_fails_closed_instead_of_emitting_warn(
    tmp_path: Path, monkeypatch
) -> None:
    skill = make_skill(tmp_path)
    monkeypatch.setenv("AEGIS_OPENCLAW_REVIEW_MODE", "block")

    response = evaluate_install_request(
        request_for(skill),
        skill_scan=scan_with({"id": "review-1", "severity": "MEDIUM"}),
    )

    assert response["decision"] == "block"
    assert "兼容模式" in response["reason"]


def test_invalid_review_mode_fails_closed(tmp_path: Path, monkeypatch) -> None:
    skill = make_skill(tmp_path)
    monkeypatch.setenv("AEGIS_OPENCLAW_REVIEW_MODE", "unexpected")

    response = evaluate_install_request(
        request_for(skill),
        skill_scan=scan_with({"id": "review-1", "severity": "MEDIUM"}),
    )

    assert response["decision"] == "block"
    assert "配置无效" in response["reason"]


def test_cli_emits_exactly_one_fail_closed_json_object_for_invalid_json() -> None:
    script = Path(__file__).resolve().parents[2] / "tools" / "openclaw_install_policy.py"

    completed = subprocess.run(
        [sys.executable, str(script)],
        input="not-json",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=10,
    )
    response = json.loads(completed.stdout)

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert response["protocolVersion"] == 1
    assert response["decision"] == "block"
    assert "无法解析" in response["reason"]
    assert response["findings"][0]["ruleId"] == "AEGIS_POLICY_INVALID_REQUEST"


def test_node_proxy_fails_closed_when_required_paths_are_missing() -> None:
    proxy = Path(__file__).resolve().parents[2] / "tools" / "openclaw_install_policy_proxy.mjs"
    child_env = {
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
        "WINDIR": os.environ.get("WINDIR", "C:\\Windows"),
    }

    completed = subprocess.run(
        ["node", str(proxy)],
        input="{}",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=child_env,
        check=False,
        timeout=10,
    )
    response = json.loads(completed.stdout)

    assert completed.returncode == 0
    assert response["decision"] == "block"
    assert response["findings"][0]["ruleId"] == "AEGIS_POLICY_PROXY_CONFIGURATION_ERROR"
