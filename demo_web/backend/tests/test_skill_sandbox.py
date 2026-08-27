from __future__ import annotations

from pathlib import Path

import pytest

from backend.dynamic_audit.skill_sandbox import (
    SkillSandboxRejected,
    classify_dynamic_events,
    discover_python_entrypoints,
    evaluate_dynamic_result,
    fuse_static_dynamic_decision,
)
from backend.models import Decision


def make_skill(root: Path, manifest: str, files: dict[str, str]) -> Path:
    root.mkdir()
    (root / "SKILL.md").write_text(manifest, encoding="utf-8")
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def test_discovers_manifest_referenced_python_entrypoint(tmp_path: Path) -> None:
    skill = make_skill(
        tmp_path / "skill",
        "Run `scripts/check.py` before installation.\n",
        {"scripts/check.py": "print('ok')\n", "scripts/unused.py.txt": "x"},
    )
    plan = discover_python_entrypoints(skill)
    assert plan.entrypoints == ("scripts/check.py",)
    assert plan.discovery == "skill_manifest"
    assert plan.files_seen == 3


def test_falls_back_to_bounded_scripts_directory(tmp_path: Path) -> None:
    skill = make_skill(
        tmp_path / "skill",
        "No explicit executable path.\n",
        {"scripts/a.py": "print('a')\n", "scripts/b.py": "print('b')\n"},
    )
    plan = discover_python_entrypoints(skill)
    assert plan.entrypoints == ("scripts/a.py", "scripts/b.py")
    assert plan.discovery == "scripts_fallback"


def test_rejects_ambiguous_and_linked_skill(tmp_path: Path) -> None:
    skill = make_skill(
        tmp_path / "many",
        "No explicit path.\n",
        {f"scripts/{name}.py": "pass\n" for name in "abcd"},
    )
    with pytest.raises(SkillSandboxRejected, match="ENTRYPOINT_AMBIGUOUS"):
        discover_python_entrypoints(skill)

    linked = make_skill(
        tmp_path / "linked",
        "Run scripts/real.py\n",
        {"scripts/real.py": "pass\n"},
    )
    link = linked / "scripts" / "alias.py"
    try:
        link.symlink_to(linked / "scripts" / "real.py")
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(SkillSandboxRejected, match="SKILL_LINK_DENIED"):
        discover_python_entrypoints(linked)


def test_classifies_network_shell_decoy_and_sensitive_paths() -> None:
    findings = classify_dynamic_events(
        [
            {"type": "socket.connect", "host": "203.0.113.10", "port": 443},
            {"type": "process.spawn", "executable": "/bin/bash"},
            {"type": "decoy.read", "marker_id": "official_document_1"},
            {"type": "file.open", "path": "/root/.ssh/id_ed25519"},
            {"type": "socket.connect", "host": "127.0.0.1", "port": 8080},
        ]
    )
    rules = {item["rule_id"] for item in findings}
    assert rules == {
        "AEGIS_DYNAMIC_EXTERNAL_NETWORK_ATTEMPT",
        "AEGIS_DYNAMIC_SHELL_SPAWN",
        "AEGIS_DYNAMIC_DECOY_ACCESS",
        "AEGIS_DYNAMIC_SENSITIVE_PATH_ACCESS",
    }


def test_dynamic_evaluation_blocks_high_and_reviews_incomplete() -> None:
    blocked = evaluate_dynamic_result(
        [{"type": "os.system", "command": "sh"}],
        execution_status="completed",
        telemetry_complete=True,
    )
    assert blocked.decision == Decision.BLOCK
    assert blocked.highest_severity == "CRITICAL"

    review = evaluate_dynamic_result(
        [], execution_status="timeout", telemetry_complete=False
    )
    assert review.decision == Decision.REVIEW
    assert {item["rule_id"] for item in review.findings} == {
        "AEGIS_DYNAMIC_TELEMETRY_INCOMPLETE",
        "AEGIS_DYNAMIC_EXECUTION_INCONCLUSIVE",
    }


@pytest.mark.parametrize(
    ("static", "dynamic_events", "status", "complete", "expected"),
    [
        (Decision.BLOCK, [], "completed", True, Decision.BLOCK),
        (Decision.ALLOW, [], "completed", True, Decision.ALLOW),
        (Decision.REVIEW, [], "completed", True, Decision.REVIEW),
        (
            Decision.ALLOW,
            [{"type": "network.connect", "host": "198.51.100.8"}],
            "completed",
            True,
            Decision.BLOCK,
        ),
        (Decision.ALLOW, [], "timeout", True, Decision.REVIEW),
    ],
)
def test_static_dynamic_fusion_is_monotonic(
    static: Decision,
    dynamic_events: list[dict[str, object]],
    status: str,
    complete: bool,
    expected: Decision,
) -> None:
    dynamic = evaluate_dynamic_result(
        dynamic_events, execution_status=status, telemetry_complete=complete
    )
    assert fuse_static_dynamic_decision(static, dynamic) == expected


def test_missing_dynamic_result_never_allows() -> None:
    assert fuse_static_dynamic_decision(Decision.ALLOW, None) == Decision.REVIEW
    assert fuse_static_dynamic_decision(Decision.BLOCK, None) == Decision.BLOCK
