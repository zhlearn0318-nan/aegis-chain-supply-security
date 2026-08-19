from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from backend.dynamic_audit.policy import (
    DynamicPolicyViolation,
    DynamicSafetyPolicy,
    canonical_argv_sha256,
    command_line_sha256,
)
from backend.dynamic_audit.runner import (
    DEMO_ROOT,
    DynamicAuditConfigurationError,
    run_safe_fixture_set,
    sha256_file,
)


CONFIG_PATH = DEMO_ROOT / "config" / "safe_dynamic_fixtures.json"
FIXTURE_ROOT = DEMO_ROOT / "tools" / "dynamic" / "fixtures"
CHILD_TAIL = (
    "-I",
    "-c",
    "import sys; data=sys.stdin.read(); sys.stdout.write(str(len(data)))",
)


def build_policy(tmp_path: Path, port: int | None = 43123) -> DynamicSafetyPolicy:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return DynamicSafetyPolicy(
        workspace=workspace,
        fixture_root=FIXTURE_ROOT,
        allowed_python=Path(sys.executable),
        allowed_loopback_port=port,
        allowed_process_argv_sha256=frozenset({
            canonical_argv_sha256(["<PYTHON>", *CHILD_TAIL]),
            command_line_sha256(subprocess.list2cmdline([sys.executable, *CHILD_TAIL])),
        }),
    )


def test_write_outside_workspace_is_denied_before_open(tmp_path: Path) -> None:
    policy = build_policy(tmp_path)
    with pytest.raises(DynamicPolicyViolation, match="WRITE_OUTSIDE_WORKSPACE"):
        policy.validate_write_path(tmp_path / "outside.txt")
    assert not (tmp_path / "outside.txt").exists()


def test_relative_write_uses_current_directory_and_chdir_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = build_policy(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    with pytest.raises(DynamicPolicyViolation, match="WRITE_OUTSIDE_WORKSPACE"):
        policy.validate_write_path("relative.txt")
    with pytest.raises(DynamicPolicyViolation, match="CHDIR_OUTSIDE_WORKSPACE"):
        policy.validate_chdir_path(outside)


def test_link_creation_is_always_denied(tmp_path: Path) -> None:
    policy = build_policy(tmp_path)
    with pytest.raises(DynamicPolicyViolation, match="LINK_CREATION_DENIED"):
        policy.deny_link_creation()


@pytest.mark.parametrize("address", [
    ("203.0.113.1", 43123),
    ("example.invalid", 43123),
    ("127.0.0.1", 43124),
])
def test_non_loopback_hostname_and_unapproved_port_are_denied_without_connect(
    tmp_path: Path, address: tuple[str, int]
) -> None:
    policy = build_policy(tmp_path)
    with pytest.raises(DynamicPolicyViolation):
        policy.validate_network_address(address)


def test_only_exact_python_argv_is_allowed(tmp_path: Path) -> None:
    policy = build_policy(tmp_path)
    canonical, digest = policy.validate_process(
        sys.executable,
        [sys.executable, *CHILD_TAIL],
    )
    assert canonical[0] == "<PYTHON>"
    assert digest in policy.allowed_process_argv_sha256
    inferred, inferred_digest = policy.validate_process(None, [sys.executable, *CHILD_TAIL])
    assert inferred == canonical
    assert inferred_digest == digest
    windows_command = subprocess.list2cmdline([sys.executable, *CHILD_TAIL])
    command_marker, command_digest = policy.validate_process(None, windows_command)
    assert command_marker == ["<EXACT_WINDOWS_COMMAND_LINE>"]
    assert command_digest in policy.allowed_process_argv_sha256
    with pytest.raises(DynamicPolicyViolation):
        policy.validate_process(None, f"{sys.executable} -c pass")
    with pytest.raises(DynamicPolicyViolation):
        policy.validate_process(sys.executable, [sys.executable, "-c", "pass"])


def test_fixture_config_hashes_match_sources() -> None:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    for row in payload["fixtures"]:
        assert sha256_file(FIXTURE_ROOT / row["script"]) == row["sha256"]


def test_hash_mismatch_is_rejected_before_execution(tmp_path: Path) -> None:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    payload["fixtures"][0]["sha256"] = "0" * 64
    bad_config = tmp_path / "bad-config.json"
    bad_config.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DynamicAuditConfigurationError, match="sha256 mismatch"):
        run_safe_fixture_set(bad_config, tmp_path / "never-created-workspaces")
    assert not (tmp_path / "never-created-workspaces").exists()


def test_three_safe_fixtures_emit_expected_redacted_evidence(tmp_path: Path) -> None:
    result = run_safe_fixture_set(CONFIG_PATH, tmp_path / "workspaces")
    metrics = result["metrics"]

    assert result["success"] is True
    assert metrics["fixtures_completed"] == metrics["fixtures_total"] == 3
    assert metrics["expected_checks_passed"] == metrics["expected_checks_total"] == 7
    assert metrics["policy_violations"] == 0
    assert metrics["timeouts"] == 0
    assert metrics["event_parse_errors"] == 0
    assert metrics["server_receipts"] == metrics["server_payload_matches"] == 1
    assert metrics["non_info_evidence"] == 0
    assert metrics["raw_token_leaks"] == 0
    assert metrics["protected_samples_read"] == metrics["protected_samples_executed"] == 0
    assert metrics["internet_connections_allowed"] == 0
    assert metrics["decision_changes"] == 0

    counts = metrics["event_type_counts"]
    assert counts["process_spawn"] >= 1
    assert counts["stdin_read"] >= 1
    assert counts["environment_read"] >= 3
    assert counts["file_write"] >= 1
    assert counts["file_read"] >= 1
    assert counts["network_connect"] >= 1

    evidence_events = [event for event in result["events"] if "severity" in event]
    assert evidence_events
    assert all(event["severity"] == "INFO" for event in evidence_events)
    assert all(event["policy_effect"] == "none" for event in evidence_events)

    serialized = json.dumps(result, ensure_ascii=False)
    for token in (
        "DYNFIXTURE_STDIN_9C2E6A1F",
        "DYNFIXTURE_ENV_8A5D3C7E",
        "DYNFIXTURE_LOOPBACK_2F6C9B4D",
    ):
        assert token not in serialized

    file_result = next(item for item in result["fixture_results"] if item["fixture_id"] == "file_io")
    assert file_result["workspace_files"] == [{
        "path": "fixture_output.txt",
        "bytes": 24,
        "sha256": sha256_file(tmp_path / "workspaces" / "file_io" / "fixture_output.txt"),
    }]
