from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from backend.install_policy_audit import (
    read_recent_install_policy_audits,
    record_install_policy_audit,
    verify_install_policy_audit,
)
from backend.openclaw_install_policy import evaluate_install_request

from .test_openclaw_install_policy import make_skill, request_for, scan_with


def test_audit_chain_records_minimized_allow_and_block_events(tmp_path: Path) -> None:
    database = tmp_path / "audit" / "admission.db"
    skill_parent = tmp_path / "skill-root"
    skill_parent.mkdir()
    skill = make_skill(skill_parent)
    payload = request_for(skill)
    recorder = lambda request, response, digest, duration: record_install_policy_audit(
        request,
        response,
        digest,
        duration,
        database=database,
    )

    allow = evaluate_install_request(
        payload,
        skill_scan=scan_with(),
        audit_recorder=recorder,
    )
    block = evaluate_install_request(
        payload,
        skill_scan=scan_with({"id": "critical-1", "severity": "CRITICAL"}),
        audit_recorder=recorder,
    )

    assert allow["decision"] == "allow"
    assert block["decision"] == "block"
    verification = verify_install_policy_audit(database)
    assert verification["valid"] is True
    assert verification["rows"] == 2

    raw_database = database.read_bytes()
    assert str(skill).encode() not in raw_database
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT decision, source_tree_sha256, target_name FROM install_policy_audit ORDER BY sequence"
        ).fetchall()
    assert [row[0] for row in rows] == ["allow", "block"]
    assert all(len(row[1]) == 64 for row in rows)
    assert all(row[2] == "install-policy-test" for row in rows)
    recent = read_recent_install_policy_audits(database, limit=1)
    assert len(recent) == 1
    assert recent[0]["decision"] == "block"
    assert "source_path" not in recent[0]


def test_audit_table_rejects_updates_and_deletes(tmp_path: Path) -> None:
    database = tmp_path / "admission.db"
    record_install_policy_audit(
        {},
        {
            "decision": "block",
            "findings": [
                {
                    "ruleId": "AEGIS_POLICY_INVALID_REQUEST",
                    "severity": "critical",
                }
            ],
        },
        None,
        1,
        database=database,
    )

    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE install_policy_audit SET decision = 'allow' WHERE sequence = 1"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM install_policy_audit WHERE sequence = 1")


def test_audit_write_failure_changes_allow_to_fail_closed(tmp_path: Path) -> None:
    skill = make_skill(tmp_path)

    def broken_recorder(*_args) -> str:
        raise OSError("disk unavailable")

    response = evaluate_install_request(
        request_for(skill),
        skill_scan=scan_with(),
        audit_recorder=broken_recorder,
    )

    assert response["decision"] == "block"
    assert response["findings"][0]["ruleId"] == "AEGIS_POLICY_AUDIT_FAILED"
