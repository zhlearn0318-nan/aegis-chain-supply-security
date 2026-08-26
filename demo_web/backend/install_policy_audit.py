from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AUDIT_SCHEMA_VERSION = "1.0"
AUDIT_DB_ENV = "AEGIS_OPENCLAW_AUDIT_DB"
MAX_AUDIT_TEXT = 300
DEMO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT_DB = (
    DEMO_ROOT / "data" / "openclaw-install-policy" / "admission_audit.db"
)


def _bounded_text(value: Any, limit: int = MAX_AUDIT_TEXT) -> str:
    normalized = "".join(
        character for character in str(value or "") if ord(character) >= 32
    )
    return " ".join(normalized.split()).strip()[:limit]


def resolve_audit_db() -> Path:
    configured = os.getenv(AUDIT_DB_ENV, "").strip()
    return Path(configured).resolve(strict=False) if configured else DEFAULT_AUDIT_DB


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = FULL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS install_policy_audit (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            schema_version TEXT NOT NULL,
            created_at TEXT NOT NULL,
            protocol_version INTEGER,
            openclaw_version TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_name TEXT NOT NULL,
            source_tree_sha256 TEXT,
            decision TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            finding_rule_ids_json TEXT NOT NULL,
            finding_severities_json TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            review_mode TEXT NOT NULL,
            previous_chain_sha256 TEXT NOT NULL,
            chain_sha256 TEXT NOT NULL UNIQUE
        );
        CREATE TRIGGER IF NOT EXISTS install_policy_audit_no_update
        BEFORE UPDATE ON install_policy_audit
        BEGIN
            SELECT RAISE(ABORT, 'install policy audit rows are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS install_policy_audit_no_delete
        BEFORE DELETE ON install_policy_audit
        BEGIN
            SELECT RAISE(ABORT, 'install policy audit rows are append-only');
        END;
        """
    )
    return connection


def _event_payload(
    payload: Any,
    response: dict[str, Any],
    *,
    source_tree_sha256: str | None,
    duration_ms: int,
) -> dict[str, Any]:
    request = payload if isinstance(payload, dict) else {}
    findings = response.get("findings")
    if not isinstance(findings, list):
        findings = []
    rule_ids = [
        _bounded_text(item.get("ruleId"), 120)
        for item in findings
        if isinstance(item, dict) and _bounded_text(item.get("ruleId"), 120)
    ]
    severities = [
        _bounded_text(item.get("severity"), 20).lower()
        for item in findings
        if isinstance(item, dict) and _bounded_text(item.get("severity"), 20)
    ]
    reason_code = rule_ids[0] if rule_ids else "AEGIS_POLICY_NO_FINDINGS"
    digest = source_tree_sha256 if isinstance(source_tree_sha256, str) else None
    if digest is not None and (
        len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest)
    ):
        digest = None
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "protocol_version": request.get("protocolVersion")
        if isinstance(request.get("protocolVersion"), int)
        else None,
        "openclaw_version": _bounded_text(request.get("openclawVersion"), 100),
        "target_type": _bounded_text(request.get("targetType"), 32),
        "target_name": _bounded_text(request.get("targetName"), 240),
        "source_tree_sha256": digest,
        "decision": _bounded_text(response.get("decision"), 20).lower() or "block",
        "reason_code": reason_code,
        "finding_rule_ids": rule_ids[:3],
        "finding_severities": severities[:3],
        "duration_ms": max(0, int(duration_ms)),
        "review_mode": _bounded_text(
            os.getenv("AEGIS_OPENCLAW_REVIEW_MODE", "warn"), 20
        ).lower()
        or "warn",
    }


def record_install_policy_audit(
    payload: Any,
    response: dict[str, Any],
    source_tree_sha256: str | None,
    duration_ms: int,
    *,
    database: Path | None = None,
) -> str:
    """Append one minimized event and return its integrity-chain SHA-256."""
    event = _event_payload(
        payload,
        response,
        source_tree_sha256=source_tree_sha256,
        duration_ms=duration_ms,
    )
    database = database or resolve_audit_db()
    with closing(_connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_row = connection.execute(
                "SELECT chain_sha256 FROM install_policy_audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = str(previous_row[0]) if previous_row else "0" * 64
            canonical = json.dumps(
                event, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            chain_hash = hashlib.sha256(
                f"{previous_hash}\n{canonical}".encode("utf-8")
            ).hexdigest()
            connection.execute(
                """
                INSERT INTO install_policy_audit (
                    event_id, schema_version, created_at, protocol_version,
                    openclaw_version, target_type, target_name, source_tree_sha256,
                    decision, reason_code, finding_rule_ids_json,
                    finding_severities_json, duration_ms, review_mode,
                    previous_chain_sha256, chain_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    event["schema_version"],
                    event["created_at"],
                    event["protocol_version"],
                    event["openclaw_version"],
                    event["target_type"],
                    event["target_name"],
                    event["source_tree_sha256"],
                    event["decision"],
                    event["reason_code"],
                    json.dumps(event["finding_rule_ids"], ensure_ascii=False),
                    json.dumps(event["finding_severities"], ensure_ascii=False),
                    event["duration_ms"],
                    event["review_mode"],
                    previous_hash,
                    chain_hash,
                ),
            )
    return chain_hash


def verify_install_policy_audit(database: Path | None = None) -> dict[str, Any]:
    database = database or resolve_audit_db()
    if not database.is_file():
        return {"valid": False, "rows": 0, "error": "audit database does not exist"}
    previous_hash = "0" * 64
    with closing(_connect(database)) as connection:
        rows = connection.execute(
            "SELECT * FROM install_policy_audit ORDER BY sequence"
        ).fetchall()
    for row in rows:
        event = {
            "schema_version": row["schema_version"],
            "created_at": row["created_at"],
            "protocol_version": row["protocol_version"],
            "openclaw_version": row["openclaw_version"],
            "target_type": row["target_type"],
            "target_name": row["target_name"],
            "source_tree_sha256": row["source_tree_sha256"],
            "decision": row["decision"],
            "reason_code": row["reason_code"],
            "finding_rule_ids": json.loads(row["finding_rule_ids_json"]),
            "finding_severities": json.loads(row["finding_severities_json"]),
            "duration_ms": row["duration_ms"],
            "review_mode": row["review_mode"],
        }
        canonical = json.dumps(
            event, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        expected = hashlib.sha256(
            f"{previous_hash}\n{canonical}".encode("utf-8")
        ).hexdigest()
        if row["previous_chain_sha256"] != previous_hash or row["chain_sha256"] != expected:
            return {
                "valid": False,
                "rows": len(rows),
                "failed_sequence": row["sequence"],
                "error": "audit integrity chain mismatch",
            }
        previous_hash = expected
    return {
        "valid": True,
        "rows": len(rows),
        "head_chain_sha256": previous_hash,
    }


def read_recent_install_policy_audits(
    database: Path | None = None, *, limit: int = 20
) -> list[dict[str, Any]]:
    database = database or resolve_audit_db()
    if not database.is_file():
        return []
    bounded_limit = min(max(int(limit), 1), 100)
    with closing(_connect(database)) as connection:
        rows = connection.execute(
            """
            SELECT sequence, event_id, created_at, openclaw_version, target_type,
                   target_name, source_tree_sha256, decision, reason_code,
                   finding_rule_ids_json, finding_severities_json, duration_ms,
                   review_mode, chain_sha256
            FROM install_policy_audit
            ORDER BY sequence DESC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()
    return [
        {
            "sequence": row["sequence"],
            "event_id": row["event_id"],
            "created_at": row["created_at"],
            "openclaw_version": row["openclaw_version"],
            "target_type": row["target_type"],
            "target_name": row["target_name"],
            "source_tree_sha256": row["source_tree_sha256"],
            "decision": row["decision"],
            "reason_code": row["reason_code"],
            "finding_rule_ids": json.loads(row["finding_rule_ids_json"]),
            "finding_severities": json.loads(row["finding_severities_json"]),
            "duration_ms": row["duration_ms"],
            "review_mode": row["review_mode"],
            "chain_sha256": row["chain_sha256"],
        }
        for row in rows
    ]
