#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[1]
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.custom_rules import (  # noqa: E402
    CustomRuleError,
    delete_custom_rule,
    load_custom_rule_registry,
    resolve_custom_rules_path,
    set_custom_rule_enabled,
    upsert_custom_rule,
)
from backend.install_policy_audit import (  # noqa: E402
    read_install_policy_audit,
    read_recent_install_policy_audits,
    verify_install_policy_audit,
)
from backend.mcp_server_admission import admit_mcp_server  # noqa: E402


MAX_STDIN_BYTES = 128 * 1024
BUILTIN_REGISTRY = DEMO_ROOT / "config" / "aegis_rule_registry.json"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _builtin_summary() -> dict[str, Any]:
    payload = json.loads(BUILTIN_REGISTRY.read_text(encoding="utf-8"))
    families = payload.get("families") if isinstance(payload, dict) else []
    rows = []
    for family in families if isinstance(families, list) else []:
        if not isinstance(family, dict):
            continue
        rules = family.get("rules") if isinstance(family.get("rules"), dict) else {}
        rows.append({
            "analyzer": str(family.get("analyzer") or "unknown"),
            "scope": str(family.get("scope") or "unknown"),
            "decision_effect": bool(family.get("decision_effect")),
            "count": len(rules),
        })
    return {
        "registry_id": payload.get("registry_id"),
        "status": payload.get("status"),
        "count": sum(row["count"] for row in rows),
        "families": rows,
        "editable": False,
    }


def _rule_change_path() -> Path:
    return resolve_custom_rules_path().with_name("custom_rule_changes.jsonl")


def _read_rule_changes(limit: int = 50) -> dict[str, Any]:
    path = _rule_change_path()
    if not path.is_file():
        return {"valid": True, "rows": 0, "events": []}
    previous = "0" * 64
    events: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return {"valid": False, "rows": len(events), "failed_sequence": index, "events": []}
        chain = event.pop("chain_sha256", None)
        expected = hashlib.sha256(f"{previous}\n{_canonical(event)}".encode("utf-8")).hexdigest()
        if event.get("previous_chain_sha256") != previous or chain != expected:
            return {"valid": False, "rows": len(events), "failed_sequence": index, "events": []}
        event["chain_sha256"] = chain
        events.append(event)
        previous = expected
    return {"valid": True, "rows": len(events), "head_chain_sha256": previous, "events": list(reversed(events[-limit:]))}


def _record_rule_change(action: str, rule_id: str, registry: dict[str, Any]) -> None:
    path = _rule_change_path()
    current = _read_rule_changes(limit=1)
    if current.get("valid") is not True:
        raise CustomRuleError("custom rule change audit chain is invalid")
    previous = str(current.get("head_chain_sha256") or "0" * 64)
    rules_hash = hashlib.sha256(_canonical(registry["rules"]).encode("utf-8")).hexdigest()
    event = {
        "sequence": int(current.get("rows") or 0) + 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "actor": "openclaw-current-user",
        "action": action,
        "rule_id": rule_id,
        "registry_revision": registry["revision"],
        "rules_sha256": rules_hash,
        "previous_chain_sha256": previous,
    }
    event["chain_sha256"] = hashlib.sha256(
        f"{previous}\n{_canonical(event)}".encode("utf-8")
    ).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(_canonical(event) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _rules_payload() -> dict[str, Any]:
    custom = load_custom_rule_registry()
    return {
        "builtin": _builtin_summary(),
        "custom": custom,
        "change_audit": _read_rule_changes(),
    }


def handle(request: dict[str, Any]) -> Any:
    operation = str(request.get("operation") or "").strip().lower()
    if operation == "overview":
        audits = read_recent_install_policy_audits(limit=100)
        counts = {"allow": 0, "warn": 0, "block": 0}
        for row in audits:
            decision = str(row.get("decision") or "").lower()
            if decision in counts:
                counts[decision] += 1
        rules = load_custom_rule_registry()
        return {
            "audit_integrity": verify_install_policy_audit(),
            "decision_counts": counts,
            "recent_total": len(audits),
            "custom_rule_revision": rules["revision"],
            "custom_rules": len(rules["rules"]),
            "enabled_custom_rules": sum(bool(rule["enabled"]) for rule in rules["rules"]),
            "builtin_rules": _builtin_summary()["count"],
        }
    if operation == "list_audits":
        limit = min(max(int(request.get("limit") or 30), 1), 100)
        return {
            "integrity": verify_install_policy_audit(),
            "audits": read_recent_install_policy_audits(limit=limit),
        }
    if operation == "get_audit":
        row = read_install_policy_audit(int(request.get("sequence") or 0))
        if row is None:
            raise CustomRuleError("audit record does not exist")
        return {"integrity": verify_install_policy_audit(), "audit": row}
    if operation == "list_rules":
        return _rules_payload()
    if operation == "upsert_rule":
        registry = upsert_custom_rule(
            request.get("rule"), expected_revision=int(request.get("expected_revision"))
        )
        _record_rule_change("upsert", str(request["rule"].get("id") or "").upper(), registry)
        return _rules_payload()
    if operation == "toggle_rule":
        rule_id = str(request.get("rule_id") or "").upper()
        registry = set_custom_rule_enabled(
            rule_id,
            bool(request.get("enabled")),
            expected_revision=int(request.get("expected_revision")),
        )
        _record_rule_change("enable" if request.get("enabled") else "disable", rule_id, registry)
        return _rules_payload()
    if operation == "delete_rule":
        rule_id = str(request.get("rule_id") or "").upper()
        registry = delete_custom_rule(
            rule_id, expected_revision=int(request.get("expected_revision"))
        )
        _record_rule_change("delete", rule_id, registry)
        return _rules_payload()
    if operation == "rule_changes":
        return _read_rule_changes(min(max(int(request.get("limit") or 30), 1), 100))
    if operation == "admit_mcp":
        payload = request.get("request")
        if not isinstance(payload, dict):
            raise CustomRuleError("MCP admission request must be an object")
        return admit_mcp_server(payload, commit=True)
    raise CustomRuleError("unsupported administrator operation")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="strict", newline="")
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
        if len(raw) > MAX_STDIN_BYTES:
            raise CustomRuleError("administrator request exceeds 128 KiB")
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict):
            raise CustomRuleError("administrator request must be a JSON object")
        response = {"ok": True, "data": handle(request)}
    except Exception as exc:
        response = {
            "ok": False,
            "error": {
                "code": type(exc).__name__,
                "message": str(exc)[:500],
            },
        }
    sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()
    return 0 if response["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
