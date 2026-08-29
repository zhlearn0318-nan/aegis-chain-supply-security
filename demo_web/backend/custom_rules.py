from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .normalizers import finding_dict


ANALYZER_ID = "aegis-custom-rules-v1"
RULES_ENV = "AEGIS_CUSTOM_RULES_PATH"
SCHEMA_VERSION = "1.0"
MAX_RULES = 200
MAX_RULE_SOURCE = 32_000
MAX_PATTERN = 500
MAX_FILES = 1_000
MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_RULES_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "openclaw-final"
    / "custom_rules.json"
)
RULE_ID = re.compile(r"CUSTOM_[A-Z0-9_]{3,80}\Z")
SAFE_EXTENSIONS = {
    ".cfg", ".conf", ".ini", ".json", ".json5", ".jsx", ".md", ".mjs",
    ".ps1", ".py", ".sh", ".toml", ".ts", ".tsx", ".txt", ".yaml", ".yml",
}
VALID_SCOPES = {"skill", "plugin", "mcp"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_ACTIONS = {"BLOCK", "REVIEW", "INFO"}


class CustomRuleError(ValueError):
    pass


def resolve_custom_rules_path() -> Path:
    configured = os.getenv(RULES_ENV, "").strip()
    return Path(configured).resolve(strict=False) if configured else DEFAULT_RULES_PATH


def empty_registry() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": 0,
        "updated_at": None,
        "rules": [],
    }


def _bounded_text(value: Any, limit: int) -> str:
    text = "".join(ch for ch in str(value or "") if ord(ch) >= 32).strip()
    return text[:limit]


def _validate_action_severity(action: str, severity: str) -> None:
    allowed = {
        "BLOCK": {"CRITICAL", "HIGH"},
        "REVIEW": {"MEDIUM", "LOW"},
        "INFO": {"INFO"},
    }
    if severity not in allowed[action]:
        raise CustomRuleError(f"{action} action is incompatible with {severity} severity")


def _compile_yara(source: str) -> None:
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError as exc:
        raise CustomRuleError("yara-python is unavailable in the Aegis runtime") from exc
    try:
        yara.compile(source=source)
    except Exception as exc:
        raise CustomRuleError(f"YARA compilation failed: {type(exc).__name__}: {exc}") from exc


def validate_rule(value: Any, *, compile_yara: bool = True) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CustomRuleError("rule must be a JSON object")
    rule_id = _bounded_text(value.get("id"), 96).upper()
    if not RULE_ID.fullmatch(rule_id):
        raise CustomRuleError("rule id must match CUSTOM_[A-Z0-9_]{3,80}")
    kind = _bounded_text(value.get("kind"), 20).lower()
    if kind not in {"structured", "yara"}:
        raise CustomRuleError("kind must be structured or yara")
    name = _bounded_text(value.get("name"), 120)
    description = _bounded_text(value.get("description"), 500)
    if not name or not description:
        raise CustomRuleError("name and description are required")
    scopes = sorted({_bounded_text(item, 20).lower() for item in value.get("scopes", [])})
    if not scopes or not set(scopes).issubset(VALID_SCOPES):
        raise CustomRuleError("scopes must contain skill, plugin, or mcp")
    severity = _bounded_text(value.get("severity"), 20).upper()
    action = _bounded_text(value.get("action"), 20).upper()
    if severity not in VALID_SEVERITIES or action not in VALID_ACTIONS:
        raise CustomRuleError("severity or action is invalid")
    _validate_action_severity(action, severity)
    normalized: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "description": description,
        "kind": kind,
        "scopes": scopes,
        "severity": severity,
        "action": action,
        "enabled": bool(value.get("enabled", True)),
    }
    if kind == "structured":
        match = value.get("match")
        if not isinstance(match, dict):
            raise CustomRuleError("structured rules require a match object")
        mode = _bounded_text(match.get("mode"), 20).lower()
        if mode not in {"contains", "filename"}:
            raise CustomRuleError("structured match mode must be contains or filename")
        pattern = _bounded_text(match.get("value"), MAX_PATTERN)
        if len(pattern) < 2:
            raise CustomRuleError("structured match value must contain at least 2 characters")
        extensions = sorted({
            extension.lower() if str(extension).startswith(".") else f".{str(extension).lower()}"
            for extension in match.get("extensions", [])
            if _bounded_text(extension, 20)
        })
        if extensions and not set(extensions).issubset(SAFE_EXTENSIONS):
            raise CustomRuleError("structured rule contains an unsupported file extension")
        normalized["match"] = {
            "mode": mode,
            "value": pattern,
            "case_sensitive": bool(match.get("case_sensitive", False)),
            "extensions": extensions,
        }
    else:
        source = str(value.get("source") or "").strip()
        if not source or len(source.encode("utf-8")) > MAX_RULE_SOURCE:
            raise CustomRuleError("YARA source is empty or exceeds 32000 UTF-8 bytes")
        if compile_yara:
            _compile_yara(source)
        normalized["source"] = source
    return normalized


def load_custom_rule_registry(path: Path | None = None) -> dict[str, Any]:
    path = path or resolve_custom_rules_path()
    if not path.is_file():
        return empty_registry()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CustomRuleError(f"custom rule registry is unreadable: {type(exc).__name__}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise CustomRuleError("custom rule registry schema is invalid")
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_RULES:
        raise CustomRuleError("custom rule registry rule count is invalid")
    rules = [validate_rule(rule, compile_yara=True) for rule in raw_rules]
    identifiers = [rule["id"] for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        raise CustomRuleError("custom rule ids must be unique")
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": max(0, int(payload.get("revision") or 0)),
        "updated_at": payload.get("updated_at"),
        "rules": rules,
    }


def save_custom_rule_registry(
    rules: Iterable[dict[str, Any]],
    *,
    path: Path | None = None,
    expected_revision: int | None = None,
) -> dict[str, Any]:
    path = path or resolve_custom_rules_path()
    current = load_custom_rule_registry(path)
    if expected_revision is not None and current["revision"] != expected_revision:
        raise CustomRuleError("custom rule registry revision conflict; reload before saving")
    normalized = [validate_rule(rule, compile_yara=True) for rule in rules]
    if len(normalized) > MAX_RULES:
        raise CustomRuleError(f"custom rule count exceeds {MAX_RULES}")
    identifiers = [rule["id"] for rule in normalized]
    if len(identifiers) != len(set(identifiers)):
        raise CustomRuleError("custom rule ids must be unique")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "revision": current["revision"] + 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "rules": sorted(normalized, key=lambda rule: rule["id"]),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return payload


def upsert_custom_rule(
    rule: dict[str, Any], *, path: Path | None = None, expected_revision: int | None = None
) -> dict[str, Any]:
    path = path or resolve_custom_rules_path()
    registry = load_custom_rule_registry(path)
    normalized = validate_rule(rule, compile_yara=True)
    rules = [item for item in registry["rules"] if item["id"] != normalized["id"]]
    rules.append(normalized)
    return save_custom_rule_registry(
        rules, path=path, expected_revision=expected_revision if expected_revision is not None else registry["revision"]
    )


def delete_custom_rule(
    rule_id: str, *, path: Path | None = None, expected_revision: int | None = None
) -> dict[str, Any]:
    path = path or resolve_custom_rules_path()
    registry = load_custom_rule_registry(path)
    normalized_id = _bounded_text(rule_id, 96).upper()
    rules = [item for item in registry["rules"] if item["id"] != normalized_id]
    if len(rules) == len(registry["rules"]):
        raise CustomRuleError("custom rule does not exist")
    return save_custom_rule_registry(
        rules, path=path, expected_revision=expected_revision if expected_revision is not None else registry["revision"]
    )


def set_custom_rule_enabled(
    rule_id: str,
    enabled: bool,
    *,
    path: Path | None = None,
    expected_revision: int | None = None,
) -> dict[str, Any]:
    path = path or resolve_custom_rules_path()
    registry = load_custom_rule_registry(path)
    normalized_id = _bounded_text(rule_id, 96).upper()
    found = False
    rules = []
    for item in registry["rules"]:
        if item["id"] == normalized_id:
            item = {**item, "enabled": bool(enabled)}
            found = True
        rules.append(item)
    if not found:
        raise CustomRuleError("custom rule does not exist")
    return save_custom_rule_registry(
        rules, path=path, expected_revision=expected_revision if expected_revision is not None else registry["revision"]
    )


def _candidate_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if not root.is_symlink() and root.stat().st_size <= MAX_FILE_BYTES else []
    files: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().lower()):
        if len(files) >= MAX_FILES:
            break
        try:
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_FILE_BYTES:
                files.append(path)
        except OSError:
            continue
    return files


def _finding(rule: dict[str, Any], root: Path, path: Path, evidence_code: str) -> dict[str, Any]:
    relative = path.name if root.is_file() else path.relative_to(root).as_posix()
    digest = hashlib.sha256(f"{rule['id']}|{relative}|{evidence_code}".encode("utf-8")).hexdigest()
    return finding_dict(
        id=f"custom-{digest[:20]}",
        title=rule["name"],
        category="CUSTOM_POLICY",
        severity=rule["severity"],
        analyzer=ANALYZER_ID,
        location={"file": relative},
        evidence=f"match={evidence_code}; content_retained=false",
        description=rule["description"],
        remediation="Review the administrator-defined rule and remove or explicitly approve the matched behavior before admission.",
        rule_id=rule["id"],
    )


def analyze_custom_rules(
    root: Path, scope: str, *, registry_path: Path | None = None
) -> tuple[list[dict[str, Any]], list[str]]:
    normalized_scope = scope.strip().lower()
    if normalized_scope not in VALID_SCOPES:
        raise CustomRuleError("custom rule scan scope is invalid")
    registry = load_custom_rule_registry(registry_path)
    rules = [rule for rule in registry["rules"] if rule["enabled"] and normalized_scope in rule["scopes"]]
    if not rules:
        return [], [ANALYZER_ID]
    files = _candidate_files(root)
    findings: list[dict[str, Any]] = []
    structured = [rule for rule in rules if rule["kind"] == "structured"]
    yara_rules = [rule for rule in rules if rule["kind"] == "yara"]
    for path in files:
        suffix = path.suffix.lower()
        for rule in structured:
            match = rule["match"]
            extensions = set(match["extensions"])
            if extensions and suffix not in extensions:
                continue
            if match["mode"] == "filename":
                candidate = path.name if match["case_sensitive"] else path.name.casefold()
                needle = match["value"] if match["case_sensitive"] else match["value"].casefold()
                if needle in candidate:
                    findings.append(_finding(rule, root, path, "structured_filename"))
                continue
            if suffix not in SAFE_EXTENSIONS:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            candidate = text if match["case_sensitive"] else text.casefold()
            needle = match["value"] if match["case_sensitive"] else match["value"].casefold()
            if needle in candidate:
                findings.append(_finding(rule, root, path, "structured_contains"))
    if yara_rules:
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError as exc:
            raise CustomRuleError("yara-python is unavailable in the Aegis runtime") from exc
        # Compile all administrator rules into namespaces and invoke libyara
        # once per bounded file. This avoids an accidental rules × files
        # timeout multiplier while preserving each custom rule's identity.
        matcher = yara.compile(sources={rule["id"]: rule["source"] for rule in yara_rules})
        rules_by_namespace = {rule["id"]: rule for rule in yara_rules}
        for path in files:
            try:
                content = path.read_bytes()
            except OSError:
                continue
            try:
                # Match bounded bytes instead of passing the path to libyara.
                # The latter cannot reliably open non-ASCII Windows paths.
                matches = matcher.match(data=content, timeout=3)
            except Exception as exc:
                raise CustomRuleError(f"YARA execution failed: {type(exc).__name__}") from exc
            for namespace in sorted({match.namespace for match in matches}):
                rule = rules_by_namespace.get(namespace)
                if rule is not None:
                    findings.append(_finding(rule, root, path, "yara_match"))
    unique = {finding["id"]: finding for finding in findings}
    return sorted(unique.values(), key=lambda item: (item["rule_id"], item["location"].get("file", ""))), [ANALYZER_ID]
