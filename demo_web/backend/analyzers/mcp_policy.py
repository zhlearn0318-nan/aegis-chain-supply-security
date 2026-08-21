from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-mcp-policy-v1"
MAX_OBJECT_FILE_BYTES = 1 * 1024 * 1024
MAX_OBJECTS_PER_KIND = 500

COMMAND_PARAMETERS = {"command", "cmd", "shell", "script", "code", "program", "executable", "argv", "args"}
PATH_PARAMETERS = {"path", "file", "filepath", "file_path", "directory", "dir", "folder", "target_path"}
URL_PARAMETERS = {"url", "uri", "endpoint", "target_url", "webhook", "callback_url"}
SCOPE_KEYS = {"scope", "scopes", "permission", "permissions", "allowed_tools", "allowedtools", "verbs", "actions", "resources"}

COMMAND_ACTION = re.compile(r"(?i)\b(?:execute|exec|run|launch|invoke)\b.{0,60}\b(?:arbitrary|system|shell|command|code|program|script)\b|\b(?:shell|command|code)\b.{0,60}\b(?:execute|exec|run|launch|invoke)\b")
FILESYSTEM_MUTATION = re.compile(r"(?i)\b(?:write|overwrite|delete|remove|rename|move|modify|edit|create)\b.{0,60}\b(?:file|directory|folder|path)\b|\b(?:file|directory|folder|path)\b.{0,60}\b(?:write|overwrite|delete|remove|rename|move|modify|edit|create)\b")
FILESYSTEM_READ = re.compile(r"(?i)\b(?:read|list|search|open|access)\b.{0,60}\b(?:file|directory|folder|path)\b|\b(?:file|directory|folder|path)\b.{0,60}\b(?:read|list|search|open|access)\b")
NETWORK_FETCH = re.compile(r"(?i)\b(?:fetch|request|download|retrieve|open|call|send)\b.{0,60}\b(?:url|uri|endpoint|web|http|network)\b|\b(?:url|uri|endpoint|web|http|network)\b.{0,60}\b(?:fetch|request|download|retrieve|open|call|send)\b")
SCOPE_GUARD = re.compile(r"(?i)\b(?:allowlist|allow-list|approved (?:root|domain|host|directory)|within (?:the )?(?:approved )?(?:workspace|sandbox|root)|restricted to|scoped to|deny private|block private)\b")
MACHINE_BOUNDARY_KEY = "x-aegis-boundary"
BOUNDARY_ENFORCERS = {"mcp_server", "platform_gateway"}
OVERRIDE = re.compile(r"(?i)(?:ignore|disregard|bypass|override).{0,80}(?:previous|prior|system|developer|security|safety|instruction|check)|system\s+override")
SENSITIVE_INTENT = re.compile(r"(?i)\b(?:credential|secret|token|password|api[_ -]?key|private[_ -]?key|ssh|environment variable|aws_access_key)\b")
OUTBOUND_INTENT = re.compile(r"(?i)\b(?:upload|exfiltrat|send|post|transmit|external server|webhook|base64)\b")
SENSITIVE_RESOURCE = re.compile(r"(?i)(?:/(?:etc/(?:shadow|passwd|sudoers)|root/\.ssh|home/[^/]+/\.ssh|\.aws/(?:credentials|config)|proc/self/environ)|[\\/](?:system32[\\/]config[\\/]sam|users[\\/][^\\/]+[\\/]\.ssh)|(?:^|[\\/])\.env(?:$|[\\/]))")


@dataclass(frozen=True)
class McpIssue:
    rule_id: str
    severity: str
    object_type: str
    object_name: str
    evidence_code: str


def _read_objects(path: Path, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if not path.is_file():
        raise ValueError(f"MCP object file is unavailable: {path.name}")
    data = path.read_bytes()
    if len(data) > MAX_OBJECT_FILE_BYTES:
        raise ValueError(f"MCP object file exceeds the 1 MiB static inspection limit: {path.name}")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"MCP object file is not valid UTF-8 JSON: {path.name}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"MCP object file root must be an object: {path.name}")
    raw: Any = []
    for key in keys:
        if key in payload:
            raw = payload[key]
            break
    if not isinstance(raw, list):
        raise ValueError(f"MCP object collection must be an array: {path.name}")
    if len(raw) > MAX_OBJECTS_PER_KIND:
        raise ValueError(f"MCP object collection exceeds {MAX_OBJECTS_PER_KIND} objects: {path.name}")
    if not all(isinstance(item, dict) for item in raw):
        raise ValueError(f"MCP object collection contains a non-object item: {path.name}")
    return raw


def _schema_fields(schema: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            fields.update(str(key).lower() for key in properties)
        for key, value in schema.items():
            if key in {"properties", "$defs", "definitions", "items", "allOf", "anyOf", "oneOf"}:
                fields.update(_schema_fields(value))
    elif isinstance(schema, list):
        for item in schema:
            fields.update(_schema_fields(item))
    return fields


def _bounded_scope_values(value: Any, *, hostname: bool = False) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not value or len(value) > 32:
        return None
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return None
        candidate = item.strip()
        if not candidate or len(candidate) > 253 or "*" in candidate or ".." in candidate:
            return None
        if any(ord(character) < 32 for character in candidate):
            return None
        if hostname and not re.fullmatch(r"[A-Za-z0-9.-]+", candidate):
            return None
        normalized.append(candidate.lower() if hostname else candidate)
    return tuple(normalized)


def _has_machine_boundary(boundary: Any, capability: str) -> bool:
    """Validate a caller-owned sidecar contract, never an uploaded self-claim."""
    if not isinstance(boundary, dict) or boundary.get("enforced_by") not in BOUNDARY_ENFORCERS:
        return False
    section = boundary.get(capability)
    if not isinstance(section, dict) or section.get("deny_unlisted") is not True:
        return False
    if capability == "filesystem":
        roots = _bounded_scope_values(section.get("roots"))
        return bool(roots) and all(root.startswith("workspace://") for root in roots)
    if capability == "network":
        hosts = _bounded_scope_values(section.get("allowed_hosts"), hostname=True)
        schemes = _bounded_scope_values(section.get("allowed_schemes"))
        return bool(hosts) and bool(schemes) and set(scheme.lower() for scheme in schemes) == {"https"}
    return False


def _has_wildcard_scope(value: Any, parent_key: str = "") -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in SCOPE_KEYS and (
                child == "*" or (isinstance(child, list) and "*" in child)
            ):
                return True
            if _has_wildcard_scope(child, normalized):
                return True
    elif isinstance(value, list):
        return any(_has_wildcard_scope(item, parent_key) for item in value)
    elif value == "*" and parent_key in SCOPE_KEYS:
        return True
    return False


def _is_nonlocal_plaintext_http(uri: str) -> bool:
    parsed = urlparse(uri)
    if parsed.scheme.lower() != "http":
        return False
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "localhost.localdomain"}:
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True


def _object_text(item: dict[str, Any]) -> str:
    parts = [str(item.get(key) or "") for key in ("name", "title", "description", "text", "content")]
    return "\n".join(parts)[:200_000]


def _object_name(item: dict[str, Any], object_type: str, index: int) -> str:
    value = item.get("name") or item.get("title")
    if isinstance(value, str) and value.strip():
        return value.strip()[:120]
    return f"{object_type}-{index + 1}"


def _issue_finding(issue: McpIssue) -> dict[str, Any]:
    titles = {
        "AEGIS_MCP_ARBITRARY_COMMAND_TOOL": "MCP tool exposes arbitrary command execution",
        "AEGIS_MCP_UNSCOPED_FILESYSTEM_ACCESS": "MCP filesystem capability lacks an explicit root boundary",
        "AEGIS_MCP_UNRESTRICTED_URL_FETCH": "MCP network-fetch capability lacks a destination policy",
        "AEGIS_MCP_WILDCARD_SCOPE": "MCP object declares wildcard privileges",
        "AEGIS_MCP_PROMPT_INSTRUCTION_OVERRIDE": "MCP content attempts to override trusted instructions",
        "AEGIS_MCP_SENSITIVE_RESOURCE_URI": "MCP resource references a sensitive local path",
        "AEGIS_MCP_PLAINTEXT_RESOURCE_URI": "MCP resource uses non-local plaintext HTTP",
    }
    descriptions = {
        "AEGIS_MCP_ARBITRARY_COMMAND_TOOL": "The declared input schema and capability description jointly expose a general command/code execution primitive.",
        "AEGIS_MCP_UNSCOPED_FILESYSTEM_ACCESS": "A path-controlled file capability lacks a bounded workspace contract supplied by a trusted platform sidecar. Uploaded fields and natural-language claims do not prove an enforceable root boundary.",
        "AEGIS_MCP_UNRESTRICTED_URL_FETCH": "A caller-controlled URL lacks a bounded destination contract supplied by a trusted platform sidecar. Uploaded fields and natural-language claims do not prove SSRF or egress enforcement.",
        "AEGIS_MCP_WILDCARD_SCOPE": "A wildcard privilege prevents least-privilege review and may include future capabilities automatically.",
        "AEGIS_MCP_PROMPT_INSTRUCTION_OVERRIDE": "Untrusted MCP metadata or resource content contains instruction-precedence manipulation; sensitive/outbound intent raises severity.",
        "AEGIS_MCP_SENSITIVE_RESOURCE_URI": "The advertised resource points to credentials or security-sensitive operating-system state.",
        "AEGIS_MCP_PLAINTEXT_RESOURCE_URI": "A remote resource URI lacks transport confidentiality and server authentication.",
    }
    remediation = {
        "AEGIS_MCP_ARBITRARY_COMMAND_TOOL": "Replace general execution with enumerated operations, fixed argument schemas, and server-side authorization.",
        "AEGIS_MCP_UNSCOPED_FILESYSTEM_ACCESS": "Enforce a canonical approved root, reject traversal/symlinks, and separate read from mutation permissions.",
        "AEGIS_MCP_UNRESTRICTED_URL_FETCH": "Allowlist schemes and destinations; deny loopback, private, link-local, metadata, redirect, and DNS-rebinding paths.",
        "AEGIS_MCP_WILDCARD_SCOPE": "Replace wildcard access with an explicit minimal capability list and review each resource/action.",
        "AEGIS_MCP_PROMPT_INSTRUCTION_OVERRIDE": "Treat MCP descriptions/content as untrusted data and remove instruction overrides or secret-transfer requests.",
        "AEGIS_MCP_SENSITIVE_RESOURCE_URI": "Remove the resource or expose only an approved redacted artifact through a scoped server-side identifier.",
        "AEGIS_MCP_PLAINTEXT_RESOURCE_URI": "Use HTTPS with certificate verification or a documented loopback-only transport.",
    }
    identity = "|".join([issue.rule_id, issue.object_type, issue.object_name, issue.evidence_code])
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    return finding_dict(
        id=f"{issue.rule_id}_{suffix}",
        title=titles[issue.rule_id],
        category="mcp_capability_policy",
        severity=issue.severity,
        analyzer=ANALYZER_ID,
        location={"object": issue.object_name, "type": issue.object_type},
        evidence=f"mcp_signal={issue.evidence_code}; raw_content_retained=false",
        description=descriptions[issue.rule_id],
        remediation=remediation[issue.rule_id],
        rule_id=issue.rule_id,
    )


def _summary_finding(counts: dict[str, int]) -> dict[str, Any]:
    encoded = ",".join(f"{key}:{counts[key]}" for key in ("tools", "prompts", "resources", "policy_findings"))
    suffix = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:12]
    return finding_dict(
        id=f"AEGIS_MCP_CAPABILITY_SUMMARY_{suffix}",
        title="MCP capability and object coverage summary",
        category="mcp_capability_inventory",
        severity="INFO",
        analyzer=ANALYZER_ID,
        location={"type": "mcp_collection"},
        evidence=f"object_counts={encoded}; dynamic_server_invocation=false",
        description="All supplied Tool, Prompt, and Resource declarations were inventoried by bounded static policy analysis.",
        remediation="Review accompanying policy findings and verify runtime enforcement separately before production admission.",
        rule_id="AEGIS_MCP_CAPABILITY_SUMMARY",
    )


def _content_override_issue(item: dict[str, Any], object_type: str, name: str) -> McpIssue | None:
    text = _object_text(item)
    if not OVERRIDE.search(text):
        return None
    critical = bool(SENSITIVE_INTENT.search(text) and OUTBOUND_INTENT.search(text))
    return McpIssue(
        "AEGIS_MCP_PROMPT_INSTRUCTION_OVERRIDE",
        "CRITICAL" if critical else "HIGH",
        object_type,
        name,
        "instruction_override_with_sensitive_egress" if critical else "instruction_precedence_override",
    )


def analyze_mcp_objects(
    tools_path: Path,
    prompts_path: Path,
    resources_path: Path,
    *,
    trusted_boundaries: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Statically review MCP declarations without connecting to or invoking an MCP server."""
    tools = _read_objects(tools_path, ("tools",))
    prompts = _read_objects(prompts_path, ("prompts",))
    resources = _read_objects(resources_path, ("resources", "contents"))
    issues: list[McpIssue] = []

    for index, item in enumerate(tools):
        name = _object_name(item, "tool", index)
        text = _object_text(item)
        schema = item.get("inputSchema", item.get("input_schema", {}))
        fields = _schema_fields(schema)
        if fields & COMMAND_PARAMETERS and COMMAND_ACTION.search(text):
            issues.append(McpIssue("AEGIS_MCP_ARBITRARY_COMMAND_TOOL", "CRITICAL", "tool", name, "command_parameter_and_general_execution"))
        embedded_boundary = item.get(MACHINE_BOUNDARY_KEY)
        claimed_guard = bool(SCOPE_GUARD.search(text)) or isinstance(embedded_boundary, dict)
        trusted_boundary = (trusted_boundaries or {}).get(name)
        filesystem_guard = _has_machine_boundary(trusted_boundary, "filesystem")
        network_guard = _has_machine_boundary(trusted_boundary, "network")
        filesystem_claim_evidence = (
            "uploaded_machine_boundary_without_trusted_sidecar"
            if isinstance(embedded_boundary, dict)
            else "text_scope_claim_without_machine_root"
        )
        network_claim_evidence = (
            "uploaded_machine_boundary_without_trusted_sidecar"
            if isinstance(embedded_boundary, dict)
            else "text_allowlist_claim_without_machine_policy"
        )
        if fields & PATH_PARAMETERS and not filesystem_guard:
            if FILESYSTEM_MUTATION.search(text):
                issues.append(McpIssue(
                    "AEGIS_MCP_UNSCOPED_FILESYSTEM_ACCESS",
                    "MEDIUM" if claimed_guard else "HIGH",
                    "tool",
                    name,
                    filesystem_claim_evidence if claimed_guard else "caller_path_with_mutation_no_root",
                ))
            elif FILESYSTEM_READ.search(text):
                issues.append(McpIssue(
                    "AEGIS_MCP_UNSCOPED_FILESYSTEM_ACCESS",
                    "MEDIUM",
                    "tool",
                    name,
                    filesystem_claim_evidence if claimed_guard else "caller_path_with_read_no_root",
                ))
        if fields & URL_PARAMETERS and NETWORK_FETCH.search(text) and not network_guard:
            issues.append(McpIssue(
                "AEGIS_MCP_UNRESTRICTED_URL_FETCH",
                "MEDIUM" if claimed_guard else "HIGH",
                "tool",
                name,
                network_claim_evidence if claimed_guard else "caller_url_without_destination_policy",
            ))
        if _has_wildcard_scope(item):
            issues.append(McpIssue("AEGIS_MCP_WILDCARD_SCOPE", "HIGH", "tool", name, "wildcard_capability_scope"))
        override = _content_override_issue(item, "tool", name)
        if override:
            issues.append(override)

    for index, item in enumerate(prompts):
        name = _object_name(item, "prompt", index)
        if _has_wildcard_scope(item):
            issues.append(McpIssue("AEGIS_MCP_WILDCARD_SCOPE", "HIGH", "prompt", name, "wildcard_capability_scope"))
        override = _content_override_issue(item, "prompt", name)
        if override:
            issues.append(override)

    for index, item in enumerate(resources):
        name = _object_name(item, "resource", index)
        uri = str(item.get("uri") or "")
        if uri and SENSITIVE_RESOURCE.search(urlparse(uri).path or uri):
            issues.append(McpIssue("AEGIS_MCP_SENSITIVE_RESOURCE_URI", "HIGH", "resource", name, "sensitive_local_resource_path"))
        if uri and _is_nonlocal_plaintext_http(uri):
            issues.append(McpIssue("AEGIS_MCP_PLAINTEXT_RESOURCE_URI", "MEDIUM", "resource", name, "remote_plaintext_http"))
        if _has_wildcard_scope(item):
            issues.append(McpIssue("AEGIS_MCP_WILDCARD_SCOPE", "HIGH", "resource", name, "wildcard_capability_scope"))
        override = _content_override_issue(item, "resource", name)
        if override:
            issues.append(override)

    normalized = [_issue_finding(issue) for issue in issues]
    by_id = {finding["id"]: finding for finding in normalized}
    findings = sorted(by_id.values(), key=lambda item: (item["location"].get("type") or "", item["location"].get("object") or "", item["rule_id"] or ""))
    findings.append(_summary_finding({"tools": len(tools), "prompts": len(prompts), "resources": len(resources), "policy_findings": len(findings)}))
    return findings, [ANALYZER_ID]
