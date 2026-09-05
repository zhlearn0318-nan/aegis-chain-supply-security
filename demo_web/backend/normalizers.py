from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .models import EvidenceSource, Finding
from .policy import parse_severity


IDENTIFIER = re.compile(r"[A-Za-z0-9_.:@/-]{1,160}")


def _digest(value: Any) -> str:
    if isinstance(value, str):
        encoded = value
    else:
        try:
            encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            encoded = repr(value)
    return hashlib.sha256(encoded.encode("utf-8", errors="replace")).hexdigest()


def _safe_identifier(value: Any, fallback: str) -> str:
    candidate = str(value or "").strip()
    return candidate if IDENTIFIER.fullmatch(candidate) else fallback


def _safe_location(value: Any, fallback: str | None = None, limit: int = 512) -> str | None:
    if value is None:
        return fallback
    candidate = "".join(character for character in str(value) if ord(character) >= 32).strip()
    return candidate[:limit] or fallback


def _vendor_evidence(signal: str, raw: Any) -> str:
    return (
        f"vendor_signal={_safe_identifier(signal, 'vendor_finding')}; "
        f"evidence_sha256={_digest(raw)}; raw_content_retained=false"
    )


def finding_dict(**values: Any) -> dict[str, Any]:
    values["severity"] = parse_severity(values.get("severity"))
    if "evidence_source" not in values:
        rule_id = str(values.get("rule_id") or "")
        analyzer = str(values.get("analyzer") or "").casefold()
        category = str(values.get("category") or "")
        if category in {"vendor_skill_finding", "vendor_mcp_finding"}:
            values["evidence_source"] = EvidenceSource.CISCO
        elif rule_id.startswith("AEGIS_") or analyzer.startswith("aegis"):
            values["evidence_source"] = EvidenceSource.AEGIS_STATIC
        elif category == "supply_chain_vulnerability":
            values["evidence_source"] = EvidenceSource.DEPENDENCY
    finding = Finding.model_validate(values)
    result = finding.model_dump(mode="json")
    result["location"] = finding.location.model_dump(mode="json", exclude_none=True)
    return result


def normalize_skill(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    results = report.get("results") or ([report] if report.get("skill_name") else [])
    if not results:
        raise RuntimeError("Skill Scanner returned no result objects")
    normalized: list[dict[str, Any]] = []
    analyzers: set[str] = set()
    for result_index, result in enumerate(results):
        analyzers.update(
            _safe_identifier(item, "skill-scanner")
            for item in (result.get("analyzers_used") or [])
        )
        skill_reference = f"skill-{result_index + 1}-{_digest(result.get('skill_name'))[:12]}"
        for finding_index, finding in enumerate(result.get("findings") or []):
            rule_id = _safe_identifier(
                finding.get("rule_id") or finding.get("id"),
                "VENDOR_SKILL_FINDING",
            )
            raw_evidence = finding.get("snippet") or finding.get("description") or ""
            finding_identity = {
                "result": result_index,
                "finding": finding_index,
                "rule_id": rule_id,
                "file": finding.get("file_path"),
                "line": finding.get("line_number"),
                "evidence_sha256": _digest(raw_evidence),
            }
            normalized.append(finding_dict(
                id=f"vendor-skill-{_digest(finding_identity)[:20]}",
                title="Skill scanner reported a static security risk",
                category="vendor_skill_finding",
                severity=finding.get("severity"),
                analyzer=_safe_identifier(finding.get("analyzer"), "skill-scanner"),
                location={
                    "file": _safe_location(finding.get("file_path")),
                    "line": finding.get("line_number"),
                    "object": skill_reference,
                },
                evidence=_vendor_evidence(rule_id, raw_evidence),
                description="The vendor scanner reported a static risk; raw scanner text is deliberately not retained.",
                remediation="Review the referenced source location and apply the control associated with the vendor rule before admission.",
                rule_id=rule_id,
                evidence_confidence="POTENTIAL",
                reachability="UNKNOWN",
                behavior_alignment="UNKNOWN",
                evidence_source="CISCO",
            ))
    return normalized, sorted(analyzers)


def normalize_mcp(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    results = report.get("scan_results") or []
    if not results:
        raise RuntimeError("MCP Scanner returned no scan results")
    normalized: list[dict[str, Any]] = []
    analyzers: set[str] = set()
    for item_index, item in enumerate(results):
        if item.get("status") not in {None, "completed"}:
            raise RuntimeError(f"MCP item did not complete: {item.get('status')}")
        raw_item_name = (
            item.get("tool_name") or item.get("prompt_name") or
            item.get("resource_name") or item.get("resource_uri") or "MCP object"
        )
        item_type = _safe_identifier(item.get("item_type"), "mcp_object")
        item_name = f"{item_type}-{item_index + 1}-{_digest(raw_item_name)[:12]}"
        for analyzer, details in (item.get("findings") or {}).items():
            analyzer_id = _safe_identifier(analyzer, "mcp-scanner")
            analyzers.add(analyzer_id)
            if not isinstance(details, dict):
                continue
            total = int(details.get("total_findings") or 0)
            names = details.get("threat_names") or []
            if total == 0 and not names:
                continue
            for index, name in enumerate(names or ["MCP security finding"]):
                raw_evidence = (
                    item.get("tool_description") or item.get("prompt_description") or
                    details.get("threat_summary") or ""
                )
                identity = {
                    "item": item_index,
                    "finding": index,
                    "analyzer": analyzer_id,
                    "name_sha256": _digest(name),
                    "evidence_sha256": _digest(raw_evidence),
                }
                normalized.append(finding_dict(
                    id=f"vendor-mcp-{_digest(identity)[:20]}",
                    title="MCP scanner reported a security risk",
                    category="vendor_mcp_finding",
                    severity=details.get("severity"),
                    analyzer=analyzer_id,
                    location={"object": item_name, "type": item_type},
                    evidence=_vendor_evidence("mcp_vendor_finding", raw_evidence),
                    description="The vendor scanner reported an MCP metadata or capability risk; raw object content is deliberately not retained.",
                    remediation="Review the MCP object description and remove untrusted instructions or excessive capabilities.",
                    rule_id=None,
                ))
    return normalized, sorted(analyzers)


def normalize_dependencies(report: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    if not report:
        raise RuntimeError("Dependency scanner returned an empty report")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(report):
        if item.get("status") not in {None, "completed"}:
            raise RuntimeError("Dependency scan did not complete")
        if item.get("is_safe", False):
            continue
        details = (item.get("findings") or {}).get("vulnerable_package_analyzer") or {}
        normalized.append(finding_dict(
            id=f"dependency-{index}",
            title="Vulnerable dependency",
            category="supply_chain_vulnerability",
            severity=details.get("severity") or "HIGH",
            analyzer="vulnerable_package_analyzer",
            location={"object": item.get("package_name"), "type": "dependency"},
            evidence=_vendor_evidence(
                "dependency_vulnerability",
                item.get("vulnerability_description") or details.get("threat_summary") or "",
            ),
            description="The dependency scanner reported a known package vulnerability; raw scanner text is deliberately not retained.",
            remediation="Upgrade to a fixed package version and regenerate the lock file.",
            rule_id=None,
        ))
    return normalized, ["vulnerable_package_analyzer"]


def normalize_pip_audit(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    dependencies = report.get("dependencies")
    if not isinstance(dependencies, list):
        raise RuntimeError("pip-audit returned an invalid report")
    findings: list[dict[str, Any]] = []
    finding_id_counts: dict[str, int] = {}
    for dependency in dependencies:
        package = f"{dependency.get('name', 'unknown')}=={dependency.get('version', 'unknown')}"
        for vulnerability in dependency.get("vulns") or []:
            fixes = vulnerability.get("fix_versions") or []
            aliases = vulnerability.get("aliases") or []
            vuln_id = vulnerability.get("id") or "UNKNOWN"
            base_finding_id = f"dependency-{package}-{vuln_id}"
            occurrence = finding_id_counts.get(base_finding_id, 0) + 1
            finding_id_counts[base_finding_id] = occurrence
            finding_id = base_finding_id if occurrence == 1 else f"{base_finding_id}-{occurrence}"
            findings.append(finding_dict(
                id=finding_id,
                title=f"{package} - {vuln_id}",
                category="supply_chain_vulnerability",
                severity="HIGH",
                analyzer="mcp:pip-audit",
                location={"object": package, "type": "dependency"},
                evidence=vulnerability.get("description") or f"Aliases: {', '.join(aliases)}",
                description=f"Known vulnerability {vuln_id}; aliases: {', '.join(aliases) or 'none'}",
                remediation=f"Upgrade to: {', '.join(fixes)}" if fixes else "Upgrade to a fixed package version.",
                rule_id=vuln_id,
            ))
    return findings, ["vulnerable_package_analyzer", "pip-audit"]
