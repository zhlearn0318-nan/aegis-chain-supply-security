from __future__ import annotations

import uuid
from typing import Any

from .models import Finding
from .policy import parse_severity


def finding_dict(**values: Any) -> dict[str, Any]:
    values["severity"] = parse_severity(values.get("severity"))
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
    for result in results:
        analyzers.update(result.get("analyzers_used") or [])
        for finding in result.get("findings") or []:
            normalized.append(finding_dict(
                id=finding.get("id") or finding.get("rule_id") or uuid.uuid4().hex,
                title=finding.get("title") or "Skill static finding",
                category=finding.get("category") or "unknown",
                severity=finding.get("severity"),
                analyzer=finding.get("analyzer") or "skill-scanner",
                location={
                    "file": finding.get("file_path"),
                    "line": finding.get("line_number"),
                    "object": result.get("skill_name"),
                },
                evidence=finding.get("snippet") or finding.get("description") or "",
                description=finding.get("description") or "",
                remediation=finding.get("remediation") or "",
                rule_id=finding.get("rule_id"),
            ))
    return normalized, sorted(analyzers)


def normalize_mcp(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    results = report.get("scan_results") or []
    if not results:
        raise RuntimeError("MCP Scanner returned no scan results")
    normalized: list[dict[str, Any]] = []
    analyzers: set[str] = set()
    for item in results:
        if item.get("status") not in {None, "completed"}:
            raise RuntimeError(f"MCP item did not complete: {item.get('status')}")
        item_name = (
            item.get("tool_name") or item.get("prompt_name") or
            item.get("resource_name") or item.get("resource_uri") or "MCP object"
        )
        for analyzer, details in (item.get("findings") or {}).items():
            analyzers.add(analyzer)
            if not isinstance(details, dict):
                continue
            total = int(details.get("total_findings") or 0)
            names = details.get("threat_names") or []
            if total == 0 and not names:
                continue
            for index, name in enumerate(names or ["MCP security finding"]):
                normalized.append(finding_dict(
                    id=f"{analyzer}-{item_name}-{index}",
                    title=str(name).title(),
                    category=str(name).lower().replace(" ", "_"),
                    severity=details.get("severity"),
                    analyzer=analyzer,
                    location={"object": item_name, "type": item.get("item_type")},
                    evidence=(
                        item.get("tool_description") or item.get("prompt_description") or
                        details.get("threat_summary") or ""
                    ),
                    description=details.get("threat_summary") or "",
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
            evidence=item.get("vulnerability_description") or details.get("threat_summary") or "",
            description=details.get("threat_summary") or "Known dependency vulnerability",
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
