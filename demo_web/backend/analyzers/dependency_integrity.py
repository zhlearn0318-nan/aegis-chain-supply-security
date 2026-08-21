from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-dependency-integrity-v1"
MAX_REQUIREMENTS_BYTES = 1 * 1024 * 1024
MAX_LOGICAL_LINES = 2000

EXACT_PIN = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(===|==)\s*([^\s;,]+)", re.IGNORECASE
)
PACKAGE_NAME = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?", re.IGNORECASE)
HASH_VALUE = re.compile(r"--hash\s*=\s*sha256:([0-9a-fA-F]{64})")
VERSION_OPERATOR = re.compile(r"(?:===|==|~=|!=|<=|>=|<|>)")
REMOTE_SOURCE = re.compile(r"(?i)(?:^|\s)(?:git\+|hg\+|svn\+|bzr\+|https?://|file://)")
DIRECT_REFERENCE = re.compile(r"(?i)^\s*[A-Za-z0-9_.-]+(?:\[[^\]]+\])?\s*@\s*")
LOCAL_ARCHIVE = re.compile(r"(?i)(?:^|[\\/])[^\s]+\.(?:whl|zip|tar\.gz|tgz)$")
WINDOWS_PATH = re.compile(r"(?i)^[a-z]:[\\/]")
EXTERNAL_INCLUDE = re.compile(r"(?i)^(?:-r|--requirement|-c|--constraint)(?:\s+|=)?.+")


@dataclass(frozen=True)
class RequirementRecord:
    line: int
    name: str
    version: str | None
    source_class: str
    hashes: tuple[str, ...]


@dataclass(frozen=True)
class IntegrityIssue:
    rule_id: str
    severity: str
    line: int
    object_name: str
    evidence_code: str


def _logical_lines(text: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    start = 1
    buffer = ""
    for line_number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer:
            start = line_number
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        result.append((start, (buffer + stripped).strip()))
        buffer = ""
    if buffer:
        result.append((start, buffer.strip()))
    if len(result) > MAX_LOGICAL_LINES:
        raise ValueError(f"Dependency manifest contains more than {MAX_LOGICAL_LINES} logical lines")
    return result


def _display_name(raw_name: str | None, line: int) -> str:
    return raw_name.lower().replace("_", "-") if raw_name else f"requirement-line-{line}"


def _issue_finding(issue: IntegrityIssue, filename: str) -> dict[str, Any]:
    titles = {
        "AEGIS_DEPENDENCY_VERSION_UNPINNED": "Dependency version is not exactly pinned",
        "AEGIS_DEPENDENCY_HASHES_MISSING": "Dependency artifacts are not hash locked",
        "AEGIS_DEPENDENCY_DIRECT_SOURCE_UNVERIFIED": "Direct dependency source is not cryptographically verified",
        "AEGIS_DEPENDENCY_EXTRA_INDEX": "Additional package index increases dependency-confusion exposure",
        "AEGIS_DEPENDENCY_INSECURE_INDEX": "Dependency index transport or trust verification is weakened",
        "AEGIS_DEPENDENCY_EXTERNAL_INCLUDE": "Referenced dependency manifest is outside this static inspection unit",
        "AEGIS_DEPENDENCY_MANIFEST_ENTRY_UNPARSED": "Dependency manifest entry could not be classified",
    }
    descriptions = {
        "AEGIS_DEPENDENCY_VERSION_UNPINNED": "A resolver may select different code at different times, so the reviewed dependency graph is not reproducible.",
        "AEGIS_DEPENDENCY_HASHES_MISSING": "Exact versions identify releases but do not bind installation to approved distribution bytes.",
        "AEGIS_DEPENDENCY_DIRECT_SOURCE_UNVERIFIED": "A URL, VCS, editable, or local source bypasses the normal locked-index trust path.",
        "AEGIS_DEPENDENCY_EXTRA_INDEX": "Package names may be resolved from an unintended index when index precedence or namespace ownership changes.",
        "AEGIS_DEPENDENCY_INSECURE_INDEX": "Plaintext transport or trusted-host bypass can remove repository authenticity guarantees.",
        "AEGIS_DEPENDENCY_EXTERNAL_INCLUDE": "The referenced requirements or constraints file was not supplied as part of this scan target.",
        "AEGIS_DEPENDENCY_MANIFEST_ENTRY_UNPARSED": "The bounded parser cannot prove the meaning or integrity of this active manifest entry.",
    }
    remediations = {
        "AEGIS_DEPENDENCY_VERSION_UNPINNED": "Use an exact == pin generated from an approved lock workflow.",
        "AEGIS_DEPENDENCY_HASHES_MISSING": "Generate sha256 hashes for every permitted distribution and install with hash checking enabled.",
        "AEGIS_DEPENDENCY_DIRECT_SOURCE_UNVERIFIED": "Use an approved registry artifact, or bind the direct source to an immutable commit and verified artifact hash.",
        "AEGIS_DEPENDENCY_EXTRA_INDEX": "Use a controlled internal mirror with unique namespaces and explicit source policy.",
        "AEGIS_DEPENDENCY_INSECURE_INDEX": "Require HTTPS with certificate verification; remove trusted-host bypasses.",
        "AEGIS_DEPENDENCY_EXTERNAL_INCLUDE": "Upload a flattened lock file or include every referenced manifest in the audited artifact.",
        "AEGIS_DEPENDENCY_MANIFEST_ENTRY_UNPARSED": "Rewrite the entry in a supported PEP 508/requirements form and rescan.",
    }
    identity = f"{issue.rule_id}|{filename}|{issue.line}|{issue.object_name}|{issue.evidence_code}"
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    return finding_dict(
        id=f"{issue.rule_id}_{suffix}",
        title=titles[issue.rule_id],
        category="dependency_integrity",
        severity=issue.severity,
        analyzer=ANALYZER_ID,
        location={"file": filename, "line": issue.line, "object": issue.object_name, "type": "dependency"},
        evidence=f"integrity_signal={issue.evidence_code}; raw_source_retained=false",
        description=descriptions[issue.rule_id],
        remediation=remediations[issue.rule_id],
        rule_id=issue.rule_id,
    )


def _summary_finding(filename: str, counts: dict[str, int], manifest_sha256: str) -> dict[str, Any]:
    order = ["components", "exact_pins", "hashed_components", "direct_sources", "unparsed", "external_includes"]
    encoded = ",".join(f"{key}:{counts[key]}" for key in order)
    identity = hashlib.sha256(f"{manifest_sha256}|{encoded}".encode("utf-8")).hexdigest()[:12]
    return finding_dict(
        id=f"AEGIS_DEPENDENCY_INVENTORY_SUMMARY_{identity}",
        title="Dependency integrity and inventory summary",
        category="dependency_inventory",
        severity="INFO",
        analyzer=ANALYZER_ID,
        location={"file": filename, "type": "dependency"},
        evidence=f"inventory_counts={encoded}; manifest_sha256={manifest_sha256}; resolution_executed=false",
        description="A deterministic inventory records declared install-set components and the integrity evidence available to static inspection.",
        remediation="Resolve all accompanying integrity findings before admission and retain the generated SBOM with the scan record.",
        rule_id="AEGIS_DEPENDENCY_INVENTORY_SUMMARY",
    )


def _make_sbom(records: list[RequirementRecord], manifest_sha256: str, complete: bool) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda item: (item.name, item.version or "", item.line)):
        component: dict[str, Any] = {
            "type": "library",
            "name": record.name,
            "properties": [
                {"name": "aegis:declaration-line", "value": str(record.line)},
                {"name": "aegis:source-class", "value": record.source_class},
                {"name": "aegis:dependency-role", "value": "manifest-entry-role-unknown"},
            ],
        }
        if record.version:
            component["version"] = record.version
            component["purl"] = f"pkg:pypi/{record.name}@{record.version}"
        if record.hashes:
            component["hashes"] = [{"alg": "SHA-256", "content": value.lower()} for value in record.hashes]
        components.append(component)
    serial_digest = hashlib.sha256(
        json.dumps(components, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.UUID(serial_digest[:32])}",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "uploaded-python-dependency-manifest"},
            "properties": [
                {"name": "aegis:manifest-sha256", "value": manifest_sha256},
                {"name": "aegis:inventory-scope", "value": "declared-install-set"},
                {"name": "aegis:transitive-resolution-performed", "value": "false"},
                {"name": "aegis:transitive-graph-completeness", "value": "not-proven"},
                {"name": "aegis:declared-component-integrity-complete", "value": str(complete).lower()},
            ],
        },
        "components": components,
    }


def analyze_dependency_manifest(requirements: Path) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Audit a bounded requirements manifest without resolving, installing, or executing code."""
    if not requirements.is_file():
        raise ValueError("Dependency manifest is unavailable")
    data = requirements.read_bytes()
    if len(data) > MAX_REQUIREMENTS_BYTES:
        raise ValueError("Dependency manifest exceeds the 1 MiB static inspection limit")
    if b"\x00" in data[:8192]:
        raise ValueError("Dependency manifest contains binary data")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Dependency manifest must be valid UTF-8") from exc

    records: list[RequirementRecord] = []
    issues: list[IntegrityIssue] = []
    counts = {"components": 0, "exact_pins": 0, "hashed_components": 0, "direct_sources": 0, "unparsed": 0, "external_includes": 0}
    filename = requirements.name

    for line_number, logical in _logical_lines(text):
        line = logical.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if EXTERNAL_INCLUDE.match(line):
            counts["external_includes"] += 1
            issues.append(IntegrityIssue("AEGIS_DEPENDENCY_EXTERNAL_INCLUDE", "MEDIUM", line_number, "external-manifest", "external_manifest_not_inspected"))
            continue
        if lower.startswith("--extra-index-url"):
            issues.append(IntegrityIssue("AEGIS_DEPENDENCY_EXTRA_INDEX", "HIGH", line_number, "package-index", "additional_index_configured"))
            continue
        if lower.startswith(("--find-links", "-f ")):
            issues.append(IntegrityIssue("AEGIS_DEPENDENCY_DIRECT_SOURCE_UNVERIFIED", "HIGH", line_number, "package-source", "alternative_distribution_source"))
            continue
        if lower.startswith("--trusted-host"):
            issues.append(IntegrityIssue("AEGIS_DEPENDENCY_INSECURE_INDEX", "HIGH", line_number, "package-index", "certificate_verification_bypass"))
            continue
        if lower.startswith("--index-url"):
            if "http://" in lower:
                issues.append(IntegrityIssue("AEGIS_DEPENDENCY_INSECURE_INDEX", "HIGH", line_number, "package-index", "plaintext_index_transport"))
            continue
        if lower.startswith(("--only-binary", "--no-binary", "--pre", "--prefer-binary", "--require-hashes")):
            continue

        candidate = line
        if lower.startswith("-e "):
            candidate = line[3:].strip()
        elif lower.startswith("--editable "):
            candidate = line[len("--editable "):].strip()
        name_match = PACKAGE_NAME.match(candidate)
        name = _display_name(name_match.group(1) if name_match else None, line_number)
        hashes = tuple(sorted(set(HASH_VALUE.findall(line))))
        direct = bool(
            lower.startswith(("-e ", "--editable ", ".", "/", "file:"))
            or DIRECT_REFERENCE.search(line)
            or REMOTE_SOURCE.search(line)
            or WINDOWS_PATH.search(line)
            or LOCAL_ARCHIVE.search(line)
        )
        if direct:
            counts["components"] += 1
            counts["direct_sources"] += 1
            if hashes:
                counts["hashed_components"] += 1
            else:
                issues.append(IntegrityIssue("AEGIS_DEPENDENCY_DIRECT_SOURCE_UNVERIFIED", "HIGH", line_number, name, "direct_source_without_sha256"))
            records.append(RequirementRecord(line_number, name, None, "direct", hashes))
            continue

        pin = EXACT_PIN.match(line)
        if pin:
            name = _display_name(pin.group(1), line_number)
            version = pin.group(3)
            counts["components"] += 1
            counts["exact_pins"] += 1
            if hashes:
                counts["hashed_components"] += 1
            else:
                issues.append(IntegrityIssue("AEGIS_DEPENDENCY_HASHES_MISSING", "MEDIUM", line_number, name, "exact_pin_without_sha256"))
            records.append(RequirementRecord(line_number, name, version, "registry", hashes))
            continue

        if name_match:
            counts["components"] += 1
            issues.append(IntegrityIssue("AEGIS_DEPENDENCY_VERSION_UNPINNED", "MEDIUM", line_number, name, "version_not_exactly_pinned" if VERSION_OPERATOR.search(line) else "version_absent"))
            if not hashes:
                issues.append(IntegrityIssue("AEGIS_DEPENDENCY_HASHES_MISSING", "MEDIUM", line_number, name, "unlocked_artifact"))
            records.append(RequirementRecord(line_number, name, None, "registry", hashes))
            continue

        counts["unparsed"] += 1
        issues.append(IntegrityIssue("AEGIS_DEPENDENCY_MANIFEST_ENTRY_UNPARSED", "MEDIUM", line_number, name, "active_entry_unparsed"))

    manifest_sha256 = hashlib.sha256(data).hexdigest()
    findings = [_issue_finding(issue, filename) for issue in issues]
    findings.sort(key=lambda item: (item["location"].get("line") or 0, item["rule_id"] or ""))
    findings.append(_summary_finding(filename, counts, manifest_sha256))
    complete = not issues and bool(records) and counts["hashed_components"] == counts["components"]
    return findings, [ANALYZER_ID], _make_sbom(records, manifest_sha256, complete)
