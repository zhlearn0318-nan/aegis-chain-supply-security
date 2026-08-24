from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import uuid
from typing import Any, Iterable
from urllib.parse import quote


EXACT_VERSION = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")
LOCK_ENTRY = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")
LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-fA-F]{64})")
PNPM_PACKAGE = re.compile(r"^  (\S.+):$")
PNPM_INTEGRITY = re.compile(r"^    resolution: \{integrity: (sha(?:256|384|512)-[^}]+)\}$")
SECRET_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
)
GENERIC_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)"
    r"\s*[:=]\s*[\"']([^\"'\r\n]{16,})[\"']"
)
LICENSE_CLASSIFIERS = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}
LICENSE_ALIASES = {
    "Apache": "Apache-2.0",
    "Apache 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "BSD": "BSD-3-Clause",
    "Expat license": "MIT",
    "ISC License": "ISC",
    "PSF": "PSF-2.0",
    "PSFL": "PSF-2.0",
}
PACKAGE_LICENSE_OVERRIDES = {
    "cisco-ai-mcp-scanner": "Apache-2.0",
    "tiktoken": "MIT",
}


@dataclass(frozen=True)
class Component:
    ecosystem: str
    name: str
    version: str
    license_id: str
    integrity: str = ""

    @property
    def purl(self) -> str:
        package_type = "pypi" if self.ecosystem == "python" else "npm"
        return f"pkg:{package_type}/{quote(self.name, safe='@/')}@{quote(self.version, safe='.-+')}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_python_lock(path: Path) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        match = LOCK_ENTRY.match(line)
        if match:
            current = {"name": match.group(1), "version": match.group(2), "hashes": []}
            packages.append(current)
        if current:
            current["hashes"].extend(item.lower() for item in LOCK_HASH.findall(line))
    return packages


def _strip_yaml_key(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _split_pnpm_key(key: str) -> tuple[str, str]:
    name, separator, version = key.rpartition("@")
    if not separator or not name or not version:
        raise ValueError(f"Unsupported pnpm package key: {key}")
    return name, version


def parse_pnpm_lock(path: Path) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    in_packages = False
    current: dict[str, str] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "packages:":
            in_packages = True
            continue
        if in_packages and line == "snapshots:":
            break
        if not in_packages:
            continue
        key_match = PNPM_PACKAGE.match(line)
        if key_match:
            raw_key = _strip_yaml_key(key_match.group(1))
            name, version = _split_pnpm_key(raw_key)
            current = {"name": name, "version": version, "integrity": ""}
            packages.append(current)
            continue
        integrity_match = PNPM_INTEGRITY.match(line)
        if current and integrity_match:
            current["integrity"] = integrity_match.group(1)
    return packages


def python_license(name: str) -> str:
    if name.lower() in PACKAGE_LICENSE_OVERRIDES:
        return PACKAGE_LICENSE_OVERRIDES[name.lower()]
    metadata = importlib.metadata.metadata(name)
    expression = (metadata.get("License-Expression") or "").strip()
    if expression:
        return LICENSE_ALIASES.get(expression, expression)
    raw = (metadata.get("License") or "").strip()
    if raw.startswith("MIT License"):
        return "MIT"
    if raw and len(raw) <= 80 and "\n" not in raw:
        return LICENSE_ALIASES.get(raw, raw)
    for classifier in metadata.get_all("Classifier", []):
        if classifier in LICENSE_CLASSIFIERS:
            return LICENSE_CLASSIFIERS[classifier]
    return "UNKNOWN"


def load_node_licenses(path: Path) -> dict[tuple[str, str], str]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    result: dict[tuple[str, str], str] = {}
    for license_id, entries in payload.items():
        for entry in entries:
            for version in entry.get("versions", []):
                result[(entry["name"], version)] = entry.get("license") or license_id
    return result


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in map(value.count, set(value)))


def _git_files(project_root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=project_root,
        capture_output=True,
        check=True,
    )
    return [project_root / item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def scan_repository_secrets(project_root: Path, synthetic_markers: Iterable[str]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    ignored_synthetic = 0
    scanned = 0
    markers = tuple(item.lower() for item in synthetic_markers)
    for path in _git_files(project_root):
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        relative = path.relative_to(project_root).as_posix()
        for line_number, line in enumerate(text.splitlines(), 1):
            candidates: list[tuple[str, str]] = []
            for rule_id, pattern in SECRET_PATTERNS:
                candidates.extend((rule_id, match.group(0)) for match in pattern.finditer(line))
            for match in GENERIC_SECRET.finditer(line):
                value = match.group(1).strip()
                if _entropy(value) >= 3.4:
                    candidates.append(("generic_high_entropy_secret", value))
            for rule_id, value in candidates:
                lowered = value.lower()
                if any(marker in lowered for marker in markers):
                    ignored_synthetic += 1
                    continue
                findings.append(
                    {
                        "rule_id": rule_id,
                        "path": relative,
                        "line": line_number,
                        "fingerprint": hashlib.sha256(value.encode("utf-8")).hexdigest()[:16],
                    }
                )
    return {
        "scanned_text_files": scanned,
        "verified_leaks": len(findings),
        "ignored_synthetic_values": ignored_synthetic,
        "findings": findings,
        "redaction": "matched values are never written; only SHA-256 prefixes are retained",
    }


def audit_repository_hygiene(project_root: Path, policy: dict[str, Any]) -> dict[str, Any]:
    forbidden_names = {item.lower() for item in policy["forbidden_tracked_names"]}
    forbidden_suffixes = tuple(item.lower() for item in policy["forbidden_tracked_suffixes"])
    violations = []
    for path in _git_files(project_root):
        relative = path.relative_to(project_root).as_posix()
        name = path.name.lower()
        if name in forbidden_names or name.endswith(forbidden_suffixes):
            violations.append(relative)
        if "/node_modules/" in f"/{relative}/" or relative.startswith((".runtime", ".venv")):
            violations.append(relative)
    return {"violations": sorted(set(violations)), "violation_count": len(set(violations))}


def vulnerability_counts(pip_path: Path, runtime_path: Path, pnpm_path: Path) -> dict[str, Any]:
    pip_payload = json.loads(pip_path.read_text(encoding="utf-8-sig"))
    runtime_payload = json.loads(runtime_path.read_text(encoding="utf-8-sig"))
    pnpm_payload = json.loads(pnpm_path.read_text(encoding="utf-8-sig"))
    python_findings = sum(len(item.get("vulns", [])) for item in pip_payload.get("dependencies", []))
    runtime_findings = sum(len(item.get("vulns", [])) for item in runtime_payload.get("dependencies", []))
    node_counts = pnpm_payload.get("metadata", {}).get("vulnerabilities", {})
    return {
        "python_known": python_findings,
        "python_shared_runtime_known": runtime_findings,
        "node": {key: int(node_counts.get(key, 0)) for key in ("info", "low", "moderate", "high", "critical")},
    }


def _cyclonedx_hash(integrity: str) -> dict[str, str] | None:
    if not integrity or "-" not in integrity:
        return None
    algorithm, encoded = integrity.split("-", 1)
    try:
        value = base64.b64decode(encoded).hex()
    except ValueError:
        return None
    return {"alg": algorithm.upper().replace("SHA", "SHA-"), "content": value}


def build_sbom(components: list[Component], source_hashes: dict[str, str]) -> dict[str, Any]:
    components = sorted(components, key=lambda item: (item.ecosystem, item.name.lower(), item.version))
    seed = "|".join(f"{item.purl}:{item.license_id}" for item in components)
    seed += "|" + "|".join(f"{key}:{source_hashes[key]}" for key in sorted(source_hashes))
    root_ref = "pkg:generic/aegis-chain@1.0.0"
    entries = []
    for item in components:
        entry: dict[str, Any] = {
            "type": "library",
            "bom-ref": item.purl,
            "group": item.ecosystem,
            "name": item.name,
            "version": item.version,
            "purl": item.purl,
            "licenses": [{"license": {"id": item.license_id}}],
        }
        digest = _cyclonedx_hash(item.integrity)
        if digest:
            entry["hashes"] = [digest]
        entries.append(entry)
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "aegis-chain-supply-security",
                "version": "1.0.0",
                "licenses": [{"license": {"name": "Proprietary - competition evaluation only"}}],
            },
            "properties": [
                {"name": f"aegis:source:{key}:sha256", "value": value}
                for key, value in sorted(source_hashes.items())
            ],
        },
        "components": entries,
        "dependencies": [{"ref": root_ref, "dependsOn": [item.purl for item in components]}],
    }


def render_notices(components: list[Component]) -> str:
    lines = [
        "# Third-Party Notices",
        "",
        "> Generated by `demo_web/audit_project_supply_chain.ps1`. This inventory is",
        "> an engineering aid, not legal advice. The upstream license text controls.",
        "",
        "## Pinned security scanners",
        "",
        "| Component | Source revision | License | Redistribution |",
        "| --- | --- | --- | --- |",
        "| Cisco AI Skill Scanner | `4dee90371890ff23e1b21ea974e02847eacaa464` | Apache-2.0 | Source/binary not committed; rebuilt locally |",
        "| Cisco AI MCP Scanner | `51966cce214ae057e69c3a672307911f5026e255` | Apache-2.0 | Source/binary not committed; rebuilt locally |",
        "",
        "## Locked project runtime inventory",
        "",
        "| Ecosystem | Package | Version | License |",
        "| --- | --- | --- | --- |",
    ]
    for item in sorted(components, key=lambda value: (value.ecosystem, value.name.lower(), value.version)):
        lines.append(f"| {item.ecosystem} | `{item.name}` | `{item.version}` | {item.license_id} |")
    lines.extend(
        [
            "",
            "The frontend list represents the packages installed for the verified Windows x64",
            "release environment. Cross-platform optional packages retained only in the pnpm",
            "lock are still integrity-checked but are not claimed as installed components.",
            "",
        ]
    )
    return "\n".join(lines)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> dict[str, Any]:
    project_root = args.project_root.resolve()
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    python_lock = parse_python_lock(args.python_lock)
    python_dev_lock = parse_python_lock(args.python_dev_lock)
    cisco_lock = parse_python_lock(args.cisco_lock)
    security_lock = parse_python_lock(args.security_lock)
    pnpm_lock = parse_pnpm_lock(args.pnpm_lock)
    package = json.loads(args.package_json.read_text(encoding="utf-8"))
    node_licenses = load_node_licenses(args.node_licenses)

    runtime_payload = json.loads(args.runtime_audit.read_text(encoding="utf-8-sig"))
    python_components = [
        Component("python", item["name"], item["version"], python_license(item["name"]))
        for item in runtime_payload.get("dependencies", [])
    ]
    lock_integrity = {(item["name"], item["version"]): item["integrity"] for item in pnpm_lock}
    node_components = [
        Component("node", name, version, license_id, lock_integrity.get((name, version), ""))
        for (name, version), license_id in node_licenses.items()
    ]
    components = python_components + node_components

    direct_specs = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
    direct_unpinned = sorted(name for name, version in direct_specs.items() if not EXACT_VERSION.fullmatch(version))
    package_manager_pinned = bool(re.fullmatch(r"pnpm@\d+(?:\.\d+){2}", package.get("packageManager", "")))
    python_unhashed = sorted(item["name"] for item in python_lock if not item["hashes"])
    python_dev_unhashed = sorted(item["name"] for item in python_dev_lock if not item["hashes"])
    security_unhashed = sorted(item["name"] for item in security_lock if not item["hashes"])
    node_unhashed = sorted(f"{item['name']}@{item['version']}" for item in pnpm_lock if not item["integrity"])
    approved = set(policy["approved_licenses"])
    unapproved_licenses = sorted(
        f"{item.ecosystem}:{item.name}@{item.version}:{item.license_id}"
        for item in components
        if item.license_id not in approved
    )
    missing_node_license = sorted(
        f"{name}@{version}" for name, version in node_licenses if (name, version) not in lock_integrity
    )
    locked_versions = {
        (item["name"].lower().replace("_", "-"), item["version"])
        for item in cisco_lock + python_lock + security_lock
    }
    runtime_lock_mismatches = sorted(
        f"{item.name}@{item.version}"
        for item in python_components
        if item.name.lower().replace("_", "-") != "cisco-ai-mcp-scanner"
        and (item.name.lower().replace("_", "-"), item.version) not in locked_versions
    )
    vulnerabilities = vulnerability_counts(args.pip_audit, args.runtime_audit, args.pnpm_audit)
    secrets = scan_repository_secrets(project_root, policy["synthetic_secret_markers"])
    hygiene = audit_repository_hygiene(project_root, policy)
    required_files = [project_root / "LICENSE", project_root / "THIRD_PARTY_NOTICES.md", project_root / "PROJECT_SBOM.cdx.json"]
    required_missing = [path.name for path in required_files if not path.is_file()]

    source_hashes = {
        "python-lock": sha256_file(args.python_lock),
        "python-dev-lock": sha256_file(args.python_dev_lock),
        "cisco-mcp-lock": sha256_file(args.cisco_lock),
        "runtime-security-lock": sha256_file(args.security_lock),
        "pnpm-lock": sha256_file(args.pnpm_lock),
        "package-json": sha256_file(args.package_json),
    }
    sbom = build_sbom(components, source_hashes)
    notices = render_notices(components)
    if args.write_artifacts:
        write_json(project_root / "PROJECT_SBOM.cdx.json", sbom)
        (project_root / "THIRD_PARTY_NOTICES.md").write_text(notices, encoding="utf-8")
        required_missing = [path.name for path in required_files if not path.is_file()]

    gates = {
        "direct_dependencies_exact": not direct_unpinned,
        "package_manager_pinned": package_manager_pinned,
        "python_lock_hashed": bool(python_lock) and not python_unhashed,
        "python_dev_lock_hashed": bool(python_dev_lock) and not python_dev_unhashed,
        "runtime_security_lock_hashed": bool(security_lock) and not security_unhashed,
        "installed_runtime_fully_locked": not runtime_lock_mismatches,
        "pnpm_lock_integrity": bool(pnpm_lock) and not node_unhashed,
        "licenses_approved": not unapproved_licenses and not missing_node_license,
        "known_vulnerabilities_zero": vulnerabilities["python_known"] == 0
        and vulnerabilities["python_shared_runtime_known"] == 0
        and sum(vulnerabilities["node"].values()) == 0,
        "verified_secrets_zero": secrets["verified_leaks"] == 0,
        "repository_hygiene": hygiene["violation_count"] == 0,
        "required_legal_and_sbom_files": not required_missing,
    }
    report = {
        "schema_version": "1.0",
        "decision": "PASS" if all(gates.values()) else "FAIL",
        "gates": gates,
        "metrics": {
            "python_components": len(python_components),
            "python_project_lock_components": len(python_lock),
            "python_dev_lock_components": len(python_dev_lock),
            "node_installed_components": len(node_components),
            "pnpm_locked_components": len(pnpm_lock),
            "direct_dependencies": len(direct_specs),
            "direct_unpinned": direct_unpinned,
            "python_unhashed": python_unhashed,
            "python_dev_unhashed": python_dev_unhashed,
            "runtime_security_unhashed": security_unhashed,
            "runtime_lock_mismatches": runtime_lock_mismatches,
            "node_unhashed": node_unhashed,
            "unapproved_licenses": unapproved_licenses,
            "installed_node_components_missing_from_lock": missing_node_license,
            "required_files_missing": required_missing,
            "vulnerabilities": vulnerabilities,
            "secrets": secrets,
            "repository_hygiene": hygiene,
            "source_hashes": source_hashes,
            "sbom_sha256": hashlib.sha256(
                (json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
            ).hexdigest(),
        },
        "limitations": [
            "Vulnerability results are a point-in-time view of the selected advisory services.",
            "Secret scanning uses deterministic high-confidence patterns and is not proof that no credential exists.",
            "License classification is an engineering inventory and not legal advice.",
            "The Python SBOM covers the installed shared Cisco/Aegis runtime; the Node graph represents installed Windows x64 packages.",
            "The entire pnpm lock is integrity checked, including optional packages not installed on Windows x64.",
        ],
    }
    write_json(args.output / "project_supply_chain_report.json", report)
    write_json(args.output / "project_sbom.generated.cdx.json", sbom)
    (args.output / "third_party_notices.generated.md").write_text(notices, encoding="utf-8")
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit Aegis Chain's own software supply chain.")
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--python-lock", type=Path, required=True)
    parser.add_argument("--python-dev-lock", type=Path, required=True)
    parser.add_argument("--cisco-lock", type=Path, required=True)
    parser.add_argument("--security-lock", type=Path, required=True)
    parser.add_argument("--package-json", type=Path, required=True)
    parser.add_argument("--pnpm-lock", type=Path, required=True)
    parser.add_argument("--pip-audit", type=Path, required=True)
    parser.add_argument("--runtime-audit", type=Path, required=True)
    parser.add_argument("--pnpm-audit", type=Path, required=True)
    parser.add_argument("--node-licenses", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--write-artifacts", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = run(args)
    print(json.dumps({"decision": report["decision"], "gates": report["gates"]}, ensure_ascii=False))
    return 0 if report["decision"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
