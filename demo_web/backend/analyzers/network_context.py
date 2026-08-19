from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-network-context-v1"
MAX_FILES = 500
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024
MAX_FEATURE_HITS = 2048
MAX_CORRELATION_LINES = 80

TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".yaml", ".yml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".go", ".rs", ".java",
    ".rb", ".php", ".pl", ".lua", ".sql", ".env", ".properties",
}
DOCUMENT_EXTENSIONS = {".md", ".txt"}


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


DECLARATION_PATTERNS = {
    "network_declared": _rx(
        r"\b(?:api|https?|rest|web|internet|online|network|url|fetch|download|scrap(?:e|ing)?|"
        r"crawl(?:er|ing)?|remote|live data|webhook)\b|(?:网络|联网|接口|在线|网址|链接|抓取|爬取|下载|远程|实时数据)"
    ),
    "outbound_declared": _rx(
        r"\b(?:upload|send|submit|post|publish|push|sync|webhook|callback|report to)\b|"
        r"(?:上传|发送|提交|发布|推送|同步|回调|上报)"
    ),
    "credential_declared": _rx(
        r"\b(?:api[_ -]?key|token|secret|credential|oauth|authorization|authentication|bearer)\b|"
        r"(?:密钥|令牌|凭据|认证|鉴权)"
    ),
    "mock_or_local_network": _rx(
        r"\b(?:mock(?:ed)?\s+(?:http|network|url)|localhost|127\.0\.0\.1|"
        r"no\s+(?:external\s+|real\s+)?network\s+access|offline[- ]only)\b|"
        r"(?:模拟网络|本地回环|无需联网|不需要网络|无外部网络)"
    ),
}

FEATURE_PATTERNS = {
    "network_read": _rx(
        r"\b(?:requests\.(?:get|head)\s*\(|httpx\.(?:get|head)\s*\(|"
        r"urllib(?:\.request)?\.(?:urlopen|urlretrieve)\s*\(|aiohttp\.[^\n]{0,80}\.get\s*\(|"
        r"axios\.(?:get|head)\s*\(|(?:session|client)\.(?:get|head)\s*\(|"
        r"fetch\s*\(|curl\b(?![^\n]{0,160}(?:-x\s+post|--data|-d\s))|wget\b|"
        r"invoke-webrequest\b|invoke-restmethod\b|\biwr\b|\birm\b)"
    ),
    "outbound_sink": _rx(
        r"\b(?:requests\.(?:post|put|patch|delete)\s*\(|httpx\.(?:post|put|patch|delete)\s*\(|"
        r"aiohttp\.[^\n]{0,80}\.(?:post|put|patch|delete)\s*\(|axios\.(?:post|put|patch|delete)\s*\(|"
        r"(?:session|client)\.(?:post|put|patch|delete)\s*\(|"
        r"fetch\s*\([^\n]{0,300}method\s*:\s*['\"](?:post|put|patch|delete)|"
        r"urllib(?:\.request)?\.Request\s*\([^\n]{0,300}\bdata\s*=|"
        r"curl\b[^\n]{0,200}(?:-x\s+(?:post|put|patch|delete)|--data(?:-binary)?\b|-d\s)|"
        r"socket\.(?:send|sendall)\s*\(|webhook\s*\(|upload\s*\()"
    ),
    "environment_source": _rx(
        r"\b(?:os\.environ|os\.getenv\s*\(|process\.env|system\.getenv\s*\(|getenv\s*\()|\$env:"
    ),
    "credential_file_source": _rx(
        r"(?:\.ssh[/\\]|\.aws[/\\]|\.kube[/\\]|credentials?(?:\.json)?|id_rsa\b|"
        r"wallet\.dat\b|keychain\b|cookies?(?:\.sqlite)?\b|login\.keychain\b)"
    ),
    "secret_identifier": _rx(
        r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|"
        r"password|credential|bearer[_-]?token)\b"
    ),
    "auth_usage": _rx(
        r"(?:authorization[\"']?\s*[:=]|bearer\s+|x-api-key|api[_-]?key[\"']?\s*[:=]|"
        r"headers?\s*=\s*\{[^\n]{0,300}(?:token|authorization|api[_-]?key))"
    ),
}


@dataclass(frozen=True)
class TextDocument:
    relative_path: str
    suffix: str
    text: str


@dataclass(frozen=True)
class FeatureHit:
    feature: str
    relative_path: str
    line: int


def _inside(root: Path, candidate: Path) -> bool:
    return candidate == root or root in candidate.parents


def _read_documents(skill_root: Path) -> list[TextDocument]:
    root = skill_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Skill root must be a directory")
    documents: list[TextDocument] = []
    total_bytes = 0
    visited = 0
    for path in sorted(skill_root.rglob("*"), key=lambda item: item.as_posix().lower()):
        if path.is_symlink() or not path.is_file():
            continue
        visited += 1
        if visited > MAX_FILES:
            raise ValueError(f"Skill contains more than {MAX_FILES} files")
        resolved = path.resolve(strict=True)
        if not _inside(root, resolved):
            raise ValueError("Skill contains a file outside its root")
        suffix = path.suffix.lower()
        if path.name != "SKILL.md" and suffix not in TEXT_EXTENSIONS:
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            continue
        if total_bytes + size > MAX_TOTAL_BYTES:
            raise ValueError("Skill text exceeds the bounded context-analysis limit")
        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            continue
        total_bytes += size
        documents.append(TextDocument(
            relative_path=resolved.relative_to(root).as_posix(),
            suffix=suffix,
            text=data.decode("utf-8", errors="replace"),
        ))
    return documents


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _hits(document: TextDocument, feature: str) -> list[FeatureHit]:
    hits: list[FeatureHit] = []
    for match in FEATURE_PATTERNS[feature].finditer(document.text):
        hits.append(FeatureHit(
            feature=feature,
            relative_path=document.relative_path,
            line=_line_number(document.text, match.start()),
        ))
        if len(hits) >= MAX_FEATURE_HITS:
            break
    return hits


def _nearby(first: list[FeatureHit], second: list[FeatureHit]) -> bool:
    if not first or not second:
        return False
    left = sorted(hit.line for hit in first)
    right = sorted(hit.line for hit in second)
    first_index = 0
    second_index = 0
    while first_index < len(left) and second_index < len(right):
        delta = left[first_index] - right[second_index]
        if abs(delta) <= MAX_CORRELATION_LINES:
            return True
        if delta < 0:
            first_index += 1
        else:
            second_index += 1
    return False


def _declarations(documents: list[TextDocument]) -> set[str]:
    skill_text = "\n".join(
        document.text for document in documents if document.relative_path.casefold() == "skill.md"
    )
    return {
        name for name, pattern in DECLARATION_PATTERNS.items() if pattern.search(skill_text)
    }


def _cisco_network_rule_ids(findings: list[dict[str, Any]]) -> list[str]:
    rule_ids: set[str] = set()
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        category = str(finding.get("category") or "")
        if "NETWORK" in rule_id.upper() or "EXFIL" in rule_id.upper() or category in {
            "data_exfiltration", "unauthorized_tool_use",
        }:
            rule_ids.add(rule_id or str(finding.get("id") or "unidentified"))
    return sorted(rule_ids)


def _finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    paths: Iterable[str],
    line: int | None,
    evidence_codes: Iterable[str],
    cisco_rule_ids: Iterable[str],
    description: str,
    remediation: str,
) -> dict[str, Any]:
    normalized_paths = sorted(set(paths))
    normalized_codes = sorted(set(evidence_codes))
    normalized_cisco = sorted(set(cisco_rule_ids))
    identity = "|".join([rule_id, *normalized_paths, *normalized_codes, *normalized_cisco])
    finding_id = f"{rule_id}_{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:12]}"
    displayed_paths = normalized_paths[:12]
    evidence = (
        f"context_features={','.join(normalized_codes)}; "
        f"files={','.join(displayed_paths)}; "
        f"cisco_rule_ids={','.join(normalized_cisco)}"
    )
    return finding_dict(
        id=finding_id,
        title=title,
        category=category,
        severity="INFO",
        analyzer=ANALYZER_ID,
        location={"file": normalized_paths[0] if normalized_paths else None, "line": line},
        evidence=evidence,
        description=description,
        remediation=remediation,
        rule_id=rule_id,
    )


def analyze_network_context(
    skill_root: Path,
    cisco_findings: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Add INFO-only network context evidence without changing admission decisions."""
    documents = _read_documents(skill_root)
    declarations = _declarations(documents)
    cisco_rule_ids = _cisco_network_rule_ids(cisco_findings or [])
    feature_hits: dict[str, list[FeatureHit]] = {name: [] for name in FEATURE_PATTERNS}
    per_document: dict[str, dict[str, list[FeatureHit]]] = {}
    for document in documents:
        current = {name: _hits(document, name) for name in FEATURE_PATTERNS}
        per_document[document.relative_path] = current
        for name, hits in current.items():
            feature_hits[name].extend(hits)

    findings: list[dict[str, Any]] = []
    network_hits = feature_hits["network_read"] + feature_hits["outbound_sink"]
    if not network_hits:
        if "network_declared" in declarations and cisco_rule_ids:
            findings.append(_finding(
                rule_id="AEGIS_CONTEXT_NETWORK_CAPABILITY_DECLARED_NO_DIRECT_PRIMITIVE",
                title="Network capability is declared, but no direct primitive was recognized",
                category="network_context_support",
                paths=["SKILL.md"],
                line=None,
                evidence_codes=[
                    "network_declared", "cisco_network_finding_present",
                    "direct_network_primitive_not_observed",
                ],
                cisco_rule_ids=cisco_rule_ids,
                description="SKILL.md declares network use and Cisco reported network risk, while this context layer did not recognize a direct HTTP primitive; SDK or wrapper use may be present.",
                remediation="Review the Cisco location and any SDK or wrapper implementation before interpreting the declaration as sufficient justification.",
            ))
            if "mock_or_local_network" in declarations:
                findings.append(_finding(
                    rule_id="AEGIS_CONTEXT_NETWORK_MOCK_OR_LOCAL_ONLY_DECLARED",
                    title="Network use is described as mocked, local-only, or offline",
                    category="network_context_support",
                    paths=["SKILL.md"],
                    line=None,
                    evidence_codes=["network_declared", "mock_or_local_network"],
                    cisco_rule_ids=cisco_rule_ids,
                    description="The Skill documentation describes mocked, loopback, or no-external-network behavior.",
                    remediation="Verify that runtime destinations are constrained to loopback or test fixtures and cannot be overridden by untrusted input.",
                ))
        ordered = sorted(findings, key=lambda item: (item["rule_id"] or "", item["id"]))
        return ordered, [ANALYZER_ID]

    network_paths = [hit.relative_path for hit in network_hits]
    if "network_declared" in declarations:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_NETWORK_CAPABILITY_DECLARED",
            title="Network capability is declared by the Skill",
            category="network_context_support",
            paths=["SKILL.md", *network_paths],
            line=None,
            evidence_codes=["network_declared", "network_behavior_observed"],
            cisco_rule_ids=cisco_rule_ids,
            description="The Skill documentation declares network use and the implementation contains network behavior.",
            remediation="Keep the declared endpoints, methods, data classes, and purpose explicit for admission review.",
        ))
    else:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_NETWORK_BEHAVIOR_UNDECLARED",
            title="Observed network behavior is not explicitly declared",
            category="network_context_review",
            paths=network_paths,
            line=None,
            evidence_codes=["network_behavior_observed", "network_declaration_absent"],
            cisco_rule_ids=cisco_rule_ids,
            description="Network primitives were observed, but no explicit network capability declaration was found in SKILL.md.",
            remediation="Declare network purpose, allowed endpoints, HTTP methods, and transmitted data before admission.",
        ))

    if feature_hits["network_read"] and not feature_hits["outbound_sink"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_READ_ONLY_NETWORK_BEHAVIOR",
            title="Observed network behavior is read-oriented",
            category="network_context_support",
            paths=[hit.relative_path for hit in feature_hits["network_read"]],
            line=None,
            evidence_codes=["network_read", "outbound_write_sink_absent"],
            cisco_rule_ids=cisco_rule_ids,
            description="Recognized network calls are read-oriented; no supported POST, upload, webhook, or socket-send sink was found.",
            remediation="Confirm the endpoint allowlist and response-handling limits during human review.",
        ))

    if feature_hits["outbound_sink"]:
        declared_code = (
            "outbound_declared" if "outbound_declared" in declarations
            else "outbound_declaration_absent"
        )
        findings.append(_finding(
            rule_id=(
                "AEGIS_CONTEXT_OUTBOUND_BEHAVIOR_DECLARED"
                if "outbound_declared" in declarations
                else "AEGIS_CONTEXT_OUTBOUND_BEHAVIOR_NOT_EXPLICITLY_DECLARED"
            ),
            title=(
                "Outbound network behavior is declared by the Skill"
                if "outbound_declared" in declarations
                else "Outbound network behavior lacks an explicit data-transfer declaration"
            ),
            category=(
                "network_context_support"
                if "outbound_declared" in declarations else "network_context_review"
            ),
            paths=[hit.relative_path for hit in feature_hits["outbound_sink"]],
            line=None,
            evidence_codes=["outbound_sink", declared_code],
            cisco_rule_ids=cisco_rule_ids,
            description="An outbound write-capable network sink was observed and compared with the Skill declaration.",
            remediation="Document transmitted fields, destination allowlist, retention, and user-consent requirements.",
        ))

    sensitive_features = ("environment_source", "credential_file_source", "secret_identifier")
    for document in documents:
        if document.suffix in DOCUMENT_EXTENSIONS:
            continue
        current = per_document[document.relative_path]
        sensitive = [hit for name in sensitive_features for hit in current[name]]
        if sensitive and _nearby(sensitive, current["outbound_sink"]):
            findings.append(_finding(
                rule_id="AEGIS_CONTEXT_SENSITIVE_SOURCE_WITH_OUTBOUND_SINK",
                title="Sensitive-source and outbound-sink indicators are correlated",
                category="sensitive_flow_context",
                paths=[document.relative_path],
                line=min(hit.line for hit in sensitive + current["outbound_sink"]),
                evidence_codes=[
                    *[name for name in sensitive_features if current[name]],
                    "outbound_sink",
                    "data_flow_not_proven",
                ],
                cisco_rule_ids=cisco_rule_ids,
                description="Sensitive-source indicators and an outbound sink occur within a bounded window; exact data flow is not proven.",
                remediation="Trace variables into the request body, query, headers, and destination before changing admission policy.",
            ))
        if current["auth_usage"] and _nearby(current["auth_usage"], current["outbound_sink"]):
            findings.append(_finding(
                rule_id="AEGIS_CONTEXT_CREDENTIAL_USED_FOR_NETWORK_AUTH",
                title="Credential-like value appears to support network authentication",
                category="network_auth_context",
                paths=[document.relative_path],
                line=min(hit.line for hit in current["auth_usage"] + current["outbound_sink"]),
                evidence_codes=["auth_usage", "outbound_sink", "business_auth_possible"],
                cisco_rule_ids=cisco_rule_ids,
                description="Authentication syntax is adjacent to an outbound request; this may represent expected API authentication rather than payload exfiltration.",
                remediation="Verify that credentials remain in approved authentication fields and are never included in request payloads or logs.",
            ))

    unique = {finding["id"]: finding for finding in findings}
    ordered = sorted(unique.values(), key=lambda item: (item["rule_id"] or "", item["id"]))
    if any(item["severity"] != "INFO" for item in ordered):
        raise RuntimeError("Network context analyzer emitted a policy-changing severity")
    return ordered, [ANALYZER_ID]
