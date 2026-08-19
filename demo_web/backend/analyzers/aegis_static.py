from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-static-v1"
MAX_FILES = 500
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024
MAX_CORRELATION_LINES = 80
MAX_FEATURE_HITS = 2048

TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".yaml", ".yml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".go", ".rs", ".java",
    ".rb", ".php", ".pl", ".lua", ".sql", ".env", ".properties",
}


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


FEATURE_PATTERNS: dict[str, re.Pattern[str]] = {
    "remote_fetch": _rx(
        r"\b(?:requests\.(?:get|post)\s*\(|urllib(?:\.request)?\.(?:urlopen|urlretrieve)\s*\(|"
        r"httpx\.(?:get|post)\s*\(|aiohttp\.|fetch\s*\(|axios\.(?:get|post)\s*\(|"
        r"curl\b|wget\b|invoke-webrequest\b|invoke-restmethod\b|\biwr\b|\birm\b|"
        r"downloadstring\s*\(|downloadfile\s*\()"
    ),
    "payload_decode": _rx(
        r"\b(?:base64\.(?:b64decode|urlsafe_b64decode)\s*\(|frombase64string\s*\(|"
        r"atob\s*\(|bytes\.fromhex\s*\(|base64\s+(?:-d|--decode)\b|certutil\s+-decode\b|"
        r"codecs\.decode\s*\([^\n]{0,160}(?:base64|hex|rot_13))"
    ),
    "execution_sink": _rx(
        r"\b(?:exec\s*\(|eval\s*\(|os\.system\s*\(|subprocess\.(?:run|call|popen|check_call|check_output)\s*\(|"
        r"child_process\.(?:exec|execsync|spawn)\s*\(|new\s+function\s*\(|"
        r"powershell(?:\.exe)?\s+(?:-[a-z]+\s+)*(?:-enc|-encodedcommand|-command)\b|"
        r"(?:bash|sh|zsh)\s+-c\b|cmd(?:\.exe)?\s+/c\b|start-process\b|invoke-expression\b|\biex\b)"
    ),
    "paste_service": _rx(
        r"https?://(?:www\.)?(?:pastebin\.com/(?:raw/)?|paste\.ee/(?:r/)?|hastebin\.com/raw/|"
        r"glot\.io/snippets/)"
    ),
    "embedded_blob": re.compile(
        r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{160,}={0,2}(?![A-Za-z0-9+/=])",
        re.MULTILINE,
    ),
    "startup_target": _rx(
        r"(?:\.bashrc\b|\.zshrc\b|(?:^|[/\\])\.profile\b|authorized_keys\b|rc\.local\b|"
        r"\\currentversion\\run(?:once)?\b|startup[/\\]|loginitems?\b|launchagents?[/\\])"
    ),
    "write_action": _rx(
        r"(?:>>|\btee\b|\b(?:add|set)-content\b|\bout-file\b|\breg(?:\.exe)?\s+add\b|"
        r"\.write_(?:text|bytes)\s*\(|\.write\s*\(|\.append\s*\(|"
        r"\bopen\s*\([^\n]{0,240}['\"](?:a|w|ab|wb|a\+|w\+)['\"]|"
        r"\b(?:copy|cp|install)\s+[^\n]{0,240})"
    ),
    "startup_execution": _rx(
        r"\b(?:pythonstartup|prompt_command|bash_env|ld_preload)\b"
    ),
}

DIRECT_REMOTE_EXEC = _rx(
    r"(?:\b(?:curl|wget)\b[^\n|]{0,500}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|powershell|pwsh)\b|"
    r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,500}\|\s*(?:iex|invoke-expression)\b|"
    r"\b(?:iex|invoke-expression)\s*\(?[^\n]{0,500}(?:downloadstring|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b))"
)

SCHEDULED_TASK_CREATE = _rx(
    r"(?:\bschtasks(?:\.exe)?\b[^\n]{0,240}/create\b|\bregister-scheduledtask\b|"
    r"\bcrontab\b[^\n]{0,240}(?:-\s*$|-e\b|-l\b|-r\b|<<|\||<)|"
    r"(?:/etc/cron(?:tab|\.d)|cron\.(?:daily|hourly|weekly|monthly))[^\n]{0,240}(?:>>|tee|write|copy|install))"
)

SERVICE_CREATE = _rx(
    r"(?:\bsystemctl\b[^\n]{0,240}\b(?:enable|reenable|link)\b|"
    r"\b(?:new-service|create_service)\b|\bsc(?:\.exe)?\s+create\b|"
    r"\blaunchctl\b[^\n]{0,240}\b(?:load|bootstrap|enable)\b|"
    r"/etc/systemd/system/[^\n]{0,160}\.service[^\n]{0,240}(?:>>|tee|write|copy|install))"
)


@dataclass(frozen=True)
class TextDocument:
    relative_path: str
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
        if path.name != "SKILL.md" and path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            continue
        if total_bytes + size > MAX_TOTAL_BYTES:
            raise ValueError("Skill text exceeds the bounded static-analysis limit")
        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            continue
        total_bytes += size
        documents.append(TextDocument(
            relative_path=resolved.relative_to(root).as_posix(),
            text=data.decode("utf-8", errors="replace"),
        ))
    return documents


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _hits(document: TextDocument, feature: str) -> list[FeatureHit]:
    pattern = FEATURE_PATTERNS[feature]
    hits: list[FeatureHit] = []
    for match in pattern.finditer(document.text):
        hits.append(FeatureHit(
            feature,
            document.relative_path,
            _line_number(document.text, match.start()),
        ))
        if len(hits) >= MAX_FEATURE_HITS:
            break
    return hits


def _nearby(*groups: list[FeatureHit]) -> bool:
    if not groups or any(not group for group in groups):
        return False
    indexed = sorted(
        (hit.line, group_index)
        for group_index, group in enumerate(groups)
        for hit in group
    )
    counts = [0] * len(groups)
    covered = 0
    left = 0
    for right, (right_line, right_group) in enumerate(indexed):
        if counts[right_group] == 0:
            covered += 1
        counts[right_group] += 1
        while right_line - indexed[left][0] > MAX_CORRELATION_LINES:
            left_group = indexed[left][1]
            counts[left_group] -= 1
            if counts[left_group] == 0:
                covered -= 1
            left += 1
        if covered == len(groups):
            return True
    return False


def _finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    severity: str,
    relative_paths: Iterable[str],
    line: int | None,
    evidence_codes: Iterable[str],
    description: str,
    remediation: str,
) -> dict:
    paths = sorted(set(relative_paths))
    codes = sorted(set(evidence_codes))
    identity = "|".join([rule_id, *paths, *codes])
    finding_id = f"{rule_id}_{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:12]}"
    evidence = f"correlated_features={','.join(codes)}; files={','.join(paths)}"
    return finding_dict(
        id=finding_id,
        title=title,
        category=category,
        severity=severity,
        analyzer=ANALYZER_ID,
        location={"file": paths[0] if paths else None, "line": line},
        evidence=evidence,
        description=description,
        remediation=remediation,
        rule_id=rule_id,
    )


def _pattern_line(pattern: re.Pattern[str], document: TextDocument) -> int | None:
    match = pattern.search(document.text)
    return _line_number(document.text, match.start()) if match else None


def _analyze_remote_execution(documents: list[TextDocument]) -> list[dict]:
    findings: list[dict] = []
    all_hits: dict[str, list[FeatureHit]] = {name: [] for name in ("remote_fetch", "payload_decode", "execution_sink")}
    has_critical = False
    for document in documents:
        feature_hits = {name: _hits(document, name) for name in all_hits}
        for name, hits in feature_hits.items():
            all_hits[name].extend(hits)

        direct_line = _pattern_line(DIRECT_REMOTE_EXEC, document)
        if direct_line is not None:
            has_critical = True
            findings.append(_finding(
                rule_id="AEGIS_REMOTE_FETCH_PIPE_SHELL",
                title="Remote content is piped into a command interpreter",
                category="remote_payload_execution",
                severity="CRITICAL",
                relative_paths=[document.relative_path],
                line=direct_line,
                evidence_codes=["remote_fetch", "direct_interpreter_pipe"],
                description="The skill contains an explicit download-and-execute command chain.",
                remediation="Remove remote pipe-to-shell behavior; pin and verify an offline artifact before any approved execution.",
            ))

        if _nearby(feature_hits["remote_fetch"], feature_hits["payload_decode"], feature_hits["execution_sink"]):
            has_critical = True
            line = min(hit.line for hits in feature_hits.values() for hit in hits)
            findings.append(_finding(
                rule_id="AEGIS_REMOTE_FETCH_DECODE_EXECUTE",
                title="Remote payload is fetched, decoded, and executed",
                category="remote_payload_execution",
                severity="CRITICAL",
                relative_paths=[document.relative_path],
                line=line,
                evidence_codes=["remote_fetch", "payload_decode", "execution_sink"],
                description="Three high-risk primitives form a bounded same-file payload execution chain.",
                remediation="Prohibit runtime remote-code execution; use signed, pinned artifacts and isolate any approved execution path.",
            ))

        paste_hits = _hits(document, "paste_service")
        if paste_hits and _nearby(paste_hits, feature_hits["remote_fetch"], feature_hits["execution_sink"]):
            has_critical = True
            findings.append(_finding(
                rule_id="AEGIS_PASTE_SERVICE_PAYLOAD_EXECUTION",
                title="Paste or raw-content service supplies an executed payload",
                category="remote_payload_execution",
                severity="CRITICAL",
                relative_paths=[document.relative_path],
                line=min(hit.line for hit in paste_hits),
                evidence_codes=["paste_service", "remote_fetch", "execution_sink"],
                description="An ephemeral raw-content source is correlated with retrieval and an execution sink.",
                remediation="Reject ephemeral payload sources; require an approved repository, immutable digest, signature, and review.",
            ))

        blob_hits = _hits(document, "embedded_blob")
        if blob_hits and _nearby(blob_hits, feature_hits["payload_decode"], feature_hits["execution_sink"]):
            has_critical = True
            findings.append(_finding(
                rule_id="AEGIS_EMBEDDED_BLOB_DECODE_EXECUTE",
                title="Embedded encoded payload is decoded and executed",
                category="embedded_malicious_code",
                severity="CRITICAL",
                relative_paths=[document.relative_path],
                line=min(hit.line for hit in blob_hits),
                evidence_codes=["embedded_blob", "payload_decode", "execution_sink"],
                description="A large encoded blob is correlated with decoding and an execution sink.",
                remediation="Remove opaque embedded code and replace it with reviewable source plus integrity verification.",
            ))

        if not any(item["location"].get("file") == document.relative_path for item in findings):
            present = [name for name, hits in feature_hits.items() if hits]
            if "execution_sink" in present and len(present) >= 2:
                line = min(hit.line for name in present for hit in feature_hits[name])
                findings.append(_finding(
                    rule_id="AEGIS_PARTIAL_REMOTE_EXEC_CHAIN",
                    title="Partial remote payload execution chain requires review",
                    category="remote_payload_execution",
                    severity="MEDIUM",
                    relative_paths=[document.relative_path],
                    line=line,
                    evidence_codes=present,
                    description="Two correlated primitives are present, but a complete high-confidence chain was not established.",
                    remediation="Review data flow and prove that downloaded or decoded content cannot reach an execution sink.",
                ))

    if not has_critical and all(all_hits.values()):
        paths = [hit.relative_path for hits in all_hits.values() for hit in hits]
        if len(set(paths)) > 1:
            findings.append(_finding(
                rule_id="AEGIS_PARTIAL_REMOTE_EXEC_CHAIN",
                title="Cross-file remote payload execution indicators require review",
                category="remote_payload_execution",
                severity="MEDIUM",
                relative_paths=paths,
                line=None,
                evidence_codes=all_hits.keys(),
                description="Fetch, decode, and execution primitives exist across files without proven data flow.",
                remediation="Trace cross-file data flow and separate untrusted content from all execution APIs.",
            ))
    return findings


def _analyze_persistence(documents: list[TextDocument]) -> list[dict]:
    findings: list[dict] = []
    startup_hits_all: list[FeatureHit] = []
    write_hits_all: list[FeatureHit] = []
    startup_critical = False
    for document in documents:
        scheduled_line = _pattern_line(SCHEDULED_TASK_CREATE, document)
        if scheduled_line is not None:
            findings.append(_finding(
                rule_id="AEGIS_PERSISTENCE_SCHEDULED_TASK",
                title="Skill creates or modifies a scheduled execution mechanism",
                category="system_persistence",
                severity="CRITICAL",
                relative_paths=[document.relative_path],
                line=scheduled_line,
                evidence_codes=["scheduled_task_create"],
                description="An explicit cron or scheduled-task creation primitive can survive the current session.",
                remediation="Remove persistent scheduling or require administrator approval, a fixed allowlist, and a reversible change record.",
            ))

        service_line = _pattern_line(SERVICE_CREATE, document)
        if service_line is not None:
            findings.append(_finding(
                rule_id="AEGIS_PERSISTENCE_SERVICE_CREATE",
                title="Skill creates or enables a persistent system service",
                category="system_persistence",
                severity="CRITICAL",
                relative_paths=[document.relative_path],
                line=service_line,
                evidence_codes=["service_create_or_enable"],
                description="An explicit service creation or enablement primitive establishes persistent execution.",
                remediation="Disallow service installation by default; require signed deployment packages and privileged change approval.",
            ))

        startup_hits = _hits(document, "startup_target")
        write_hits = _hits(document, "write_action")
        execution_hits = _hits(document, "startup_execution")
        startup_hits_all.extend(startup_hits)
        write_hits_all.extend(write_hits)
        if _nearby(startup_hits, write_hits, execution_hits):
            startup_critical = True
            findings.append(_finding(
                rule_id="AEGIS_PERSISTENCE_STARTUP_PROFILE_WRITE",
                title="Skill writes to an automatic-start location",
                category="system_persistence",
                severity="CRITICAL",
                relative_paths=[document.relative_path],
                line=min(hit.line for hit in startup_hits + write_hits),
                evidence_codes=["startup_target", "write_action", "startup_execution"],
                description="A write primitive and auto-executed payload are correlated with a shell, login, startup, or authorized-key target.",
                remediation="Remove automatic-start modification or gate it behind explicit privileged approval and rollback controls.",
            ))
        elif _nearby(startup_hits, write_hits):
            findings.append(_finding(
                rule_id="AEGIS_PARTIAL_PERSISTENCE_INDICATOR",
                title="Automatic-start location write requires review",
                category="system_persistence",
                severity="MEDIUM",
                relative_paths=[document.relative_path],
                line=min(hit.line for hit in startup_hits + write_hits),
                evidence_codes=["startup_target", "write_action"],
                description="A write targets an automatic-start location, but an executable startup payload was not established.",
                remediation="Confirm the written value is configuration-only and cannot trigger code or command execution.",
            ))

    if not startup_critical and startup_hits_all and write_hits_all:
        paths = [hit.relative_path for hit in startup_hits_all + write_hits_all]
        findings.append(_finding(
            rule_id="AEGIS_PARTIAL_PERSISTENCE_INDICATOR",
            title="Cross-file persistence indicators require review",
            category="system_persistence",
            severity="MEDIUM",
            relative_paths=paths,
            line=None,
            evidence_codes=["startup_target", "write_action"],
            description="A persistence target and a write primitive occur across files without proven data flow.",
            remediation="Review cross-file control flow and prove that no write reaches an automatic-start location.",
        ))
    return findings


def analyze_skill_tree(skill_root: Path) -> tuple[list[dict], list[str]]:
    """Perform bounded, read-only correlation analysis on one Skill directory."""
    documents = _read_documents(skill_root)
    findings = _analyze_remote_execution(documents) + _analyze_persistence(documents)
    unique = {item["id"]: item for item in findings}
    ordered = sorted(unique.values(), key=lambda item: (item["severity"], item["rule_id"] or "", item["id"]))
    return ordered, [ANALYZER_ID]
