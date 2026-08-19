from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-command-context-v1"
MAX_FILES = 500
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024
MAX_FEATURE_HITS = 2048
MAX_HITS_PER_FEATURE = 128
MAX_CORRELATION_LINES = 80

TEXT_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".yaml", ".yml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".go", ".rs", ".java",
    ".rb", ".php", ".pl", ".lua", ".sql", ".env", ".properties",
}
DOCUMENT_EXTENSIONS = {".md", ".txt"}
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd"}


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


DECLARATION_PATTERNS = {
    "command_declared": _rx(
        r"\b(?:command(?:-line)?|process|subprocess|shell|terminal|CLI|script|system tool|"
        r"execute|execution|run(?:s|ning)?\s+(?:the |a )?(?:command|script|tool|program)|"
        r"invoke(?:s|d|ing)?\s+(?:the |a )?(?:command|script|tool|program)|"
        r"ffmpeg|whisper|yt-dlp|docker\s+ps|unix\s+bc|system-level\s+read-only\s+commands)\b|"
        r"(?:命令行|命令|进程|子进程|外壳|终端|脚本|执行工具|运行脚本|系统工具)"
    ),
    "shell_declared": _rx(
        r"\b(?:shell|bash|zsh|sh script|powershell|pwsh|cmd\.exe|terminal)\b|"
        r"(?:外壳|终端|PowerShell|命令解释器)"
    ),
    "read_only_declared": _rx(
        r"\b(?:read[- ]only|without modifying|does not modify|monitor|inspect|status|health check|"
        r"list(?:s|ing)?|show(?:s|ing)?|collect(?:s|ing)?\s+(?:metrics|status|information))\b|"
        r"(?:只读|不修改|监控|检查状态|健康检查|采集指标)"
    ),
    "dangerous_command_declared": _rx(
        r"\b(?:install|update|upgrade|delete|remove|cleanup|configure|service|scheduled task|"
        r"cron|administrator|root|sudo|privileged)\b|"
        r"(?:安装|更新|升级|删除|清理|配置服务|计划任务|管理员|特权)"
    ),
    "security_test_declared": _rx(
        r"\b(?:security (?:test|validation)|test fixture|test payload|injection attempts? (?:are )?"
        r"blocked|saniti[sz](?:e|er|ation)|reject(?:s|ed|ing)?\s+(?:unsafe|dangerous|shell))\b|"
        r"(?:安全测试|安全验证|测试载荷|注入测试|输入净化|拒绝危险输入)"
    ),
}

FEATURE_PATTERNS = {
    "process_import": _rx(
        r"\b(?:import\s+subprocess\b|from\s+subprocess\s+import\b|"
        r"require\s*\(\s*['\"]child_process['\"]\s*\)|from\s+['\"]child_process['\"]|"
        r"import\s+.*\bchild_process\b|java\.lang\.ProcessBuilder|os/exec|std::process::Command)"
    ),
    "process_call": _rx(
        r"\b(?:subprocess\.(?:run|call|Popen|check_call|check_output)\s*\(|os\.(?:system|popen)\s*\(|"
        r"child_process\.(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|fork)\s*\(|"
        r"\b(?:spawn|spawnSync|execSync|execFile|execFileSync)\s*\(|"
        r"\bexec\s*\([^;\n]{0,500}(?:=>|function|\)|,)|\bexecAsync\s*\(|"
        r"start-process\b|invoke-expression\b|\biex\b|runtime\.getruntime\(\)\.exec\s*\(|"
        r"new\s+processbuilder\s*\(|exec\.command\s*\(|command::new\s*\()"
    ),
    "shell_script": _rx(r"(?!x)x"),
    "argv_call": _rx(
        r"\b(?:subprocess\.(?:run|call|Popen|check_call|check_output)\s*\(\s*[\[(]\s*['\"]|"
        r"(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*['\"][^'\"\n]+['\"]\s*,\s*\[|"
        r"new\s+processbuilder\s*\(\s*['\"]|exec\.command\s*\(\s*['\"]|"
        r"command::new\s*\(\s*['\"]|start-process\b[^\n]{0,120}-argumentlist\b)"
    ),
    "shell_string_call": _rx(
        r"\b(?:os\.(?:system|popen)\s*\(|(?:exec|execSync|execAsync)\s*\(\s*[`'\"]|"
        r"subprocess\.(?:run|call|Popen)\s*\([^\n]{0,500}\bshell\s*=\s*true|"
        r"(?:spawn|spawnSync)\s*\([^\n]{0,500}\bshell\s*:\s*true|"
        r"(?:bash|zsh|sh)\s+-c\b|(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,100}"
        r"(?:-command|-encodedcommand|-enc)\b|cmd(?:\.exe)?\s+/c\b|"
        r"invoke-expression\b|\biex\b)"
    ),
    "fixed_executable": _rx(
        r"\b(?:subprocess\.(?:run|call|Popen|check_call|check_output)\s*\(\s*[\[(]?\s*['\"]"
        r"[a-z0-9_.+/-]+['\"]|(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*['\"]"
        r"[a-z0-9_.+/-]+['\"]|(?:exec|execSync|execAsync)\s*\(\s*[`'\"]"
        r"[a-z0-9_.+/-]+\b|exec\.command\s*\(\s*['\"]|command::new\s*\(\s*['\"]|"
        r"new\s+processbuilder\s*\(\s*['\"])"
    ),
    "dynamic_executable": _rx(
        r"\b(?:subprocess\.(?:run|call|Popen|check_call|check_output)\s*\(\s*(?:[\[(]\s*)?"
        r"[a-z_]\w*\s*[,)]|"
        r"(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*[a-z_$]\w*\s*[,)]|"
        r"start-process\s+\$[a-z_]\w*)"
    ),
    "shell_explicitly_disabled": _rx(
        r"\bshell\s*=\s*false\b|\bshell\s*:\s*false\b|reject(?:s|ed|ing)?\s+shell\s*=\s*true"
    ),
    "stdin_channel": _rx(
        r"\.stdin\.write\s*\(|\binput\s*=\s*[^,\n)]+|communicate\s*\([^)]|"
        r"\bprocess\.stdin\b|\bsys\.stdin\b"
    ),
    "user_input_source": _rx(
        r"\b(?:sys\.argv|argparse\.|input\s*\(|process\.argv|process\.stdin|sys\.stdin|"
        r"req\.(?:body|query|params)|request\.(?:json|args|form)|tool[_ -]?input|user[_ -]?input)|"
        r"(?:\$\{?[1-9@*]\}?\b|\bgetopts\b)"
    ),
    "environment_source": _rx(
        r"\b(?:os\.environ|os\.getenv\s*\(|process\.env|system\.getenv\s*\(|getenv\s*\()|\$env:"
    ),
    "file_source": _rx(
        r"\b(?:fs\.readFile(?:Sync)?\s*\(|fs\.promises\.readFile\s*\(|"
        r"\.read_(?:text|bytes)\s*\(|open\s*\([^\n]{0,180}\)\.read\s*\(|"
        r"get-content\b|cat\s+[\"'$a-z0-9_./-])"
    ),
    "sanitization_guard": _rx(
        r"\b(?:saniti[sz](?:e|er|ation)|allowlist|whitelist|blocklist|denylist|"
        r"shlex\.(?:quote|split)|shell-quote|escapeShellArg|reject(?:s|ed|ing)?\s+shell\s*=\s*true|"
        r"illegal\s+(?:argument|character)|command\s+injection\s+(?:is\s+)?blocked)\b"
    ),
    "security_test_marker": _rx(
        r"\b(?:pytest|unittest|describe\s*\(|it\s*\(|test[_ -]fixture|test[_ -]payload|"
        r"security[_ -](?:test|validation)|dangerous[_ -]inputs?|"
        r"for\s+testing\s+only|not\s+for\s+malicious\s+purposes|def\s+test_)\b"
    ),
    "read_only_system_command": _rx(
        r"(?:^|[\s`'\";&|])(?:top\b|free\b|df\s+-[a-z]*h?\b|docker\s+ps\b|"
        r"ps\s+(?:aux|-ef)\b|whoami\b|uname\b|systeminfo\b|get-process\b|"
        r"get-ciminstance\b|netstat\b|ss\s+-[a-z]+\b)"
    ),
    "download_command": _rx(
        r"(?:^|[\s`'\";&|])(?:curl\b|wget\b|invoke-webrequest\b|invoke-restmethod\b|\biwr\b|\birm\b)"
    ),
    "destructive_command": _rx(
        r"(?:\brm\s+-[^\n]{0,15}[rR][fF]?\b|\bshred\b|\bmkfs(?:\.[a-z0-9]+)?\b|"
        r"\bdd\s+[^\n]{0,100}\bof\s*=|remove-item\b[^\n]{0,120}-recurse\b|"
        r"\bdel\s+/[fq]\b|\bformat\s+[a-z]:)"
    ),
    "privileged_command": _rx(
        r"(?:^|[\s`'\";&|])(?:sudo\b|su\s+-c\b|runas\b|doas\b)|"
        r"start-process\b[^\n]{0,160}-verb\s+runas\b"
    ),
    "persistence_command": _rx(
        r"\b(?:schtasks\b[^\n]{0,120}/create\b|crontab\b|systemctl\s+enable\b|"
        r"sc(?:\.exe)?\s+create\b|reg(?:\.exe)?\s+add\b[^\n]{0,200}"
        r"\\currentversion\\run|launchctl\s+load\b)"
    ),
    "package_install_command": _rx(
        r"(?:^|[\s`'\";&|])(?:pip3?\s+install\b|npm\s+(?:install|i)\b|pnpm\s+(?:add|install)\b|"
        r"yarn\s+add\b|apt(?:-get)?\s+install\b|yum\s+install\b|dnf\s+install\b|"
        r"brew\s+install\b|choco\s+install\b)"
    ),
    "business_tool_command": _rx(
        r"(?:^|[\s`'\";&|])(?:ffmpeg\b|ffprobe\b|whisper\b|yt-dlp\b|git\b|bc\b|"
        r"python3?\b|node\b|docker\s+ps\b)"
    ),
    "quoted_shell_variable": _rx(r"[\"']\$\{?[A-Z_][A-Z0-9_]*\}?[\"']"),
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
            raise ValueError("Skill text exceeds the bounded command-context limit")
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


def _declarations(documents: list[TextDocument]) -> set[str]:
    skill_text = "\n".join(
        document.text for document in documents
        if document.relative_path.casefold() == "skill.md"
    )
    return {
        name for name, pattern in DECLARATION_PATTERNS.items() if pattern.search(skill_text)
    }


def _is_test_fixture(document: TextDocument) -> bool:
    normalized = "/" + document.relative_path.casefold().replace("\\", "/")
    path_marker = (
        "/tests/" in normalized
        or normalized.rsplit("/", 1)[-1].startswith(("test_", "test-"))
        or normalized.rsplit("/", 1)[-1].endswith(("_test.py", ".test.js", ".spec.js"))
    )
    return path_marker or bool(FEATURE_PATTERNS["security_test_marker"].search(document.text))


def _collect_hits(
    documents: list[TextDocument],
) -> tuple[
    dict[str, list[FeatureHit]],
    dict[str, dict[str, list[FeatureHit]]],
    set[str],
]:
    feature_hits: dict[str, list[FeatureHit]] = {name: [] for name in FEATURE_PATTERNS}
    per_document: dict[str, dict[str, list[FeatureHit]]] = {}
    test_documents: set[str] = set()
    total_hits = 0
    for document in documents:
        current: dict[str, list[FeatureHit]] = {name: [] for name in FEATURE_PATTERNS}
        if document.suffix in DOCUMENT_EXTENSIONS:
            per_document[document.relative_path] = current
            continue
        if _is_test_fixture(document):
            test_documents.add(document.relative_path)
        if document.suffix in SHELL_EXTENSIONS and document.text.strip():
            for feature in ("process_call", "shell_script"):
                hit = FeatureHit(feature, document.relative_path, 1)
                current[feature].append(hit)
                feature_hits[feature].append(hit)
                total_hits += 1
        for name, pattern in FEATURE_PATTERNS.items():
            if total_hits >= MAX_FEATURE_HITS:
                break
            if len(feature_hits[name]) >= MAX_HITS_PER_FEATURE:
                continue
            for match in pattern.finditer(document.text):
                hit = FeatureHit(
                    feature=name,
                    relative_path=document.relative_path,
                    line=_line_number(document.text, match.start()),
                )
                current[name].append(hit)
                feature_hits[name].append(hit)
                total_hits += 1
                if (
                    total_hits >= MAX_FEATURE_HITS
                    or len(feature_hits[name]) >= MAX_HITS_PER_FEATURE
                ):
                    break
        per_document[document.relative_path] = current
    return feature_hits, per_document, test_documents


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


def _paths(hits: Iterable[FeatureHit]) -> list[str]:
    return sorted({hit.relative_path for hit in hits})


def _non_test(hits: list[FeatureHit], test_documents: set[str]) -> list[FeatureHit]:
    return [hit for hit in hits if hit.relative_path not in test_documents]


def _test_only(hits: list[FeatureHit], test_documents: set[str]) -> list[FeatureHit]:
    return [hit for hit in hits if hit.relative_path in test_documents]


def _cisco_command_rule_ids(findings: list[dict[str, Any]]) -> list[str]:
    markers = (
        "COMMAND", "EXEC", "SHELL", "BASH", "ALLOWED_TOOLS", "INJECTION", "YARA",
    )
    rule_ids: set[str] = set()
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        category = str(finding.get("category") or "")
        if any(marker in rule_id.upper() for marker in markers) or category in {
            "command_injection", "code_execution", "unauthorized_tool_use",
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
    evidence = (
        f"context_features={','.join(normalized_codes)}; "
        f"files={','.join(normalized_paths[:12])}; "
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


def analyze_command_context(
    skill_root: Path,
    cisco_findings: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Add INFO-only command context without changing admission decisions."""
    documents = _read_documents(skill_root)
    declarations = _declarations(documents)
    cisco_rule_ids = _cisco_command_rule_ids(cisco_findings or [])
    feature_hits, per_document, test_documents = _collect_hits(documents)
    findings: list[dict[str, Any]] = []

    process_calls = feature_hits["process_call"]
    process_imports = feature_hits["process_import"]
    fixture_markers = _test_only(feature_hits["security_test_marker"], test_documents)
    has_context_subject = bool(process_calls or process_imports or fixture_markers)
    if not has_context_subject:
        if "command_declared" in declarations and cisco_rule_ids:
            findings.append(_finding(
                rule_id="AEGIS_CONTEXT_COMMAND_CAPABILITY_DECLARED_NO_DIRECT_PRIMITIVE",
                title="Command capability is declared, but no direct process primitive was recognized",
                category="command_context_support",
                paths=["SKILL.md"],
                line=None,
                evidence_codes=["command_declared", "cisco_command_finding_present", "direct_process_primitive_not_observed"],
                cisco_rule_ids=cisco_rule_ids,
                description="The Skill describes command use and Cisco reported command-related risk, while this layer did not recognize a direct process primitive; a wrapper or prompt-only workflow may be involved.",
                remediation="Review the Cisco location and any wrapper before treating the declaration as sufficient justification.",
            ))
        ordered = sorted(findings, key=lambda item: (item["rule_id"] or "", item["id"]))
        return ordered, [ANALYZER_ID]

    behavior_paths = _paths(process_calls)
    if process_calls:
        if "command_declared" in declarations:
            findings.append(_finding(
                rule_id="AEGIS_CONTEXT_COMMAND_CAPABILITY_DECLARED",
                title="Command or process capability is declared by the Skill",
                category="command_context_support",
                paths=["SKILL.md", *behavior_paths],
                line=None,
                evidence_codes=["command_declared", "process_behavior_observed"],
                cisco_rule_ids=cisco_rule_ids,
                description="The top-level Skill documentation describes command, tool, script, or process use and source files contain process behavior.",
                remediation="Keep executable allowlists, argument schemas, shell mode, privilege, timeout, and output handling explicit.",
            ))
        else:
            findings.append(_finding(
                rule_id="AEGIS_CONTEXT_COMMAND_BEHAVIOR_UNDECLARED",
                title="Observed command or process behavior is not explicitly declared",
                category="command_context_review",
                paths=behavior_paths,
                line=None,
                evidence_codes=["process_behavior_observed", "command_declaration_absent"],
                cisco_rule_ids=cisco_rule_ids,
                description="Process behavior was observed, but no explicit command, tool, script, or shell declaration was found in the top-level SKILL.md.",
                remediation="Declare approved executables, argument sources, shell mode, privilege, side effects, timeout, and failure handling.",
            ))

    if process_imports and not process_calls:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_PROCESS_API_IMPORTED_WITHOUT_CALL",
            title="Process API is imported, but no invocation was recognized",
            category="command_context_support",
            paths=_paths(process_imports),
            line=min(hit.line for hit in process_imports),
            evidence_codes=["process_import", "process_call_not_observed", "dead_or_unused_import_possible"],
            cisco_rule_ids=cisco_rule_ids,
            description="A process-execution module is imported, but this layer found no supported invocation; the import may be unused or invoked through an unrecognized wrapper.",
            remediation="Remove unused process imports or review indirect wrappers before changing the Cisco finding.",
        ))

    if test_documents and (fixture_markers or cisco_rule_ids):
        fixture_paths = sorted(test_documents)
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_SECURITY_TEST_FIXTURE",
            title="Command or injection indicators occur in a security test fixture",
            category="security_test_context",
            paths=fixture_paths,
            line=None,
            evidence_codes=["security_test_fixture", "test_intent_observed", "fixture_safety_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="Test paths or explicit security-validation markers surround command or injection indicators; static context does not prove that the fixture is harmless or never executed in production.",
            remediation="Exclude test fixtures from production packages where possible and verify that payload strings are never passed to a real execution sink.",
        ))
        danger_names = (
            "download_command", "destructive_command", "privileged_command",
            "persistence_command", "package_install_command",
        )
        fixture_danger = [
            hit for name in danger_names for hit in _test_only(feature_hits[name], test_documents)
        ]
        if fixture_danger:
            findings.append(_finding(
                rule_id="AEGIS_CONTEXT_DANGEROUS_COMMAND_TEXT_IN_TEST_FIXTURE",
                title="Dangerous command text appears inside a test fixture",
                category="security_test_context",
                paths=_paths(fixture_danger),
                line=None,
                evidence_codes=["dangerous_command_text", "security_test_fixture", "execution_not_proven"],
                cisco_rule_ids=cisco_rule_ids,
                description="Dangerous command strings occur in files classified as tests; their presence is not equivalent to an executed command.",
                remediation="Keep payloads inert, assert rejection before any process call, and prevent test files from shipping to production.",
            ))

    if feature_hits["argv_call"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_ARGUMENT_VECTOR_PROCESS_CALL",
            title="Process call uses an argument-vector form",
            category="command_invocation_context",
            paths=_paths(feature_hits["argv_call"]),
            line=min(hit.line for hit in feature_hits["argv_call"]),
            evidence_codes=["argument_vector_call", "shell_interpretation_not_implied"],
            cisco_rule_ids=cisco_rule_ids,
            description="A recognized process call passes an argument list or uses an API designed for separate executable and arguments; this reduces but does not eliminate injection risk.",
            remediation="Keep the executable fixed, validate every argument, avoid shell mode, and enforce timeouts and resource limits.",
        ))

    if feature_hits["shell_string_call"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_SHELL_STRING_PROCESS_CALL",
            title="Process call uses shell or command-string interpretation",
            category="command_invocation_context",
            paths=_paths(feature_hits["shell_string_call"]),
            line=min(hit.line for hit in feature_hits["shell_string_call"]),
            evidence_codes=["shell_string_call", "argument_data_flow_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="A shell-enabled or command-string process API was recognized; static context does not prove whether untrusted data enters the command.",
            remediation="Prefer a fixed executable plus argument vector; otherwise enforce strict allowlists and prove untrusted data cannot reach shell syntax.",
        ))

    if feature_hits["shell_script"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_SHELL_SCRIPT_WORKFLOW",
            title="Skill contains a shell-script workflow",
            category="command_invocation_context",
            paths=_paths(feature_hits["shell_script"]),
            line=1,
            evidence_codes=["shell_script", "command_reachability_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="A shell-family script is packaged with the Skill; script presence does not prove that every command is reachable or invoked with untrusted input.",
            remediation="Review variable quoting, option injection, pipelines, temporary files, privileges, cleanup, and every external executable used by the script.",
        ))

    if feature_hits["fixed_executable"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_FIXED_EXECUTABLE_PROCESS_CALL",
            title="Process call names a fixed executable or command prefix",
            category="command_invocation_context",
            paths=_paths(feature_hits["fixed_executable"]),
            line=min(hit.line for hit in feature_hits["fixed_executable"]),
            evidence_codes=["fixed_executable", "runtime_resolution_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="A literal executable or command prefix was recognized; PATH resolution, wrappers, aliases, and later string construction are not proven safe.",
            remediation="Resolve an approved absolute executable, verify integrity, and validate every argument independently.",
        ))

    if feature_hits["dynamic_executable"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_DYNAMIC_EXECUTABLE_PROCESS_CALL",
            title="Process executable appears dynamically selected",
            category="command_invocation_context",
            paths=_paths(feature_hits["dynamic_executable"]),
            line=min(hit.line for hit in feature_hits["dynamic_executable"]),
            evidence_codes=["dynamic_executable", "source_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="The executable argument appears variable rather than a fixed literal; its source and allowed values are not proven.",
            remediation="Map a closed set of business operations to approved executable paths instead of accepting executable names from input.",
        ))

    if feature_hits["stdin_channel"] and process_calls:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_COMMAND_INPUT_VIA_STDIN",
            title="Data is supplied to a process through standard input",
            category="command_input_context",
            paths=_paths(feature_hits["stdin_channel"] + process_calls),
            line=None,
            evidence_codes=["stdin_channel", "process_call", "exact_data_flow_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="A process call and standard-input channel are present; stdin avoids shell tokenization but the child program may still interpret its own language.",
            remediation="Validate input against the child tool's grammar, bound size and runtime, and isolate the process where expressions or scripts are accepted.",
        ))

    source_rule_map = {
        "user_input_source": (
            "AEGIS_CONTEXT_USER_INPUT_NEAR_PROCESS_CALL",
            "User-input and process-call indicators are correlated",
        ),
        "environment_source": (
            "AEGIS_CONTEXT_ENVIRONMENT_INPUT_NEAR_PROCESS_CALL",
            "Environment-source and process-call indicators are correlated",
        ),
        "file_source": (
            "AEGIS_CONTEXT_FILE_INPUT_NEAR_PROCESS_CALL",
            "File-source and process-call indicators are correlated",
        ),
    }
    for source_name, (rule_id, title) in source_rule_map.items():
        correlated: list[FeatureHit] = []
        for document in documents:
            current = per_document[document.relative_path]
            if _nearby(current[source_name], current["process_call"]):
                correlated.extend(current[source_name] + current["process_call"])
        if correlated:
            findings.append(_finding(
                rule_id=rule_id,
                title=title,
                category="command_input_context",
                paths=_paths(correlated),
                line=None,
                evidence_codes=[source_name, "process_call", "data_flow_not_proven"],
                cisco_rule_ids=cisco_rule_ids,
                description="Source and process-call indicators occur within bounded same-file windows; exact variable flow into executable or arguments is not proven.",
                remediation="Trace values into executable, arguments, stdin, environment, and working directory before changing admission policy.",
            ))

    if feature_hits["sanitization_guard"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_COMMAND_SANITIZATION_GUARD",
            title="Command-input validation or sanitization guard is present",
            category="command_context_support",
            paths=_paths(feature_hits["sanitization_guard"]),
            line=None,
            evidence_codes=["sanitization_guard", "guard_correctness_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="Allowlist, blocklist, quoting, or explicit shell rejection syntax was recognized; static matching does not prove completeness or correct placement.",
            remediation="Prefer typed argument schemas and allowlists; test separators, substitutions, encodings, Unicode, nested interpreters, and platform differences.",
        ))

    if feature_hits["read_only_system_command"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_READ_ONLY_SYSTEM_COMMAND",
            title="Recognized system commands are read-oriented",
            category="command_business_context",
            paths=_paths(feature_hits["read_only_system_command"]),
            line=None,
            evidence_codes=[
                "read_only_system_command",
                *(("read_only_declared",) if "read_only_declared" in declarations else ()),
                "side_effect_absence_not_proven",
            ],
            cisco_rule_ids=cisco_rule_ids,
            description="Known status or monitoring commands were recognized; wrappers, aliases, PATH resolution, and surrounding shell operators may still add side effects.",
            remediation="Use absolute approved binaries, least privilege, fixed arguments, output limits, and no shell where possible.",
        ))

    danger_rules = {
        "download_command": (
            "AEGIS_CONTEXT_DOWNLOAD_COMMAND_PRESENT",
            "Download-capable command is present",
            "Review destination, integrity verification, and whether downloaded content reaches an execution sink.",
        ),
        "destructive_command": (
            "AEGIS_CONTEXT_DESTRUCTIVE_COMMAND_PRESENT",
            "Destructive command is present",
            "Require explicit intent, approved targets, dry-run or confirmation, and recoverable rollback.",
        ),
        "privileged_command": (
            "AEGIS_CONTEXT_PRIVILEGED_COMMAND_PRESENT",
            "Privileged command is present",
            "Require least privilege, change approval, isolated execution, and complete audit evidence.",
        ),
        "persistence_command": (
            "AEGIS_CONTEXT_PERSISTENCE_COMMAND_PRESENT",
            "Persistence-related command is present",
            "Cross-check Aegis Static persistence findings and require signed deployment plus rollback.",
        ),
        "package_install_command": (
            "AEGIS_CONTEXT_PACKAGE_INSTALL_COMMAND_PRESENT",
            "Package-install command is present",
            "Require pinned versions, approved registries, integrity verification, and isolated build environments.",
        ),
    }
    for feature, (rule_id, title, remediation) in danger_rules.items():
        actual_hits = _non_test(feature_hits[feature], test_documents)
        if actual_hits:
            findings.append(_finding(
                rule_id=rule_id,
                title=title,
                category="dangerous_command_context",
                paths=_paths(actual_hits),
                line=min(hit.line for hit in actual_hits),
                evidence_codes=[feature, "execution_context_not_proven"],
                cisco_rule_ids=cisco_rule_ids,
                description="A command associated with elevated side effects was recognized outside files classified as tests; actual runtime reachability and arguments are not proven.",
                remediation=remediation,
            ))

    if feature_hits["business_tool_command"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_NAMED_BUSINESS_TOOL_COMMAND",
            title="Named business or workflow tool is present",
            category="command_business_context",
            paths=_paths(feature_hits["business_tool_command"]),
            line=None,
            evidence_codes=["named_business_tool", "tool_safety_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="A named CLI tool such as a runtime, media utility, calculator, VCS, or monitoring command was recognized; naming a tool does not prove arguments or binary resolution are safe.",
            remediation="Maintain an executable allowlist with absolute paths, integrity metadata, argument schemas, timeouts, and resource limits.",
        ))

    quoted_shell_hits: list[FeatureHit] = []
    for document in documents:
        current = per_document[document.relative_path]
        if current["shell_script"]:
            quoted_shell_hits.extend(current["quoted_shell_variable"])
        elif _nearby(current["quoted_shell_variable"], current["shell_string_call"]):
            quoted_shell_hits.extend(current["quoted_shell_variable"])

    if quoted_shell_hits:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_QUOTED_SHELL_VARIABLE",
            title="Shell variables are quoted in command arguments",
            category="command_context_support",
            paths=_paths(quoted_shell_hits),
            line=None,
            evidence_codes=["quoted_shell_variable", "complete_shell_safety_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="Quoted shell-variable use was recognized; quoting reduces word splitting and globbing but does not make all interpreter contexts safe.",
            remediation="Keep variables quoted, avoid eval and nested shells, validate option-like inputs, and use argument-vector APIs where possible.",
        ))

    unique = {finding["id"]: finding for finding in findings}
    ordered = sorted(unique.values(), key=lambda item: (item["rule_id"] or "", item["id"]))
    if any(item["severity"] != "INFO" for item in ordered):
        raise RuntimeError("Command context analyzer emitted a policy-changing severity")
    return ordered, [ANALYZER_ID]
