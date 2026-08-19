from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-filesystem-context-v1"
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


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


DECLARATION_PATTERNS = {
    "filesystem_declared": _rx(
        r"\b(?:files?|folders?|directories|paths?|filesystem|workspace|local disk|"
        r"data director(?:y|ies)|output director(?:y|ies)|temporary director(?:y|ies))\b|"
        r"(?:文件|目录|路径|文件系统|工作区|本地磁盘|数据目录|输出目录|临时目录)"
    ),
    "read_declared": _rx(
        r"\b(?:read(?:s|ing)?|load(?:s|ed|ing)?|open(?:s|ed|ing)?|inspect(?:s|ed|ing)?|"
        r"parse(?:s|d|ing)?|import(?:s|ed|ing)?|upload(?:s|ed|ing)?)\b[^\n]{0,80}"
        r"\b(?:files?|folders?|directories|paths?|data)\b|"
        r"\b(?:files?|data)\b[^\n]{0,80}\b(?:is |are |be )?(?:read|loaded|opened|parsed|imported|uploaded)\b|"
        r"(?:读取|加载|打开|解析|导入|上传)[^\n]{0,30}(?:文件|目录|路径|数据)"
    ),
    "write_declared": _rx(
        r"\b(?:write(?:s|writing)?|save(?:s|d|saving)?|export(?:s|ed|ing)?|output(?:s|ted|ting)?|"
        r"generate(?:s|d|ing)?|create(?:s|d|ing)?|append(?:s|ed|ing)?|update(?:s|d|ing)?|"
        r"store(?:s|d|ing)?)\b[^\n]{0,80}\b(?:files?|folders?|directories|paths?|outputs?|"
        r"data|images?|reports?|results?|config(?:uration)?)\b|"
        r"\b(?:files?|outputs?|data|images?|reports?|results?|config(?:uration)?)\b[^\n]{0,80}"
        r"\b(?:is |are |be )?(?:written|saved|exported|generated|created|appended|updated|stored)\b|"
        r"(?:写入|保存|导出|输出|生成|创建|追加|更新|存储)[^\n]{0,30}"
        r"(?:文件|目录|路径|数据|图片|报告|结果)"
    ),
    "destructive_declared": _rx(
        r"\b(?:delete(?:s|d|ing)?|remove(?:s|d|ing)?|unlink(?:s|ed|ing)?|clear(?:s|ed|ing)?|"
        r"purge(?:s|d|ing)?|overwrite(?:s|writing)?|replace(?:s|d|ing)?)[^\n]{0,50}"
        r"(?:file|folder|directory|path|data|output)\b|"
        r"(?:删除|移除|清理|清空|覆盖|替换)[^\n]{0,24}(?:文件|目录|路径|数据|输出)"
    ),
    "sensitive_path_declared": _rx(
        r"\b(?:credential|secret|private key|wallet|cookie|auth(?:entication)? data|token file|"
        r"password file|resume|user profile)[^\n]{0,40}(?:file|folder|directory|path|data)?\b|"
        r"(?:凭据|密钥|私钥|钱包|Cookie|认证数据|令牌文件|密码文件|简历|用户资料)"
    ),
    "workspace_or_temp_declared": _rx(
        r"\b(?:inside|within|under|in)[^\n]{0,25}(?:skill folder|workspace|working directory|"
        r"temporary directory|temp directory|output directory|data directory)\b|"
        r"\b(?:local file|local output|/tmp/|workspace/|data/)\b|"
        r"(?:技能目录|工作区|工作目录|临时目录|输出目录|数据目录|本地文件|本地输出)"
    ),
}

FEATURE_PATTERNS = {
    "recursive_mutation": _rx(
        r"\b(?:fs\.(?:rm|rmdir)(?:Sync)?\s*\([^\n]{0,300}\brecursive\s*:\s*true|"
        r"shutil\.rmtree\s*\(|(?:rm|chmod|chown)\s+-[^\n]{0,20}r[^\n]*|"
        r"remove-item\b[^\n]{0,160}-recurse\b)"
    ),
    "delete_operation": _rx(
        r"\b(?:fs\.(?:unlink|rm|rmdir)(?:Sync)?\s*\(|fs\.promises\.(?:unlink|rm|rmdir)\s*\(|"
        r"shutil\.rmtree\s*\(|os\.(?:remove|unlink|rmdir)\s*\(|pathlib\.Path\([^\n]{0,160}"
        r"\)\.(?:unlink|rmdir)\s*\(|\.unlink\s*\(|remove-item\b|del\s+/[fq]\b|rm\s+-[^\n]*r)"
    ),
    "file_write": _rx(
        r"\b(?:fs\.(?:writeFile|appendFile|outputFile)(?:Sync)?\s*\(|"
        r"fs\.promises\.(?:writeFile|appendFile)\s*\(|(?:writeFile|appendFile)(?:Sync)?\s*\(|"
        r"createWriteStream\s*\(|(?:pathlib\.)?Path\([^\n]{0,160}\)\.write_(?:text|bytes)\s*\(|"
        r"\.write_(?:text|bytes)\s*\(|(?:file|files)\.writeAll(?:Text|Bytes)\s*\(|"
        r"set-content\b|add-content\b|deno\.write(?:Text)?File\s*\(|"
        r"open\s*\([^\n]{0,180}['\"][wax](?:[bt+])?['\"]\s*\))"
    ),
    "file_read": _rx(
        r"\b(?:fs\.(?:readFile|readFileSync)\s*\(|fs\.promises\.readFile\s*\(|"
        r"readFileSync\s*\(|createReadStream\s*\(|(?:pathlib\.)?Path\([^\n]{0,160}"
        r"\)\.read_(?:text|bytes)\s*\(|\.read_(?:text|bytes)\s*\(|"
        r"(?:file|files)\.readAll(?:Text|Bytes)\s*\(|get-content\b|"
        r"deno\.read(?:Text)?File\s*\(|open\s*\([^\n]{0,180}['\"]r(?:[bt+])?['\"]\s*\))"
    ),
    "path_probe": _rx(
        r"\b(?:fs\.(?:existsSync|statSync|lstatSync|readdirSync|accessSync)\s*\(|"
        r"fs\.promises\.(?:stat|lstat|readdir|access)\s*\(|(?:pathExists|ensureFile)\s*\(|"
        r"os\.(?:listdir|scandir|walk)\s*\(|\.exists\s*\(\)|\.is_(?:file|dir)\s*\(\)|"
        r"get-childitem\b|test-path\b)"
    ),
    "directory_create": _rx(
        r"\b(?:fs\.(?:mkdir|mkdirSync)\s*\(|fs\.promises\.mkdir\s*\(|"
        r"(?:ensureDir|makedirs|mkdir)\s*\(|new-item\b[^\n]{0,100}(?:directory|-itemtype\s+directory))"
    ),
    "workspace_or_temp_path": _rx(
        r"(?:\b__dirname\b|\bprocess\.cwd\s*\(|\bos\.tmpdir\s*\(|\btempfile\.|"
        r"\b(?:baseDir|skillDir|workspaceDir|workingDir|dataDir|outputDir)\b|"
        r"(?:^|['\"`])(?:\./|\.\\|/tmp/|/var/tmp/|data[/\\]|output[/\\]|outputs[/\\]|"
        r"workspace[/\\]|temp[/\\]|tmp[/\\]))"
    ),
    "sensitive_path": _rx(
        r"(?:\.ssh[/\\]|\.aws[/\\]|\.kube[/\\]|\.gnupg[/\\]|\.docker[/\\]config\.json|"
        r"id_rsa\b|known_hosts\b|authorized_keys\b|wallets?(?:\.json|\.dat)?\b|wallet\.dat\b|"
        r"cookies?(?:\.json|\.sqlite)?\b|login data\b|keychain\b|credentials?(?:\.json)?\b|"
        r"passwords?(?:\.json|\.txt)?\b|loggedInData\.json\b|userDetails\.json\b|"
        r"resume\.(?:md|txt|pdf)\b|auth(?:entication)?[-_ ]?data\.json\b)"
    ),
    "system_path": _rx(
        r"(?:/etc/(?:passwd|shadow|sudoers|ssh)|/root/|/boot/|/usr/(?:bin|sbin)/|"
        r"\\windows\\system32\\|\\programdata\\|/library/launch(?:agents|daemons)/)"
    ),
    "path_containment_guard": _rx(
        r"(?:\.startsWith\s*\([^\n]{0,180}(?:path\.sep|resolved?|base|root)|"
        r"\.is_relative_to\s*\(|commonpath\s*\([^\n]{0,180}\)|"
        r"resolve\s*\([^\n]{0,180}\)[^\n]{0,220}(?:startsWith|relative|commonpath))"
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
            raise ValueError("Skill text exceeds the bounded filesystem-context limit")
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


def _collect_hits(
    documents: list[TextDocument],
) -> tuple[dict[str, list[FeatureHit]], dict[str, dict[str, list[FeatureHit]]]]:
    feature_hits: dict[str, list[FeatureHit]] = {name: [] for name in FEATURE_PATTERNS}
    per_document: dict[str, dict[str, list[FeatureHit]]] = {}
    total_hits = 0
    for document in documents:
        current: dict[str, list[FeatureHit]] = {name: [] for name in FEATURE_PATTERNS}
        if document.suffix in {".md", ".txt"}:
            per_document[document.relative_path] = current
            continue
        for name, pattern in FEATURE_PATTERNS.items():
            if total_hits >= MAX_FEATURE_HITS:
                break
            for match in pattern.finditer(document.text):
                hit = FeatureHit(
                    feature=name,
                    relative_path=document.relative_path,
                    line=_line_number(document.text, match.start()),
                )
                current[name].append(hit)
                feature_hits[name].append(hit)
                total_hits += 1
                if total_hits >= MAX_FEATURE_HITS:
                    break
        per_document[document.relative_path] = current
    return feature_hits, per_document


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


def _cisco_filesystem_rule_ids(findings: list[dict[str, Any]]) -> list[str]:
    rule_ids: set[str] = set()
    markers = ("FS_ACCESS", "FILESYSTEM", "FILE_ACCESS", "FILE_READ", "FILE_WRITE", "PATH_TRAVERSAL")
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if any(marker in rule_id.upper() for marker in markers):
            rule_ids.add(rule_id or str(finding.get("id") or "unidentified"))
    return sorted(rule_ids)


def _paths(hits: Iterable[FeatureHit]) -> list[str]:
    return sorted({hit.relative_path for hit in hits})


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


def analyze_filesystem_context(
    skill_root: Path,
    cisco_findings: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Add INFO-only filesystem context without changing admission decisions."""
    documents = _read_documents(skill_root)
    declarations = _declarations(documents)
    cisco_rule_ids = _cisco_filesystem_rule_ids(cisco_findings or [])
    feature_hits, per_document = _collect_hits(documents)

    behavior_names = (
        "file_read", "file_write", "path_probe", "directory_create",
        "delete_operation", "recursive_mutation",
    )
    behavior_hits = [hit for name in behavior_names for hit in feature_hits[name]]
    findings: list[dict[str, Any]] = []

    if not behavior_hits:
        if "filesystem_declared" in declarations and cisco_rule_ids:
            findings.append(_finding(
                rule_id="AEGIS_CONTEXT_FILESYSTEM_CAPABILITY_DECLARED_NO_DIRECT_PRIMITIVE",
                title="Filesystem capability is declared, but no direct primitive was recognized",
                category="filesystem_context_support",
                paths=["SKILL.md"],
                line=None,
                evidence_codes=[
                    "filesystem_declared", "cisco_filesystem_finding_present",
                    "direct_filesystem_primitive_not_observed",
                ],
                cisco_rule_ids=cisco_rule_ids,
                description="SKILL.md declares file use and Cisco reported filesystem risk, while this context layer did not recognize a direct primitive; an SDK or wrapper may be involved.",
                remediation="Review the Cisco location and wrapper implementation before treating the declaration as sufficient justification.",
            ))
        ordered = sorted(findings, key=lambda item: (item["rule_id"] or "", item["id"]))
        return ordered, [ANALYZER_ID]

    behavior_paths = _paths(behavior_hits)
    if "filesystem_declared" in declarations:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_FILESYSTEM_CAPABILITY_DECLARED",
            title="Filesystem capability is declared by the Skill",
            category="filesystem_context_support",
            paths=["SKILL.md", *behavior_paths],
            line=None,
            evidence_codes=["filesystem_declared", "filesystem_behavior_observed"],
            cisco_rule_ids=cisco_rule_ids,
            description="The Skill documentation describes file use and the implementation contains recognized filesystem behavior.",
            remediation="Keep allowed roots, file types, read/write modes, retention, and user-consent requirements explicit.",
        ))
    else:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_FILESYSTEM_BEHAVIOR_UNDECLARED",
            title="Observed filesystem behavior is not explicitly declared",
            category="filesystem_context_review",
            paths=behavior_paths,
            line=None,
            evidence_codes=["filesystem_behavior_observed", "filesystem_declaration_absent"],
            cisco_rule_ids=cisco_rule_ids,
            description="Filesystem primitives were observed, but no explicit file capability declaration was found in the top-level SKILL.md.",
            remediation="Declare the business purpose, allowed roots, file classes, and read/write/delete modes before admission.",
        ))

    if (feature_hits["file_read"] or feature_hits["path_probe"]) and not (
        feature_hits["file_write"] or feature_hits["delete_operation"]
    ):
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_READ_ONLY_FILESYSTEM_BEHAVIOR",
            title="Observed filesystem behavior is read-oriented",
            category="filesystem_context_support",
            paths=_paths(feature_hits["file_read"] + feature_hits["path_probe"]),
            line=None,
            evidence_codes=["file_read_or_probe", "file_write_or_delete_absent"],
            cisco_rule_ids=cisco_rule_ids,
            description="Recognized operations are read or metadata probes; no supported write or delete primitive was found.",
            remediation="Verify path scope and whether read data can reach logs, prompts, network requests, or model context.",
        ))

    if feature_hits["file_write"]:
        write_declared = "write_declared" in declarations
        findings.append(_finding(
            rule_id=(
                "AEGIS_CONTEXT_FILE_WRITE_BEHAVIOR_DECLARED"
                if write_declared else "AEGIS_CONTEXT_FILE_WRITE_BEHAVIOR_NOT_EXPLICITLY_DECLARED"
            ),
            title=(
                "File-write behavior is declared by the Skill"
                if write_declared else "File-write behavior lacks an explicit write declaration"
            ),
            category="filesystem_context_support" if write_declared else "filesystem_context_review",
            paths=_paths(feature_hits["file_write"]),
            line=min(hit.line for hit in feature_hits["file_write"]),
            evidence_codes=["file_write", "write_declared" if write_declared else "write_declaration_absent"],
            cisco_rule_ids=cisco_rule_ids,
            description="A write-capable file API was observed and compared with the top-level Skill declaration.",
            remediation="Document allowed destinations, overwrite policy, file permissions, retention, and rollback behavior.",
        ))
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_OVERWRITE_CAPABLE_FILE_WRITE",
            title="Observed file-write API can replace destination contents",
            category="filesystem_mutation_context",
            paths=_paths(feature_hits["file_write"]),
            line=min(hit.line for hit in feature_hits["file_write"]),
            evidence_codes=["file_write", "overwrite_capable_api", "target_binding_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="The recognized write API is overwrite-capable; static pattern matching does not prove which runtime destination is replaced.",
            remediation="Require an approved root, reject symlink escapes, prefer atomic replacement, and preserve rollback where business data may be overwritten.",
        ))

    workspace_context = feature_hits["workspace_or_temp_path"]
    if workspace_context or "workspace_or_temp_declared" in declarations:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_WORKSPACE_OR_TEMP_PATH",
            title="Filesystem use is associated with a workspace, data, output, or temporary path",
            category="filesystem_path_context",
            paths=[
                *(("SKILL.md",) if "workspace_or_temp_declared" in declarations else ()),
                *_paths(workspace_context),
            ],
            line=min((hit.line for hit in workspace_context), default=None),
            evidence_codes=[
                "workspace_or_temp_path",
                "path_binding_not_proven",
                *(("workspace_or_temp_declared",) if "workspace_or_temp_declared" in declarations else ()),
            ],
            cisco_rule_ids=cisco_rule_ids,
            description="Workspace, data-directory, output-directory, or temporary-path indicators were found; exact runtime path binding is not proven.",
            remediation="Constrain resolved paths to an approved per-tenant workspace and reject traversal, absolute-path overrides, and symlink escapes.",
        ))

    sensitive_correlated: list[FeatureHit] = []
    system_correlated: list[FeatureHit] = []
    for document in documents:
        current = per_document[document.relative_path]
        current_behavior = [hit for name in behavior_names for hit in current[name]]
        if current["sensitive_path"] and _nearby(current["sensitive_path"], current_behavior):
            sensitive_correlated.extend(current["sensitive_path"] + current_behavior)
        if current["system_path"] and _nearby(current["system_path"], current_behavior):
            system_correlated.extend(current["system_path"] + current_behavior)

    if sensitive_correlated:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_SENSITIVE_PATH_ACCESS",
            title="Sensitive-path and filesystem-operation indicators are correlated",
            category="sensitive_file_context",
            paths=_paths(sensitive_correlated),
            line=None,
            evidence_codes=[
                "sensitive_path", "filesystem_operation", "path_binding_not_proven",
                *(("sensitive_path_declared",) if "sensitive_path_declared" in declarations else ()),
            ],
            cisco_rule_ids=cisco_rule_ids,
            description="Sensitive-path indicators and filesystem operations occur within bounded per-file windows; exact path binding and data flow are not proven.",
            remediation="Verify least privilege, tenant isolation, user authorization, logging redaction, encryption, and whether sensitive content reaches external sinks.",
        ))
    if system_correlated:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_SYSTEM_PATH_ACCESS",
            title="System-path and filesystem-operation indicators are correlated",
            category="system_file_context",
            paths=_paths(system_correlated),
            line=None,
            evidence_codes=["system_path", "filesystem_operation", "path_binding_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="Protected system-path indicators and filesystem operations occur within bounded per-file windows; exact runtime path binding is not proven.",
            remediation="Deny host-system paths by default and require an isolated, least-privilege exception with audit logging.",
        ))

    if feature_hits["delete_operation"]:
        declared = "destructive_declared" in declarations
        findings.append(_finding(
            rule_id=(
                "AEGIS_CONTEXT_DESTRUCTIVE_FILE_MUTATION_DECLARED"
                if declared else "AEGIS_CONTEXT_DESTRUCTIVE_FILE_MUTATION_NOT_EXPLICITLY_DECLARED"
            ),
            title=(
                "Destructive file mutation is declared by the Skill"
                if declared else "Destructive file mutation lacks an explicit declaration"
            ),
            category="filesystem_mutation_context",
            paths=_paths(feature_hits["delete_operation"]),
            line=min(hit.line for hit in feature_hits["delete_operation"]),
            evidence_codes=["delete_operation", "destructive_declared" if declared else "destructive_declaration_absent"],
            cisco_rule_ids=cisco_rule_ids,
            description="A delete or remove primitive was observed and compared with the top-level Skill declaration.",
            remediation="Require explicit user intent, constrain targets to an approved root, prefer recoverable deletion, and record before/after audit evidence.",
        ))

    if feature_hits["recursive_mutation"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_RECURSIVE_FILESYSTEM_MUTATION",
            title="Recursive filesystem mutation primitive is present",
            category="filesystem_mutation_context",
            paths=_paths(feature_hits["recursive_mutation"]),
            line=min(hit.line for hit in feature_hits["recursive_mutation"]),
            evidence_codes=["recursive_mutation", "runtime_scope_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="A recursive delete or permission/ownership mutation primitive was recognized; runtime target scope is not proven.",
            remediation="Block broad host paths, require a resolved per-tenant root, dry-run or confirmation, quotas, and recoverable rollback.",
        ))

    if feature_hits["path_containment_guard"]:
        findings.append(_finding(
            rule_id="AEGIS_CONTEXT_PATH_CONTAINMENT_GUARD",
            title="Path-containment guard is present",
            category="filesystem_context_support",
            paths=_paths(feature_hits["path_containment_guard"]),
            line=min(hit.line for hit in feature_hits["path_containment_guard"]),
            evidence_codes=["path_containment_guard", "guard_correctness_not_proven"],
            cisco_rule_ids=cisco_rule_ids,
            description="The implementation appears to validate that a resolved path remains under an allowed root; static matching does not prove the guard is complete.",
            remediation="Test traversal, alternate separators, case normalization, junctions, symlinks, race conditions, and non-existent targets.",
        ))

    unique = {finding["id"]: finding for finding in findings}
    ordered = sorted(unique.values(), key=lambda item: (item["rule_id"] or "", item["id"]))
    if any(item["severity"] != "INFO" for item in ordered):
        raise RuntimeError("Filesystem context analyzer emitted a policy-changing severity")
    return ordered, [ANALYZER_ID]
