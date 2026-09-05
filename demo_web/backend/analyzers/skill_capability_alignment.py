from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any

from ..models import EvidenceSource
from ..normalizers import finding_dict


ANALYZER_ID = "aegis-skill-capability-alignment-v1"
MAX_FILES = 500
MAX_BYTES = 5 * 1024 * 1024
CODE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".ps1", ".bat", ".cmd"}
REFERENCE = re.compile(r"(?<![\w.-])([\w.-]+(?:[/\\][\w.-]+)*\.(?:py|js|mjs|cjs|ts|sh|ps1|bat|cmd))(?![\w.-])", re.I)

DECLARATIONS = {
    "network": re.compile(r"\b(?:network|internet|http|api|webhook|download|upload|联网|网络|接口|下载|上传)\b", re.I),
    "filesystem": re.compile(r"\b(?:file|folder|directory|workspace|read|write|文件|目录|工作区|读取|写入)\b", re.I),
    "process": re.compile(r"\b(?:command|shell|process|script|execute|命令|脚本|进程|执行)\b", re.I),
    "credential": re.compile(r"\b(?:credential|token|secret|api[_ -]?key|凭据|令牌|密钥)\b", re.I),
    "openclaw_control": re.compile(r"\b(?:openclaw|hook|plugin|config|policy|permission|钩子|插件|配置|策略|权限)\b", re.I),
}

IMPLEMENTATIONS = {
    "network": re.compile(r"\b(?:requests\.|urllib|httpx\.|aiohttp|fetch\s*\(|axios\.|https?\.request|curl\b|wget\b)", re.I),
    "filesystem": re.compile(r"\b(?:open\s*\(|readFile|writeFile|read_text|write_text|os\.(?:listdir|walk|remove)|shutil\.|Get-ChildItem|Set-Content)\b", re.I),
    "process": re.compile(r"\b(?:subprocess\.|os\.system|child_process|execSync|spawn\s*\(|powershell\b|bash\s+-c|cmd(?:\.exe)?\s+/c)\b", re.I),
    "credential": re.compile(r"(?:\b(?:api[_ -]?key|access[_ -]?token|password|credential|secret|private[_ -]?key)\b|\.ssh(?:[/\\]|$)|\.aws(?:[/\\]|$)|\.kube(?:[/\\]|$))", re.I),
    "openclaw_control": re.compile(r"(?:\.openclaw|openclaw\.json|installPolicy|hooks?|plugins?|permissions?|audit)(?:[/\\\"'\s.:_-]|$)", re.I),
}

UNDECLARED_RULES = {
    "network": "AEGIS_UNDECLARED_NETWORK_CAPABILITY",
    "filesystem": "AEGIS_UNDECLARED_FILESYSTEM_CAPABILITY",
    "process": "AEGIS_UNDECLARED_PROCESS_CAPABILITY",
    "credential": "AEGIS_UNDECLARED_CREDENTIAL_CAPABILITY",
    "openclaw_control": "AEGIS_UNDECLARED_OPENCLAW_CONTROL_CAPABILITY",
}

OPENCLAW_MUTATION = re.compile(
    r"(?:(?:writeFile|write_text|Set-Content|Add-Content|Out-File|>>|open\s*\([^\n]{0,180}['\"](?:w|a))"
    r"[^\n]{0,400}(?:\.openclaw|openclaw\.json|hooks?|installPolicy|permissions?|audit)|"
    r"(?:\.openclaw|openclaw\.json|hooks?|installPolicy|permissions?|audit)[^\n]{0,400}"
    r"(?:writeFile|write_text|Set-Content|Add-Content|Out-File|>>|open\s*\([^\n]{0,180}['\"](?:w|a)))",
    re.I,
)
CONTROL_BYPASS = re.compile(
    r"(?:disable|skip|bypass|false|off|删除|禁用|跳过|绕过)[^\n]{0,120}"
    r"(?:audit|policy|approval|confirmation|permission|审计|策略|审批|确认|权限)",
    re.I,
)


def _role(relative: str, referenced: set[str]) -> str:
    lower = relative.casefold()
    if relative in referenced:
        return "REFERENCED"
    if any(part in {"test", "tests", "fixtures", "examples", "example", "samples"} for part in PurePosixPath(lower).parts):
        return "TEST" if "test" in lower or "fixture" in lower else "EXAMPLE"
    if lower.startswith("scripts/") or "/bin/" in f"/{lower}":
        return "REACHABLE"
    return "UNKNOWN"


def _finding(rule_id: str, title: str, severity: str, relative: str, role: str, features: set[str]) -> dict[str, Any]:
    identity = f"{rule_id}|{relative}|{role}|{'|'.join(sorted(features))}"
    return finding_dict(
        id=f"{rule_id}_{hashlib.sha256(identity.encode()).hexdigest()[:12]}",
        rule_id=rule_id,
        title=title,
        category="capability_alignment",
        severity=severity,
        analyzer=ANALYZER_ID,
        location={"file": relative},
        evidence=f"features={','.join(sorted(features))}; file_role={role}; raw_content_retained=false",
        description="对比 SKILL.md 的能力声明与可执行文件中的实际实现。",
        remediation="在 SKILL.md 中准确声明能力、数据范围、外部端点和用户确认点，或删除不必要实现。",
        evidence_confidence="CORROBORATED" if role in {"REFERENCED", "REACHABLE"} else "POTENTIAL",
        reachability=role,
        behavior_alignment="UNDECLARED",
        evidence_source=EvidenceSource.AEGIS_STATIC,
    )


def analyze_skill_capability_alignment(skill_root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    manifest = skill_root / "SKILL.md"
    if not manifest.is_file() or manifest.is_symlink():
        return [], [ANALYZER_ID]
    manifest_text = manifest.read_text(encoding="utf-8", errors="replace")
    referenced = {match.group(1).replace("\\", "/") for match in REFERENCE.finditer(manifest_text)}
    declaration_text = REFERENCE.sub(" ", manifest_text)
    declared = {name for name, pattern in DECLARATIONS.items() if pattern.search(declaration_text)}
    findings: list[dict[str, Any]] = []
    total = 0
    inspected = 0
    role_counts: dict[str, int] = {}
    for path in sorted(skill_root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if path.is_symlink() or not path.is_file() or path.suffix.casefold() not in CODE_SUFFIXES:
            continue
        inspected += 1
        if inspected > MAX_FILES:
            break
        size = path.stat().st_size
        if size > 1024 * 1024 or total + size > MAX_BYTES:
            continue
        total += size
        relative = path.relative_to(skill_root).as_posix()
        role = _role(relative, referenced)
        role_counts[role] = role_counts.get(role, 0) + 1
        text = path.read_text(encoding="utf-8", errors="replace")
        actual = {name for name, pattern in IMPLEMENTATIONS.items() if pattern.search(text)}
        undeclared = actual - declared
        if role in {"TEST", "EXAMPLE", "UNKNOWN"}:
            continue
        for capability in sorted(undeclared):
            findings.append(_finding(
                UNDECLARED_RULES[capability],
                f"可执行入口实现了未声明的 {capability} 能力",
                "MEDIUM",
                relative,
                role,
                {f"actual_{capability}", "manifest_declaration_missing"},
            ))
        if "openclaw_control" in actual and OPENCLAW_MUTATION.search(text):
            severity = "HIGH" if CONTROL_BYPASS.search(text) else "MEDIUM"
            findings.append(_finding(
                "AEGIS_OPENCLAW_CONTROL_PLANE_MUTATION",
                "Skill 可执行入口修改 OpenClaw 控制面配置",
                severity,
                relative,
                role,
                {"openclaw_control_target", "write_primitive", "control_bypass" if severity == "HIGH" else "mutation"},
            ))

    summary_identity = f"summary|{inspected}|{sorted(declared)}|{sorted(role_counts.items())}"
    findings.append(finding_dict(
        id=f"AEGIS_CAPABILITY_ALIGNMENT_SUMMARY_{hashlib.sha256(summary_identity.encode()).hexdigest()[:12]}",
        rule_id="AEGIS_CAPABILITY_ALIGNMENT_SUMMARY",
        title="Skill 能力声明与文件角色清单已生成",
        category="capability_inventory",
        severity="INFO",
        analyzer=ANALYZER_ID,
        location={"file": "SKILL.md"},
        evidence=(
            f"declared={','.join(sorted(declared)) or 'none'}; referenced={len(referenced)}; "
            f"code_files={inspected}; roles=" + ",".join(f"{key}:{value}" for key, value in sorted(role_counts.items()))
        ),
        description="该清单用于解释后续规则为何认为某段代码可达及其能力是否已声明。",
        remediation="无需处理；如清单与预期不符，请完善 SKILL.md 的入口和能力说明。",
        evidence_confidence="CONFIRMED",
        reachability="REFERENCED",
        behavior_alignment="DECLARED",
        evidence_source=EvidenceSource.AEGIS_STATIC,
    ))
    return findings, [ANALYZER_ID]
