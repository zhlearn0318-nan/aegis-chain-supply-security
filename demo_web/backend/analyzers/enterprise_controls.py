from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from ..normalizers import finding_dict
from . import sensitive_flow as sensitive_taint
from . import untrusted_exec_flow as input_taint


ANALYZER_ID = "aegis-enterprise-controls-v1"
MAX_FILES = 500
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024
MAX_FINDINGS_PER_RULE_FILE = 4

PYTHON_EXTENSIONS = {".py"}
CODE_CONFIG_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".go", ".rs", ".java", ".rb", ".php", ".pl", ".lua", ".sql",
}

WILDCARD_TOOL_PERMISSION = re.compile(
    r"(?im)^\s*allowed-tools\s*:\s*['\"]?\*['\"]?\s*$"
)
WILDCARD_IAM = re.compile(
    r"(?is)(?:effect\s*['\"]?\s*[:=]\s*['\"]?allow['\"]?).{0,1200}"
    r"(?:action\s*['\"]?\s*[:=]\s*(?:['\"]\*['\"]|\[\s*['\"]\*['\"]\s*\])).{0,1200}"
    r"(?:resource\s*['\"]?\s*[:=]\s*(?:['\"]\*['\"]|\[\s*['\"]\*['\"]\s*\]))"
)
WILDCARD_K8S = re.compile(
    r"(?is)(?:verbs\s*:\s*\[?\s*['\"]?\*['\"]?\s*\]?).{0,800}"
    r"(?:resources\s*:\s*\[?\s*['\"]?\*['\"]?\s*\]?)|"
    r"(?:resources\s*:\s*\[?\s*['\"]?\*['\"]?\s*\]?).{0,800}"
    r"(?:verbs\s*:\s*\[?\s*['\"]?\*['\"]?\s*\]?)"
)
WILDCARD_SUDO = re.compile(
    r"(?im)^\s*[^#\r\n]+\s+ALL\s*=\s*\(ALL(?::ALL)?\)\s*(?:NOPASSWD\s*:\s*)?ALL\s*$"
)
PRIVILEGED_CONTAINER = re.compile(
    r"(?is)(?:privileged\s*:\s*true.{0,800}(?:hostpath\s*:|/var/run/docker\.sock|hostpid\s*:\s*true|hostnetwork\s*:\s*true)|"
    r"(?:hostpath\s*:|/var/run/docker\.sock|hostpid\s*:\s*true|hostnetwork\s*:\s*true).{0,800}privileged\s*:\s*true)"
)

SECURITY_CONTROL_DISABLE = re.compile(
    r"(?i)(?:\bufw\s+disable\b|\bsetenforce\s+0\b|"
    r"set-mppreference\b[^\r\n]{0,240}-disablerealtimemonitoring\s+\$?true|"
    r"netsh\b[^\r\n]{0,240}advfirewall\b[^\r\n]{0,240}state\s+off|"
    r"systemctl\b[^\r\n]{0,160}\b(?:stop|disable|mask)\b[^\r\n]{0,160}\b(?:auditd|firewalld|falcon-sensor|mdatp|osqueryd)\b|"
    r"\bsc(?:\.exe)?\s+(?:stop|config)\s+(?:windefend|sense)\b)"
)
AUDIT_LOG_CLEAR = re.compile(
    r"(?i)(?:\bwevtutil\s+cl\b|\bclear-eventlog\b|\bauditctl\s+-D\b|"
    r"journalctl\b[^\r\n]{0,160}--vacuum-(?:time|size)\s*=\s*(?:0|1s|1K)\b|"
    r"(?:truncate\s+-s\s+0|rm\s+-[a-z]*f[a-z]*)\s+[^\r\n]{0,160}/var/log/(?:audit/)?[^\s]+)"
)
TLS_DISABLED = re.compile(
    r"(?i)(?:\bverify\s*=\s*false\b|ssl\._create_unverified_context\s*\(|"
    r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*['\"]?\s*[:=]\s*['\"]?0|"
    r"\bcurl\b[^\r\n]{0,160}\s(?:-k|--insecure)\b)"
)
CLOUD_METADATA = re.compile(
    r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)"
    r"[^\r\n]{0,300}(?:meta-data|instance/service-accounts|security-credentials|latest/api/token)?"
)
SHELL_DESTRUCTIVE = re.compile(
    r"(?i)(?:\brm\s+-[a-z]*r[a-z]*f[a-z]*\b|\brm\s+-[a-z]*f[a-z]*r[a-z]*\b|"
    r"remove-item\b[^\r\n]{0,200}-recurse\b[^\r\n]{0,120}-force\b|"
    r"\b(?:mkfs(?:\.[a-z0-9]+)?|format\.com)\b|"
    r"\b(?:drop\s+(?:database|schema)|truncate\s+table)\b)"
)
DESTRUCTIVE_GUARD = re.compile(
    r"(?i)(?:confirm(?:ation|ed)?|dry[_-]?run|--(?:reset|delete|purge|clean)|"
    r"read\s+-p|prompt|backup|is_relative_to|commonpath|containment|allowed[_-]?root)"
)


@dataclass(frozen=True)
class TextDocument:
    relative_path: str
    suffix: str
    text: str


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    severity: str
    category: str
    relative_path: str
    line: int
    evidence_codes: tuple[str, ...]


def _inside(root: Path, candidate: Path) -> bool:
    return candidate == root or root in candidate.parents


def _is_test_document(relative_path: str) -> bool:
    path = Path(relative_path)
    parts = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    return bool(
        parts & {"test", "tests", "fixtures", "__tests__"}
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
    )


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
        if path.name != "SKILL.md" and suffix not in CODE_CONFIG_EXTENSIONS:
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            continue
        if total_bytes + size > MAX_TOTAL_BYTES:
            raise ValueError("Skill text exceeds the bounded enterprise-control analysis limit")
        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            continue
        total_bytes += size
        relative = resolved.relative_to(root).as_posix()
        if _is_test_document(relative):
            continue
        documents.append(TextDocument(
            relative_path=relative,
            suffix=suffix,
            text=data.decode("utf-8", errors="replace"),
        ))
    return documents


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _non_comment_code(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "/*", "*", "<!--")):
            lines.append("")
        else:
            lines.append(line)
    return "\n".join(lines)


def _append_regex_hits(
    hits: list[RuleHit],
    document: TextDocument,
    pattern: re.Pattern[str],
    *,
    rule_id: str,
    severity: str,
    category: str,
    evidence_codes: tuple[str, ...],
    source_text: str | None = None,
) -> None:
    text = document.text if source_text is None else source_text
    for match in list(pattern.finditer(text))[:MAX_FINDINGS_PER_RULE_FILE]:
        hits.append(RuleHit(
            rule_id=rule_id,
            severity=severity,
            category=category,
            relative_path=document.relative_path,
            line=_line(text, match.start()),
            evidence_codes=evidence_codes,
        ))


def _call_name(call: ast.Call) -> str:
    return input_taint._call_name(call).lower()


def _string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _iter_scopes(module: ast.Module) -> Iterator[tuple[list[ast.stmt], ast.AST]]:
    module_statements = [
        node for node in module.body
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    yield module_statements, module
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.body, node


def _scope_nodes(statements: list[ast.stmt]) -> list[ast.AST]:
    return list(input_taint._walk_scope(statements))


def _ancestors(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> Iterator[ast.AST]:
    current = parents.get(node)
    while current is not None:
        yield current
        current = parents.get(current)


def _guarded_destructive_call(
    node: ast.Call,
    scope: ast.AST,
    parents: dict[ast.AST, ast.AST],
    owned_temp_names: set[str],
) -> bool:
    for ancestor in _ancestors(node, parents):
        if ancestor is scope:
            break
        if isinstance(ancestor, (ast.If, ast.Assert)):
            condition = ast.unparse(ancestor.test)
            if DESTRUCTIVE_GUARD.search(condition):
                return True
    if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in owned_temp_names:
        return True
    return False


def _python_permission_hits(document: TextDocument, module: ast.Module) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for node in ast.walk(module):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        world_writable = False
        if name in {"os.chmod", "path.chmod"} and len(node.args) >= 2:
            mode = node.args[1]
            world_writable = isinstance(mode, ast.Constant) and mode.value in {0o666, 0o777}
        if name in {
            "subprocess.run", "subprocess.call", "subprocess.popen",
            "subprocess.check_call", "subprocess.check_output",
        } and node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
            values = [_string(item) for item in node.args[0].elts]
            world_writable = bool(
                values and values[0] == "chmod"
                and any(value in {"666", "777", "a+rwx", "ugo+rwx"} for value in values[1:])
            )
        if world_writable:
            hits.append(RuleHit(
                rule_id="AEGIS_WORLD_WRITABLE_PERMISSION",
                severity="MEDIUM",
                category="excessive_permission",
                relative_path=document.relative_path,
                line=int(getattr(node, "lineno", 1)),
                evidence_codes=("world_writable_mode", "exact_permission_call"),
            ))
    return hits


def _python_destructive_hits(document: TextDocument, module: ast.Module) -> list[RuleHit]:
    hits: list[RuleHit] = []
    parents = {child: parent for parent in ast.walk(module) for child in ast.iter_child_nodes(parent)}
    for statements, scope in _iter_scopes(module):
        owned_temp_names: set[str] = set()
        for node in _scope_nodes(statements):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if isinstance(value, ast.Call) and _call_name(value) in {
                    "tempfile.mkdtemp", "tempfile.temporarydirectory", "mkdtemp", "temporarydirectory",
                }:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        owned_temp_names.update(input_taint._assignment_names(target))
        for node in _scope_nodes(statements):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            destructive = name == "shutil.rmtree"
            if name in {
                "subprocess.run", "subprocess.call", "subprocess.popen",
                "subprocess.check_call", "subprocess.check_output",
            } and node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                values = [_string(item) for item in node.args[0].elts]
                destructive = bool(
                    values and values[0] in {"rm", "remove-item"}
                    and any(value and re.fullmatch(r"-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*", value)
                            or value and re.fullmatch(r"-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*", value)
                            for value in values[1:])
                )
            if name.endswith((".execute", ".executemany")) and node.args:
                sql = _string(node.args[0]) or ""
                destructive = bool(re.search(r"(?i)\b(?:drop\s+(?:database|schema)|truncate\s+table)\b", sql))
            if destructive and not _guarded_destructive_call(node, scope, parents, owned_temp_names):
                hits.append(RuleHit(
                    rule_id="AEGIS_DESTRUCTIVE_OPERATION_NO_GUARD",
                    severity="MEDIUM",
                    category="unguarded_destructive_operation",
                    relative_path=document.relative_path,
                    line=int(getattr(node, "lineno", 1)),
                    evidence_codes=("destructive_sink", "no_confirmation_or_owned_temp_guard"),
                ))
    return hits


def _python_deserialization_hits(document: TextDocument, module: ast.Module) -> list[RuleHit]:
    hits: list[RuleHit] = []
    unsafe_names = {
        "pickle.load", "pickle.loads", "dill.load", "dill.loads",
        "marshal.loads", "joblib.load", "cloudpickle.loads",
    }
    for node in ast.walk(module):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        unsafe = name in unsafe_names
        if name in {"yaml.load", "ruamel.yaml.load"}:
            loader_values = [
                input_taint._node_name(keyword.value).lower()
                for keyword in node.keywords if keyword.arg and keyword.arg.lower() == "loader"
            ]
            unsafe = not any(value.endswith(("safeloader", "csafeloader")) for value in loader_values)
        if unsafe:
            hits.append(RuleHit(
                rule_id="AEGIS_UNSAFE_DESERIALIZATION",
                severity="MEDIUM",
                category="unsafe_deserialization",
                relative_path=document.relative_path,
                line=int(getattr(node, "lineno", 1)),
                evidence_codes=("unsafe_deserializer", "non_json_or_safe_loader"),
            ))
    return hits


def _python_network_flow_hits(document: TextDocument, module: ast.Module) -> list[RuleHit]:
    hits: list[RuleHit] = []
    functions = {
        node.name: node for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    module_statements = [
        node for node in module.body
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    input_globals, _ = input_taint._scope_taints(module_statements, {}, {})
    sensitive_globals, _ = sensitive_taint._scope_taints(module_statements, {}, {})
    scopes: list[tuple[list[ast.stmt], dict[str, set[str]], dict[str, set[str]]]] = []
    module_input, _ = input_taint._scope_taints(module_statements, input_globals, {})
    module_sensitive, _ = sensitive_taint._scope_taints(module_statements, sensitive_globals, {})
    scopes.append((module_statements, module_input, module_sensitive))
    for function in functions.values():
        input_inherited = dict(input_globals)
        kind = input_taint._decorator_kind(function)
        if kind:
            for parameter in input_taint._function_parameters(function):
                if parameter not in {"self", "cls"}:
                    input_inherited[parameter] = {kind}
        input_variables, _ = input_taint._scope_taints(function.body, input_inherited, {})
        sensitive_variables, _ = sensitive_taint._scope_taints(function.body, sensitive_globals, {})
        scopes.append((function.body, input_variables, sensitive_variables))

    network_names = {
        "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
        "httpx.get", "httpx.post", "urllib.request.urlopen", "urllib.request.urlretrieve",
        "aiohttp.client.get", "aiohttp.client.post",
    }
    for statements, input_variables, sensitive_variables in scopes:
        for node in input_taint._walk_scope(statements):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = _call_name(node)
            if name not in network_names:
                continue
            url_kinds = input_taint._expression_kinds(node.args[0], input_variables, {})
            if url_kinds:
                hits.append(RuleHit(
                    rule_id="AEGIS_UNTRUSTED_URL_TO_NETWORK_REQUEST",
                    severity="HIGH",
                    category="ssrf",
                    relative_path=document.relative_path,
                    line=int(getattr(node, "lineno", 1)),
                    evidence_codes=tuple(sorted([*url_kinds, "network_url_sink", "exact_variable_flow"])),
                ))
            url = _string(node.args[0]) or ""
            if not url.lower().startswith("http://"):
                continue
            payloads, sink_kind = sensitive_taint._payload_nodes(node)
            payload_kinds: set[str] = set()
            for payload in payloads:
                payload_kinds.update(sensitive_taint._expression_kinds(payload, sensitive_variables, {}))
            if payload_kinds:
                hits.append(RuleHit(
                    rule_id="AEGIS_SENSITIVE_DATA_OVER_PLAINTEXT_HTTP",
                    severity="HIGH",
                    category="plaintext_sensitive_transport",
                    relative_path=document.relative_path,
                    line=int(getattr(node, "lineno", 1)),
                    evidence_codes=tuple(sorted([*payload_kinds, sink_kind or "http_payload", "plaintext_http"])),
                ))
    return hits


def _python_hits(document: TextDocument) -> list[RuleHit]:
    try:
        module = ast.parse(document.text, filename=document.relative_path)
    except (SyntaxError, ValueError):
        return []
    return (
        _python_permission_hits(document, module)
        + _python_destructive_hits(document, module)
        + _python_deserialization_hits(document, module)
        + _python_network_flow_hits(document, module)
    )


def _document_hits(document: TextDocument) -> list[RuleHit]:
    hits: list[RuleHit] = []
    if document.relative_path == "SKILL.md":
        _append_regex_hits(
            hits, document, WILDCARD_TOOL_PERMISSION,
            rule_id="AEGIS_WILDCARD_TOOL_PERMISSION",
            severity="MEDIUM",
            category="excessive_tool_permission",
            evidence_codes=("manifest_allowed_tools_wildcard",),
        )
        return hits
    if document.suffix not in CODE_CONFIG_EXTENSIONS:
        return hits
    code = _non_comment_code(document.text)
    if document.suffix != ".py":
        _append_regex_hits(
            hits, document, SHELL_DESTRUCTIVE,
            rule_id="AEGIS_DESTRUCTIVE_OPERATION_NO_GUARD",
            severity="MEDIUM",
            category="unguarded_destructive_operation",
            evidence_codes=("destructive_sink", "no_confirmation_or_owned_temp_guard"),
            source_text=code if not DESTRUCTIVE_GUARD.search(code) else "",
        )
    for pattern, rule_id, severity, category, codes in (
        (WILDCARD_IAM, "AEGIS_WILDCARD_PRIVILEGE_GRANT", "CRITICAL", "excessive_privilege", ("iam_action_wildcard", "iam_resource_wildcard")),
        (WILDCARD_K8S, "AEGIS_WILDCARD_PRIVILEGE_GRANT", "CRITICAL", "excessive_privilege", ("kubernetes_verbs_wildcard", "kubernetes_resources_wildcard")),
        (WILDCARD_SUDO, "AEGIS_WILDCARD_PRIVILEGE_GRANT", "CRITICAL", "excessive_privilege", ("sudo_all_commands", "sudo_all_targets")),
        (PRIVILEGED_CONTAINER, "AEGIS_PRIVILEGED_HOST_ACCESS", "HIGH", "container_host_escape", ("privileged_container", "host_resource_access")),
        (SECURITY_CONTROL_DISABLE, "AEGIS_SECURITY_CONTROL_DISABLE", "CRITICAL", "security_control_tampering", ("security_control", "disable_or_stop_action")),
        (AUDIT_LOG_CLEAR, "AEGIS_AUDIT_LOG_CLEAR", "CRITICAL", "audit_evasion", ("audit_log_or_rule_store", "clear_action")),
        (TLS_DISABLED, "AEGIS_TLS_VERIFICATION_DISABLED", "HIGH", "insecure_transport", ("tls_verification_disabled",)),
        (CLOUD_METADATA, "AEGIS_CLOUD_METADATA_ACCESS", "HIGH", "cloud_metadata_access", ("cloud_metadata_endpoint",)),
    ):
        _append_regex_hits(
            hits, document, pattern,
            rule_id=rule_id,
            severity=severity,
            category=category,
            evidence_codes=codes,
            source_text=code,
        )
    return hits


def _finding(hit: RuleHit) -> dict:
    identity = "|".join([
        hit.rule_id, hit.relative_path, str(hit.line), *hit.evidence_codes,
    ])
    finding_id = f"{hit.rule_id}_{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:12]}"
    title_map = {
        "AEGIS_WORLD_WRITABLE_PERMISSION": "A world-writable permission is assigned",
        "AEGIS_WILDCARD_TOOL_PERMISSION": "Skill manifest grants wildcard tool access",
        "AEGIS_WILDCARD_PRIVILEGE_GRANT": "A wildcard privilege grant is configured",
        "AEGIS_PRIVILEGED_HOST_ACCESS": "A privileged container can access host resources",
        "AEGIS_SECURITY_CONTROL_DISABLE": "Security controls are explicitly disabled",
        "AEGIS_AUDIT_LOG_CLEAR": "Audit evidence is explicitly cleared",
        "AEGIS_DESTRUCTIVE_OPERATION_NO_GUARD": "A destructive operation lacks an intent or containment guard",
        "AEGIS_TLS_VERIFICATION_DISABLED": "TLS certificate verification is disabled",
        "AEGIS_CLOUD_METADATA_ACCESS": "A cloud instance metadata endpoint is accessed",
        "AEGIS_UNTRUSTED_URL_TO_NETWORK_REQUEST": "Untrusted input controls a network request URL",
        "AEGIS_SENSITIVE_DATA_OVER_PLAINTEXT_HTTP": "Sensitive data is sent over plaintext HTTP",
        "AEGIS_UNSAFE_DESERIALIZATION": "Potentially attacker-controlled data uses an unsafe deserializer",
    }
    return finding_dict(
        id=finding_id,
        title=title_map[hit.rule_id],
        category=hit.category,
        severity=hit.severity,
        analyzer=ANALYZER_ID,
        location={"file": hit.relative_path, "line": hit.line},
        evidence=(
            f"verified_features={','.join(hit.evidence_codes)}; file={hit.relative_path}; "
            "raw_value_retained=false"
        ),
        description=(
            "A deterministic static rule found an enterprise-control violation with explicit "
            "configuration, API, or bounded source-to-sink evidence."
        ),
        remediation=(
            "Apply least privilege and an explicit allowlist; preserve audit controls, require "
            "confirmation/containment for destructive actions, enforce verified TLS, and replace "
            "unsafe deserialization with a schema-validated safe format."
        ),
        rule_id=hit.rule_id,
    )


def analyze_enterprise_controls(skill_root: Path) -> tuple[list[dict], list[str]]:
    """Analyze enterprise permission, control, transport and deserialization risks."""
    documents = _read_documents(skill_root)
    hits: list[RuleHit] = []
    for document in documents:
        hits.extend(_document_hits(document))
        if document.suffix in PYTHON_EXTENSIONS:
            hits.extend(_python_hits(document))
    normalized = [_finding(hit) for hit in hits]
    findings = {finding["id"]: finding for finding in normalized}
    ordered = sorted(
        findings.values(),
        key=lambda item: (
            item["location"].get("file") or "",
            item["location"].get("line") or 0,
            item["rule_id"] or "",
        ),
    )
    return ordered, [ANALYZER_ID]
