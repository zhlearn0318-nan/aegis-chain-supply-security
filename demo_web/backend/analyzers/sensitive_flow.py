from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-sensitive-flow-v1"
MAX_FILES = 500
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024
MAX_PROPAGATION_ROUNDS = 12

PYTHON_EXTENSIONS = {".py"}
JAVASCRIPT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
CODE_EXTENSIONS = PYTHON_EXTENSIONS | JAVASCRIPT_EXTENSIONS

CREDENTIAL_KEY = re.compile(
    r"(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|token|password|passwd|"
    r"credential|private[_-]?key|client[_-]?secret|database[_-]?url|connection[_-]?string|cookie)",
    re.IGNORECASE,
)
CREDENTIAL_PATH = re.compile(
    r"(?:\.ssh[/\\]|\.aws[/\\](?:credentials|config)|\.kube[/\\]config|"
    r"\.gnupg[/\\]|\.docker[/\\]config\.json|\.netrc\b|\.env(?:\.|$)|"
    r"id_rsa\b|id_ed25519\b|private[_-]?key|credentials?(?:\.json|\.txt)?\b|"
    r"cookies?(?:\.json|\.sqlite)?\b|login data\b|keychain\b|"
    r"/etc/(?:shadow|sudoers)|wallet(?:\.dat|\.json)?)",
    re.IGNORECASE,
)
SENSITIVE_PATH = re.compile(
    r"(?:resume\.(?:pdf|docx?|txt|md)|user[_-]?(?:profile|details)|"
    r"customer[_-]?(?:data|export)|personal[_-]?(?:data|info)|"
    r"employee[_-]?(?:data|export)|payroll|medical|health[_-]?record)",
    re.IGNORECASE,
)

CREDENTIAL_KIND = "credential_source"
ENVIRONMENT_KIND = "environment_collection"
SENSITIVE_FILE_KIND = "sensitive_file_source"


@dataclass(frozen=True)
class TextDocument:
    relative_path: str
    suffix: str
    text: str


@dataclass(frozen=True)
class FlowHit:
    rule_id: str
    severity: str
    relative_path: str
    line: int
    source_kinds: tuple[str, ...]
    sink_kind: str


def _inside(root: Path, candidate: Path) -> bool:
    return candidate == root or root in candidate.parents


def _is_test_document(relative_path: str) -> bool:
    path = Path(relative_path)
    lowered_parts = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    return bool(
        lowered_parts & {"test", "tests", "fixtures", "__tests__"}
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
        if suffix not in CODE_EXTENSIONS:
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            continue
        if total_bytes + size > MAX_TOTAL_BYTES:
            raise ValueError("Skill code exceeds the bounded sensitive-flow analysis limit")
        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            continue
        total_bytes += size
        relative_path = resolved.relative_to(root).as_posix()
        documents.append(TextDocument(
            relative_path=relative_path,
            suffix=suffix,
            text=data.decode("utf-8", errors="replace"),
        ))
    return documents


def _call_name(call: ast.Call) -> str:
    def name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        if isinstance(node, ast.Call):
            return name(node.func)
        return ""

    return name(call.func)


def _string_literals(node: ast.AST) -> list[str]:
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]


def _contains_os_environ(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr == "environ":
            if isinstance(child.value, ast.Name) and child.value.id == "os":
                return True
    return False


def _direct_source_kinds(node: ast.AST) -> set[str]:
    kinds: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        call_name = _call_name(child).lower()
        literals = _string_literals(child)
        if call_name in {"os.getenv", "os.environ.get", "getenv"}:
            if any(CREDENTIAL_KEY.search(value) for value in literals):
                kinds.add(CREDENTIAL_KIND)
            else:
                kinds.add(ENVIRONMENT_KIND)
        if call_name.endswith((".read", ".read_text", ".read_bytes")) or call_name in {
            "open", "path.read_text", "path.read_bytes",
        }:
            if any(CREDENTIAL_PATH.search(value) for value in literals):
                kinds.add(CREDENTIAL_KIND)
            elif any(SENSITIVE_PATH.search(value) for value in literals):
                kinds.add(SENSITIVE_FILE_KIND)
    if _contains_os_environ(node):
        literals = _string_literals(node)
        if any(CREDENTIAL_KEY.search(value) for value in literals):
            kinds.add(CREDENTIAL_KIND)
        else:
            kinds.add(ENVIRONMENT_KIND)
    return kinds


def _expression_kinds(
    node: ast.AST,
    variable_kinds: dict[str, set[str]],
    function_returns: dict[str, set[str]],
) -> set[str]:
    kinds = _direct_source_kinds(node)
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            kinds.update(variable_kinds.get(child.id, set()))
        elif isinstance(child, ast.Call):
            kinds.update(function_returns.get(_call_name(child), set()))
    return kinds


def _assignment_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_assignment_names(item) for item in target.elts))
    if isinstance(target, ast.Subscript):
        if isinstance(target.value, ast.Name):
            return {target.value.id}
        if isinstance(target.value, ast.Attribute):
            return {target.value.attr}
    if isinstance(target, ast.Attribute):
        return {target.attr}
    return set()


def _walk_scope(statements: Iterable[ast.stmt]) -> Iterator[ast.AST]:
    def visit(node: ast.AST) -> Iterator[ast.AST]:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        for child in ast.iter_child_nodes(node):
            yield from visit(child)

    for statement in statements:
        yield from visit(statement)


def _scope_taints(
    statements: list[ast.stmt],
    inherited: dict[str, set[str]],
    function_returns: dict[str, set[str]],
) -> tuple[dict[str, set[str]], set[str]]:
    variable_kinds = {name: set(kinds) for name, kinds in inherited.items()}
    nodes = list(_walk_scope(statements))
    for _ in range(MAX_PROPAGATION_ROUNDS):
        changed = False
        for node in nodes:
            value: ast.AST | None = None
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                value = node.value
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                value = node.value
                targets = [node.target]
            elif isinstance(node, ast.AugAssign):
                value = node.value
                targets = [node.target]
            if value is None:
                continue
            kinds = _expression_kinds(value, variable_kinds, function_returns)
            if not kinds:
                continue
            for target in targets:
                for name in _assignment_names(target):
                    before = set(variable_kinds.get(name, set()))
                    variable_kinds.setdefault(name, set()).update(kinds)
                    changed = changed or variable_kinds[name] != before
        if not changed:
            break
    returned: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Return) and node.value is not None:
            returned.update(_expression_kinds(node.value, variable_kinds, function_returns))
    return variable_kinds, returned


def _payload_nodes(call: ast.Call) -> tuple[list[ast.AST], str | None]:
    call_name = _call_name(call).lower()
    tail = call_name.rsplit(".", 1)[-1]
    payload_keywords = {"data", "json", "params", "files", "content", "body", "payload"}
    payloads = [item.value for item in call.keywords if item.arg in payload_keywords]

    if tail in {"post", "put", "patch", "delete"}:
        payloads.extend(call.args[1:])
        return payloads, "http_write"
    if tail in {"get", "head", "request"} and payloads:
        return payloads, "http_query_payload"
    if tail in {"send", "sendall", "sendmail", "send_message"}:
        payloads.extend(call.args)
        return payloads, "message_or_socket_send"
    if tail in {"webhook", "upload"}:
        payloads.extend(call.args)
        return payloads, "webhook_or_upload"
    if call_name.endswith("urllib.request.request") and payloads:
        return payloads, "http_write"
    return [], None


def _python_flow_hits(document: TextDocument) -> list[FlowHit]:
    try:
        module = ast.parse(document.text, filename=document.relative_path)
    except (SyntaxError, ValueError):
        return []

    functions = {
        node.name: node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    module_statements = [
        node for node in module.body
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    global_kinds, _ = _scope_taints(module_statements, {}, {})

    function_returns: dict[str, set[str]] = {}
    for _ in range(MAX_PROPAGATION_ROUNDS):
        changed = False
        for name, function in functions.items():
            _, returned = _scope_taints(function.body, global_kinds, function_returns)
            before = set(function_returns.get(name, set()))
            function_returns.setdefault(name, set()).update(returned)
            changed = changed or function_returns[name] != before
        if not changed:
            break

    scopes: list[tuple[list[ast.stmt], dict[str, set[str]]]] = []
    module_taints, _ = _scope_taints(module_statements, global_kinds, function_returns)
    scopes.append((module_statements, module_taints))
    for function in functions.values():
        local_taints, _ = _scope_taints(function.body, global_kinds, function_returns)
        scopes.append((function.body, local_taints))

    hits: list[FlowHit] = []
    for statements, variable_kinds in scopes:
        for node in _walk_scope(statements):
            if not isinstance(node, ast.Call):
                continue
            payloads, sink_kind = _payload_nodes(node)
            if not payloads or sink_kind is None:
                continue
            kinds: set[str] = set()
            for payload in payloads:
                kinds.update(_expression_kinds(payload, variable_kinds, function_returns))
            if not kinds:
                continue
            if CREDENTIAL_KIND in kinds:
                hits.append(FlowHit(
                    rule_id="AEGIS_CREDENTIAL_IN_OUTBOUND_PAYLOAD",
                    severity="CRITICAL",
                    relative_path=document.relative_path,
                    line=int(getattr(node, "lineno", 1)),
                    source_kinds=tuple(sorted(kinds)),
                    sink_kind=sink_kind,
                ))
            else:
                hits.append(FlowHit(
                    rule_id="AEGIS_SENSITIVE_DATA_TO_OUTBOUND_SINK",
                    severity="HIGH",
                    relative_path=document.relative_path,
                    line=int(getattr(node, "lineno", 1)),
                    source_kinds=tuple(sorted(kinds)),
                    sink_kind=sink_kind,
                ))
    return hits


JS_ASSIGNMENT = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.{1,1200}?);",
    re.IGNORECASE | re.DOTALL,
)
JS_FETCH_BODY = re.compile(
    r"\bfetch\s*\(.{0,1200}?\bbody\s*:\s*([A-Za-z_$][\w$]*)",
    re.IGNORECASE | re.DOTALL,
)
JS_HTTP_PAYLOAD = re.compile(
    r"\baxios\.(?:post|put|patch|delete)\s*\(\s*[^,\n]{1,500},\s*([A-Za-z_$][\w$]*)",
    re.IGNORECASE,
)
JS_SEND_PAYLOAD = re.compile(
    r"\.(?:send|sendall)\s*\(\s*([A-Za-z_$][\w$]*)",
    re.IGNORECASE,
)
JS_MAIL_PAYLOAD = re.compile(
    r"\bsendMail\s*\(\s*\{.{0,1200}?\b(?:text|html)\s*:\s*([A-Za-z_$][\w$]*)",
    re.IGNORECASE | re.DOTALL,
)


def _javascript_source_kinds(expression: str) -> set[str]:
    kinds: set[str] = set()
    if re.search(r"\bprocess\.env\b", expression, re.IGNORECASE):
        kinds.add(CREDENTIAL_KIND if CREDENTIAL_KEY.search(expression) else ENVIRONMENT_KIND)
    if re.search(r"\breadFile(?:Sync)?\s*\(", expression, re.IGNORECASE):
        if CREDENTIAL_PATH.search(expression):
            kinds.add(CREDENTIAL_KIND)
        elif SENSITIVE_PATH.search(expression):
            kinds.add(SENSITIVE_FILE_KIND)
    return kinds


def _javascript_flow_hits(document: TextDocument) -> list[FlowHit]:
    assignments = list(JS_ASSIGNMENT.finditer(document.text))
    variable_kinds: dict[str, set[str]] = {}
    for _ in range(MAX_PROPAGATION_ROUNDS):
        changed = False
        for match in assignments:
            name, expression = match.group(1), match.group(2)
            kinds = _javascript_source_kinds(expression)
            for source_name, source_kinds in variable_kinds.items():
                if re.search(rf"(?<![\w$]){re.escape(source_name)}(?![\w$])", expression):
                    kinds.update(source_kinds)
            if not kinds:
                continue
            before = set(variable_kinds.get(name, set()))
            variable_kinds.setdefault(name, set()).update(kinds)
            changed = changed or variable_kinds[name] != before
        if not changed:
            break

    sink_patterns = (
        (JS_FETCH_BODY, "http_write"),
        (JS_HTTP_PAYLOAD, "http_write"),
        (JS_SEND_PAYLOAD, "message_or_socket_send"),
        (JS_MAIL_PAYLOAD, "message_or_socket_send"),
    )
    hits: list[FlowHit] = []
    for pattern, sink_kind in sink_patterns:
        for match in pattern.finditer(document.text):
            kinds = variable_kinds.get(match.group(1), set())
            if not kinds:
                continue
            hits.append(FlowHit(
                rule_id=(
                    "AEGIS_CREDENTIAL_IN_OUTBOUND_PAYLOAD"
                    if CREDENTIAL_KIND in kinds
                    else "AEGIS_SENSITIVE_DATA_TO_OUTBOUND_SINK"
                ),
                severity="CRITICAL" if CREDENTIAL_KIND in kinds else "HIGH",
                relative_path=document.relative_path,
                line=document.text.count("\n", 0, match.start()) + 1,
                source_kinds=tuple(sorted(kinds)),
                sink_kind=sink_kind,
            ))
    return hits


def _finding(hit: FlowHit) -> dict:
    test_context = _is_test_document(hit.relative_path)
    context_note = (
        " Test-context paths remain reviewable because a packaged Skill can import or invoke them."
        if test_context else ""
    )
    evidence_codes = [*hit.source_kinds, hit.sink_kind, "exact_variable_flow"]
    if test_context:
        evidence_codes.append("test_context_unverified_reachability")
    identity = "|".join([
        hit.rule_id, hit.relative_path, str(hit.line), *evidence_codes,
    ])
    finding_id = f"{hit.rule_id}_{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:12]}"
    credential = hit.rule_id == "AEGIS_CREDENTIAL_IN_OUTBOUND_PAYLOAD"
    return finding_dict(
        id=finding_id,
        title=(
            "Credential-derived data reaches an outbound payload sink"
            if credential else "Sensitive data reaches an outbound payload sink"
        ),
        category="credential_exfiltration" if credential else "sensitive_data_exfiltration",
        severity="MEDIUM" if test_context else hit.severity,
        analyzer=ANALYZER_ID,
        location={"file": hit.relative_path, "line": hit.line},
        evidence=(
            f"verified_flow={','.join(evidence_codes)}; file={hit.relative_path}; "
            "raw_value_retained=false"
        ),
        description=((
            "A bounded static variable-flow trace links a credential or credential-file source "
            "to an outbound request, upload, message, or socket payload. Authentication-header-only "
            "usage is excluded from this rule."
            if credential else
            "A bounded static variable-flow trace links environment or sensitive-file data to an "
            "outbound request, upload, message, or socket payload."
        ) + context_note),
        remediation=(
            "Remove credential disclosure; keep credentials in approved authentication fields, "
            "apply a destination allowlist, minimize transmitted fields, and require explicit review."
            if credential else
            "Verify the business purpose and data classification, minimize fields, require an approved "
            "destination, and record user authorization before transmission."
        ),
        rule_id=hit.rule_id,
    )


def analyze_sensitive_flows(skill_root: Path) -> tuple[list[dict], list[str]]:
    """Find high-confidence source-to-outbound-payload flows without executing Skill code."""
    documents = _read_documents(skill_root)
    hits: list[FlowHit] = []
    for document in documents:
        if document.suffix in PYTHON_EXTENSIONS:
            hits.extend(_python_flow_hits(document))
        elif document.suffix in JAVASCRIPT_EXTENSIONS:
            hits.extend(_javascript_flow_hits(document))
    normalized_findings = [_finding(hit) for hit in hits]
    findings = {finding["id"]: finding for finding in normalized_findings}
    ordered = sorted(
        findings.values(),
        key=lambda item: (
            item["location"].get("file") or "",
            item["location"].get("line") or 0,
            item["rule_id"] or "",
        ),
    )
    return ordered, [ANALYZER_ID]
