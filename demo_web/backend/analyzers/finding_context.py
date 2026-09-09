from __future__ import annotations

import ast
import copy
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any


ANALYZER_ID = "aegis-finding-context-v2"

# These rules describe a complete high-risk primitive or a bounded complete
# data-flow chain. Contextual compatibility handling must never lower them.
PROTECTED_COMPLETE_RULES = {
    "AEGIS_REMOTE_FETCH_PIPE_SHELL",
    "AEGIS_REMOTE_FETCH_DECODE_EXECUTE",
    "AEGIS_PASTE_SERVICE_PAYLOAD_EXECUTION",
    "AEGIS_EMBEDDED_BLOB_DECODE_EXECUTE",
    "AEGIS_PERSISTENCE_SCHEDULED_TASK",
    "AEGIS_PERSISTENCE_SERVICE_CREATE",
    "AEGIS_PERSISTENCE_STARTUP_PROFILE_WRITE",
    "AEGIS_CREDENTIAL_IN_OUTBOUND_PAYLOAD",
    "AEGIS_SENSITIVE_DATA_TO_OUTBOUND_SINK",
    "AEGIS_UNTRUSTED_INPUT_TO_SHELL_OR_EVAL",
    "AEGIS_UNTRUSTED_DYNAMIC_IMPORT",
}

SAFE_USER_ACTIVATION = re.compile(
    r"(?i)(?:use|trigger|invoke)\s+(?:this\s+)?skill\s+when\s+(?:the\s+)?user\s+"
    r"(?:asks?|wants?|needs?|requests?|mentions?|says?)|"
    r"when\s+to\s+use\s+this\s+skill|"
    r"(?:适用场景|当用户(?:询问|想要|需要|请求|提到).{0,80})"
)
SUSPICIOUS_CONDITIONAL_MARKER = re.compile(
    r"(?i)do\s+not\s+(?:surface|mention|tell|notify|disclose|reveal|show|ask)|"
    r"without\s+(?:user\s+)?(?:approval|confirmation|consent)|"
    r"(?:stealth|secretly|silently|hidden)|"
    r"(?:very\s+)?first\s+action|before\s+(?:producing|responding)|"
    r"(?:always|must|required)\s+(?:be\s+)?(?:to\s+)?(?:execute|run|invoke)|"
    r"(?:pre[- ]?flight|initiali[sz]ation|operational)\s+(?:step|guard|contract|note)|"
    r"(?:python(?:3)?|bash|sh|powershell|pwsh|cmd(?:\.exe)?|node)\s+[^\n`]*(?:scripts?/|\.py\b|\.sh\b|\.ps1\b|\.js\b)|"
    r"`[^`]*(?:scripts?/|\.py\b|\.sh\b|\.ps1\b|\.js\b)[^`]*`|"
    r"(?:不要|不得|无需|不必).{0,24}(?:告知|显示|通知|确认|同意|授权)|静默|隐蔽|"
    r"(?:第一步|首次操作|回复前|必须|总是).{0,36}(?:执行|运行|调用|启动)"
)
TEST_OR_EXAMPLE_PARTS = {"test", "tests", "fixtures", "fixture", "examples", "example", "samples", "sample"}
DOC_SUFFIXES = {".md", ".mdx", ".rst", ".txt"}
EXECUTABLE_TEXT = re.compile(
    r"(?i)(?:\|\s*(?:sh|bash)|;|\$\(|\beval\s*\(|\bexec\s*\(|spawn|subprocess|child_process|os\.system|"
    r"powershell|cmd(?:\.exe)?\s+/c|bash\s+-c|curl\b|wget\b|https?://)"
)
SAFE_NOTEBOOK_IMPORTS = {"__future__", "collections", "datetime", "decimal", "fractions", "itertools", "math", "random", "statistics"}
UNSAFE_NOTEBOOK_CALLS = {"eval", "exec", "compile", "open", "__import__", "os.system", "os.popen", "subprocess.run", "subprocess.Popen"}


def _relative_file(finding: dict[str, Any]) -> str:
    location = finding.get("location")
    if not isinstance(location, dict):
        return ""
    return str(location.get("file") or "").replace("\\", "/")


def _is_complete_protected(finding: dict[str, Any]) -> bool:
    return str(finding.get("rule_id") or "") in PROTECTED_COMPLETE_RULES


def _downgrade_to_info(
    finding: dict[str, Any], *, context_rule_id: str, reason: str, reachability: str | None = None
) -> dict[str, Any]:
    result = copy.deepcopy(finding)
    result["original_severity"] = str(finding.get("severity") or "UNKNOWN")
    result["severity"] = "INFO"
    result["context_disposition"] = "SUPPRESSED_TO_INFO"
    result["context_rule_id"] = context_rule_id
    result["context_reason"] = reason
    result["context_analyzer"] = ANALYZER_ID
    if reachability:
        result["original_reachability"] = str(finding.get("reachability") or "UNKNOWN")
        result["reachability"] = reachability
    return result


def _is_test_or_example_path(relative: str) -> bool:
    if not relative:
        return False
    path = PurePosixPath(relative)
    parts = {part.casefold() for part in path.parts[:-1]}
    stem = path.stem.casefold()
    return bool(parts & TEST_OR_EXAMPLE_PARTS) or stem.startswith(("test_", "example_", "sample_"))


def _is_template_path(relative: str) -> bool:
    lowered = relative.casefold()
    path = PurePosixPath(lowered)
    return (
        "templates" in path.parts
        or ".template." in path.name
        or "-template." in path.name
        or path.name.endswith(".template")
    )


def _paragraph_at(text: str, line_number: int) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    index = max(0, min(len(lines) - 1, line_number - 1))
    left = index
    right = index
    while left > 0 and lines[left - 1].strip() and index - left < 4:
        left -= 1
    while right + 1 < len(lines) and lines[right + 1].strip() and right - index < 4:
        right += 1
    return "\n".join(lines[left:right + 1])


def _window_at(text: str, line_number: int, radius: int = 14) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    index = max(0, min(len(lines) - 1, line_number - 1))
    return "\n".join(lines[max(0, index - radius):min(len(lines), index + radius + 1)])


def has_strict_conditional_risk_chain(skill_root: Path, finding: dict[str, Any]) -> bool:
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    line = int(location.get("line") or 1)
    manifest = skill_root / "SKILL.md"
    if not manifest.is_file() or manifest.is_symlink():
        return True
    text = manifest.read_text(encoding="utf-8", errors="replace")
    window = _window_at(text, line)
    # Suppression is intentionally one-way and narrow: only a conventional
    # user-intent routing sentence, with no nearby forced/hidden/script marker,
    # is treated as benign activation prose. Every other ambiguous condition is
    # retained for review. The 14-line radius matches the originating semantic
    # analyzer so an injected directive cannot be split away by paragraph gaps.
    return not (
        SAFE_USER_ACTIVATION.search(window)
        and not SUSPICIOUS_CONDITIONAL_MARKER.search(window)
    )


def _call_at_line(tree: ast.AST, line: int) -> ast.Call | None:
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and int(getattr(node, "lineno", 0)) == line]
    for call in calls:
        name = ""
        if isinstance(call.func, ast.Attribute):
            prefix = call.func.value.id if isinstance(call.func.value, ast.Name) else ""
            name = f"{prefix}.{call.func.attr}" if prefix else call.func.attr
        if name.casefold() in {"subprocess.run", "subprocess.call", "subprocess.popen", "subprocess.check_call", "subprocess.check_output"}:
            return call
    return None


def _enclosing_statements(tree: ast.Module, line: int) -> list[ast.stmt]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = int(getattr(node, "end_lineno", node.lineno))
            if node.lineno <= line <= end:
                return node.body
    return tree.body


def _trusted_executable(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(node.value.strip())
    return isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "sys" and node.attr == "executable"


def fixed_executable_command_is_proven(skill_root: Path, finding: dict[str, Any]) -> bool:
    relative = _relative_file(finding)
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    line = int(location.get("line") or 0)
    if not relative or not line or Path(relative).suffix.casefold() != ".py":
        return False
    path = skill_root / PurePosixPath(relative)
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    except (OSError, UnicodeError, SyntaxError, ValueError):
        return False
    call = _call_at_line(tree, line)
    if call is None or not call.args:
        return False
    if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in call.keywords):
        return False
    command = call.args[0]
    if isinstance(command, (ast.List, ast.Tuple)) and command.elts:
        return _trusted_executable(command.elts[0])
    if not isinstance(command, ast.Name):
        return False
    command_name = command.id
    statements = _enclosing_statements(tree, line)
    initializers: list[ast.AST] = []
    unsafe_reassignments = False
    for node in ast.walk(ast.Module(body=statements, type_ignores=[])):
        node_line = int(getattr(node, "lineno", 0))
        if not node_line or node_line >= line:
            continue
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == command_name for target in node.targets):
            initializers.append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == command_name and node.value is not None:
            initializers.append(node.value)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == command_name:
            unsafe_reassignments = True
    if unsafe_reassignments or len(initializers) != 1:
        return False
    value = initializers[0]
    return isinstance(value, (ast.List, ast.Tuple)) and bool(value.elts) and _trusted_executable(value.elts[0])


def _manifest_declares_path(skill_root: Path, relative: str) -> bool:
    manifest = skill_root / "SKILL.md"
    if not manifest.is_file() or not relative:
        return False
    text = manifest.read_text(encoding="utf-8", errors="replace").replace("\\", "/").casefold()
    normalized = relative.casefold()
    return normalized in text or PurePosixPath(normalized).name in text


def _node_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _node_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def safe_notebook_template_is_proven(skill_root: Path, relative: str) -> bool:
    if PurePosixPath(relative).suffix.casefold() != ".ipynb" or not _is_template_path(relative):
        return False
    try:
        payload = json.loads((skill_root / PurePosixPath(relative)).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict) or payload.get("nbformat") != 4 or not isinstance(payload.get("cells"), list):
        return False
    total_source = 0
    for cell in payload["cells"]:
        if not isinstance(cell, dict) or cell.get("cell_type") not in {"code", "markdown", "raw"}:
            return False
        if cell.get("outputs") not in (None, []):
            return False
        if cell.get("attachments") not in (None, {}):
            return False
        source = cell.get("source", [])
        if isinstance(source, list) and all(isinstance(item, str) for item in source):
            text = "".join(source)
        elif isinstance(source, str):
            text = source
        else:
            return False
        total_source += len(text)
        if total_source > 100_000:
            return False
        if cell.get("cell_type") != "code":
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return False
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [alias.name.split(".", 1)[0] for alias in node.names] if isinstance(node, ast.Import) else [str(node.module or "").split(".", 1)[0]]
                if any(name not in SAFE_NOTEBOOK_IMPORTS for name in names):
                    return False
            elif isinstance(node, ast.Call) and _node_name(node.func) in UNSAFE_NOTEBOOK_CALLS:
                return False
    return True


def generic_command_alert_is_lexical_only(skill_root: Path, finding: dict[str, Any]) -> bool:
    relative = _relative_file(finding)
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    line = int(location.get("line") or 0)
    if not relative or not line:
        return False
    path = skill_root / PurePosixPath(relative)
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError):
        return False
    if line > len(lines):
        return False
    window = "\n".join(lines[max(0, line - 3):min(len(lines), line + 2)])
    return not EXECUTABLE_TEXT.search(window)


def apply_finding_context(
    skill_root: Path, findings: list[dict[str, Any]], stage: str
) -> list[dict[str, Any]]:
    if stage not in {"F1", "F2", "F3"}:
        raise ValueError("stage must be F1, F2, or F3")
    output: list[dict[str, Any]] = []
    for source in findings:
        finding = copy.deepcopy(source)
        rule_id = str(finding.get("rule_id") or "")
        severity = str(finding.get("severity") or "UNKNOWN").upper()
        relative = _relative_file(finding)

        if not _is_complete_protected(finding):
            if rule_id == "MANIFEST_DESCRIPTION_TOO_LONG" and severity == "LOW":
                finding = _downgrade_to_info(
                    finding,
                    context_rule_id="AEGIS_CONTEXT_METADATA_QUALITY_ONLY",
                    reason="An overlong manifest description is a quality issue without an executable security chain.",
                )
            elif rule_id == "FILE_MAGIC_MISMATCH" and severity in {"LOW", "MEDIUM"} and _is_template_path(relative):
                finding = _downgrade_to_info(
                    finding,
                    context_rule_id="AEGIS_CONTEXT_TEMPLATE_SUFFIX",
                    reason="The extension intentionally denotes a source template; the original mismatch remains visible for audit.",
                    reachability="EXAMPLE",
                )
            elif severity in {"LOW", "MEDIUM"} and _is_test_or_example_path(relative):
                finding = _downgrade_to_info(
                    finding,
                    context_rule_id="AEGIS_CONTEXT_TEST_OR_EXAMPLE_PATH",
                    reason="The finding is confined to a test/example path and no installed reachability is proven.",
                    reachability="TEST",
                )
            elif (
                rule_id == "AEGIS_STATIC_UNSUPPORTED_CODE_UNINSPECTED"
                and severity == "MEDIUM"
                and safe_notebook_template_is_proven(skill_root, relative)
            ):
                finding = _downgrade_to_info(
                    finding,
                    context_rule_id="AEGIS_CONTEXT_SAFE_NOTEBOOK_TEMPLATE",
                    reason="The notebook template is bounded JSON with parseable allowlisted Python cells and no outputs or attachments.",
                    reachability="EXAMPLE",
                )
            elif (
                rule_id == "AEGIS_PARTIAL_REMOTE_EXEC_CHAIN"
                and severity == "MEDIUM"
                and PurePosixPath(relative).suffix.casefold() in DOC_SUFFIXES
                and relative.casefold().startswith("references/")
            ):
                finding = _downgrade_to_info(
                    finding,
                    context_rule_id="AEGIS_CONTEXT_REFERENCE_PARTIAL_CHAIN",
                    reason="Only a partial lexical chain occurs in reference documentation; no complete data flow is established.",
                    reachability="REFERENCED",
                )
            elif (
                rule_id == "YARA_command_injection_generic"
                and severity in {"HIGH", "CRITICAL"}
                and generic_command_alert_is_lexical_only(skill_root, finding)
            ):
                finding = _downgrade_to_info(
                    finding,
                    context_rule_id="AEGIS_CONTEXT_GENERIC_COMMAND_WITHOUT_SINK",
                    reason="The bounded source window is prose and contains no command syntax, interpreter, download primitive, or executable sink.",
                    reachability="REFERENCED",
                )

        if stage in {"F2", "F3"} and rule_id == "AEGIS_SEMANTIC_CONDITIONAL_RISK_TRIGGER" and finding.get("severity") != "INFO":
            if not has_strict_conditional_risk_chain(skill_root, finding):
                finding = _downgrade_to_info(
                    finding,
                    context_rule_id="AEGIS_CONTEXT_SAFE_USER_ACTIVATION",
                    reason="A bounded 14-line window proves ordinary user-intent routing and contains no forced, hidden, or script-execution marker.",
                )

        if stage == "F3" and rule_id == "AEGIS_UNTRUSTED_DYNAMIC_EXECUTABLE" and finding.get("severity") != "INFO":
            if fixed_executable_command_is_proven(skill_root, finding):
                finding = _downgrade_to_info(
                    finding,
                    context_rule_id="AEGIS_CONTEXT_FIXED_EXECUTABLE_ARGV",
                    reason="AST verification proves a fixed executable (including sys.executable); CLI data can only populate typed argv.",
                    reachability="REACHABLE",
                )

        output.append(finding)
    return output
