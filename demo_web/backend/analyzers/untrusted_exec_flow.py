from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from ..normalizers import finding_dict


ANALYZER_ID = "aegis-untrusted-exec-flow-v1"
MAX_FILES = 500
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024
MAX_PROPAGATION_ROUNDS = 12

PYTHON_EXTENSIONS = {".py"}
JAVASCRIPT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
CODE_EXTENSIONS = PYTHON_EXTENSIONS | JAVASCRIPT_EXTENSIONS

USER_INPUT_KIND = "interactive_user_input"
CLI_INPUT_KIND = "cli_input"
REQUEST_INPUT_KIND = "http_request_input"
TOOL_INPUT_KIND = "tool_handler_input"
MODEL_OUTPUT_KIND = "model_output"

SHELL_RULE = "AEGIS_UNTRUSTED_INPUT_TO_SHELL_OR_EVAL"
DYNAMIC_EXECUTABLE_RULE = "AEGIS_UNTRUSTED_DYNAMIC_EXECUTABLE"
DYNAMIC_IMPORT_RULE = "AEGIS_UNTRUSTED_DYNAMIC_IMPORT"

MODEL_CALL = re.compile(
    r"(?:^|\.)(?:llm|model|chat|completions?|openai|anthropic|gemini|agent)\."
    r"(?:invoke|predict|generate|generate_content|create|complete)$",
    re.IGNORECASE,
)
REQUEST_ACCESS = re.compile(
    r"(?:^|\.)(?:request|req)\.(?:args|form|json|values|query_params|path_params|"
    r"get_json|body|query|params)(?:\.|$)",
    re.IGNORECASE,
)
SHELL_INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
}
SHELL_FLAGS = {"-c", "/c", "-command", "-encodedcommand", "-enc"}


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
            raise ValueError("Skill code exceeds the bounded untrusted-execution analysis limit")
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


def _node_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _node_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _node_name(node.func)
    return ""


def _call_name(call: ast.Call) -> str:
    return _node_name(call.func)


def _direct_source_kinds(node: ast.AST) -> set[str]:
    kinds: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            call_name = _call_name(child).lower()
            if call_name in {"input", "builtins.input", "sys.stdin.read", "sys.stdin.readline"}:
                kinds.add(USER_INPUT_KIND)
            if call_name.endswith((".parse_args", ".parse_known_args")):
                kinds.add(CLI_INPUT_KIND)
            if REQUEST_ACCESS.search(call_name):
                kinds.add(REQUEST_INPUT_KIND)
            if MODEL_CALL.search(call_name):
                kinds.add(MODEL_OUTPUT_KIND)
        elif isinstance(child, ast.Attribute):
            attribute_name = _node_name(child).lower()
            if attribute_name.startswith("sys.argv") or attribute_name.startswith("sys.stdin"):
                kinds.add(CLI_INPUT_KIND)
            if REQUEST_ACCESS.search(attribute_name):
                kinds.add(REQUEST_INPUT_KIND)
        elif isinstance(child, ast.Subscript):
            value_name = _node_name(child.value).lower()
            if value_name == "sys.argv":
                kinds.add(CLI_INPUT_KIND)
            if REQUEST_ACCESS.search(value_name):
                kinds.add(REQUEST_INPUT_KIND)
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
        return {_node_name(target.value).split(".")[-1]}
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


def _command_expression_has_fixed_executable(
    node: ast.AST,
    fixed_variables: set[str],
) -> bool:
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        return _constant_string(node.elts[0]) is not None
    return isinstance(node, ast.Name) and node.id in fixed_variables


def _fixed_command_variables(
    statements: list[ast.stmt],
    inherited: set[str],
) -> set[str]:
    assignments: dict[str, list[ast.AST]] = {}
    for node in _walk_scope(statements):
        value: ast.AST | None = None
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            value = node.value
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value = node.value
            targets = [node.target]
        if value is None:
            continue
        for target in targets:
            for name in _assignment_names(target):
                assignments.setdefault(name, []).append(value)
    fixed = set(inherited)
    for _ in range(MAX_PROPAGATION_ROUNDS):
        next_fixed = set(inherited)
        for name, values in assignments.items():
            if values and all(_command_expression_has_fixed_executable(value, fixed) for value in values):
                next_fixed.add(name)
        if next_fixed == fixed:
            break
        fixed = next_fixed
    return fixed


def _decorator_kind(function: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    names = {_node_name(item.func if isinstance(item, ast.Call) else item).lower()
             for item in function.decorator_list}
    if any(name == "tool" or name.endswith(".tool") for name in names):
        return TOOL_INPUT_KIND
    http_methods = (".get", ".post", ".put", ".patch", ".delete", ".route", ".websocket")
    if any(name.endswith(http_methods) for name in names):
        return REQUEST_INPUT_KIND
    return None


def _function_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    arguments = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
    names = [item.arg for item in arguments]
    if function.args.vararg:
        names.append(function.args.vararg.arg)
    if function.args.kwarg:
        names.append(function.args.kwarg.arg)
    return names


def _constant_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower()
    return None


def _truthy_keyword(call: ast.Call, name: str) -> bool:
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant):
            return keyword.value.value is True
    return False


def _python_sink(
    call: ast.Call,
    variable_kinds: dict[str, set[str]],
    function_returns: dict[str, set[str]],
    fixed_command_variables: set[str],
) -> tuple[str, str, set[str]] | None:
    call_name = _call_name(call).lower()
    if not call.args:
        return None

    first_kinds = _expression_kinds(call.args[0], variable_kinds, function_returns)
    direct_shell = {
        "os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
        "eval", "builtins.eval", "exec", "builtins.exec",
    }
    if call_name in direct_shell and first_kinds:
        sink = "dynamic_code_eval" if call_name.rsplit(".", 1)[-1] in {"eval", "exec"} else "shell_command"
        return SHELL_RULE, sink, first_kinds

    if call_name in {"importlib.import_module", "__import__", "builtins.__import__"} and first_kinds:
        return DYNAMIC_IMPORT_RULE, "dynamic_module_import", first_kinds

    subprocess_calls = {
        "subprocess.run", "subprocess.call", "subprocess.popen", "subprocess.check_call",
        "subprocess.check_output",
    }
    if call_name not in subprocess_calls:
        return None
    command = call.args[0]
    if _truthy_keyword(call, "shell") and first_kinds:
        return SHELL_RULE, "subprocess_shell_true", first_kinds

    if isinstance(command, (ast.List, ast.Tuple)) and command.elts:
        executable = command.elts[0]
        executable_kinds = _expression_kinds(executable, variable_kinds, function_returns)
        if executable_kinds:
            return DYNAMIC_EXECUTABLE_RULE, "dynamic_executable", executable_kinds
        executable_name = _constant_string(executable)
        if executable_name in SHELL_INTERPRETERS:
            for index, element in enumerate(command.elts[1:-1], start=1):
                flag = _constant_string(element)
                if flag in SHELL_FLAGS:
                    payload_kinds = _expression_kinds(
                        command.elts[index + 1], variable_kinds, function_returns
                    )
                    if payload_kinds:
                        return SHELL_RULE, "interpreter_command_flag", payload_kinds
        return None

    if isinstance(command, ast.Name) and command.id in fixed_command_variables:
        return None
    if first_kinds:
        return DYNAMIC_EXECUTABLE_RULE, "dynamic_executable", first_kinds
    return None


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
    parameter_kinds: dict[str, dict[str, set[str]]] = {name: {} for name in functions}
    for name, function in functions.items():
        kind = _decorator_kind(function)
        if kind:
            parameter_kinds[name] = {
                parameter: {kind} for parameter in _function_parameters(function)
                if parameter not in {"self", "cls"}
            }

    fixed_parameters: dict[str, set[str]] = {name: set() for name in functions}
    function_returns: dict[str, set[str]] = {}
    for _ in range(MAX_PROPAGATION_ROUNDS):
        changed = False
        scope_cache: dict[str, dict[str, set[str]]] = {}
        fixed_scope_cache: dict[str, set[str]] = {}
        for name, function in functions.items():
            inherited = {**global_kinds, **parameter_kinds[name]}
            local_kinds, returned = _scope_taints(function.body, inherited, function_returns)
            scope_cache[name] = local_kinds
            fixed_scope_cache[name] = _fixed_command_variables(
                function.body, fixed_parameters[name]
            )
            before = set(function_returns.get(name, set()))
            function_returns.setdefault(name, set()).update(returned)
            changed = changed or function_returns[name] != before
        fixed_observations: dict[str, dict[str, list[bool]]] = {
            name: {} for name in functions
        }
        for caller_name, function in functions.items():
            caller_kinds = scope_cache.get(caller_name, {})
            caller_fixed = fixed_scope_cache.get(caller_name, set())
            for node in _walk_scope(function.body):
                if not isinstance(node, ast.Call):
                    continue
                target_name = _call_name(node)
                target = functions.get(target_name)
                if target is None:
                    continue
                parameters = _function_parameters(target)
                for index, argument in enumerate(node.args):
                    if index >= len(parameters):
                        break
                    kinds = _expression_kinds(argument, caller_kinds, function_returns)
                    if not kinds:
                        continue
                    parameter = parameters[index]
                    fixed_observations[target_name].setdefault(parameter, []).append(
                        _command_expression_has_fixed_executable(argument, caller_fixed)
                    )
                    before = set(parameter_kinds[target_name].get(parameter, set()))
                    parameter_kinds[target_name].setdefault(parameter, set()).update(kinds)
                    changed = changed or parameter_kinds[target_name][parameter] != before
                for keyword in node.keywords:
                    if keyword.arg not in parameters:
                        continue
                    fixed_observations[target_name].setdefault(keyword.arg, []).append(
                        _command_expression_has_fixed_executable(keyword.value, caller_fixed)
                    )
                    kinds = _expression_kinds(keyword.value, caller_kinds, function_returns)
                    if not kinds:
                        continue
                    before = set(parameter_kinds[target_name].get(keyword.arg, set()))
                    parameter_kinds[target_name].setdefault(keyword.arg, set()).update(kinds)
                    changed = changed or parameter_kinds[target_name][keyword.arg] != before
        for name, observations in fixed_observations.items():
            next_fixed = {
                parameter for parameter, values in observations.items()
                if values and all(values)
            }
            if next_fixed != fixed_parameters[name]:
                fixed_parameters[name] = next_fixed
                changed = True
        if not changed:
            break

    scopes: list[tuple[list[ast.stmt], dict[str, set[str]], set[str]]] = []
    module_taints, _ = _scope_taints(module_statements, global_kinds, function_returns)
    module_fixed = _fixed_command_variables(module_statements, set())
    scopes.append((module_statements, module_taints, module_fixed))
    for name, function in functions.items():
        inherited = {**global_kinds, **parameter_kinds[name]}
        local_taints, _ = _scope_taints(function.body, inherited, function_returns)
        local_fixed = _fixed_command_variables(function.body, fixed_parameters[name])
        scopes.append((function.body, local_taints, local_fixed))

    hits: list[FlowHit] = []
    for statements, variable_kinds, fixed_commands in scopes:
        for node in _walk_scope(statements):
            if not isinstance(node, ast.Call):
                continue
            sink = _python_sink(node, variable_kinds, function_returns, fixed_commands)
            if sink is None:
                continue
            rule_id, sink_kind, source_kinds = sink
            hits.append(FlowHit(
                rule_id=rule_id,
                severity="CRITICAL" if rule_id == SHELL_RULE else "HIGH",
                relative_path=document.relative_path,
                line=int(getattr(node, "lineno", 1)),
                source_kinds=tuple(sorted(source_kinds)),
                sink_kind=sink_kind,
            ))
    return hits


JS_ASSIGNMENT = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.{1,1600}?);",
    re.IGNORECASE | re.DOTALL,
)
JS_SHELL_SINK = re.compile(
    r"\b(?:exec|execSync|eval)\s*\(\s*([A-Za-z_$][\w$]*)|"
    r"\bnew\s+Function\s*\(\s*([A-Za-z_$][\w$]*)",
    re.IGNORECASE,
)
JS_DYNAMIC_EXECUTABLE = re.compile(
    r"\b(?:spawn|spawnSync)\s*\(\s*([A-Za-z_$][\w$]*)",
    re.IGNORECASE,
)
JS_INTERPRETER_COMMAND = re.compile(
    r"\b(?:spawn|spawnSync)\s*\(\s*['\"](?:bash|sh|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)['\"]"
    r"\s*,\s*\[\s*['\"](?:-c|/c|-command|-enc|-encodedcommand)['\"]\s*,\s*([A-Za-z_$][\w$]*)",
    re.IGNORECASE,
)


def _javascript_source_kinds(expression: str) -> set[str]:
    kinds: set[str] = set()
    if re.search(r"\b(?:prompt\s*\(|readline\.|process\.stdin)\b", expression, re.IGNORECASE):
        kinds.add(USER_INPUT_KIND)
    if re.search(r"\bprocess\.argv\b", expression, re.IGNORECASE):
        kinds.add(CLI_INPUT_KIND)
    if re.search(
        r"\b(?:req|request)\.(?:body|query|params|headers)\b", expression, re.IGNORECASE
    ):
        kinds.add(REQUEST_INPUT_KIND)
    if re.search(
        r"\b(?:llm|model|chat|openai|anthropic|gemini|agent)\."
        r"(?:invoke|predict|generate|generateContent|create|complete)\s*\(",
        expression,
        re.IGNORECASE,
    ):
        kinds.add(MODEL_OUTPUT_KIND)
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

    patterns = (
        (JS_SHELL_SINK, SHELL_RULE, "javascript_shell_or_eval", "CRITICAL"),
        (JS_INTERPRETER_COMMAND, SHELL_RULE, "interpreter_command_flag", "CRITICAL"),
        (JS_DYNAMIC_EXECUTABLE, DYNAMIC_EXECUTABLE_RULE, "dynamic_executable", "HIGH"),
    )
    hits: list[FlowHit] = []
    for pattern, rule_id, sink_kind, severity in patterns:
        for match in pattern.finditer(document.text):
            variable = next((group for group in match.groups() if group), None)
            kinds = variable_kinds.get(variable or "", set())
            if not kinds:
                continue
            hits.append(FlowHit(
                rule_id=rule_id,
                severity=severity,
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
    titles = {
        SHELL_RULE: "Untrusted input reaches a shell or dynamic-code execution sink",
        DYNAMIC_EXECUTABLE_RULE: "Untrusted input selects the executable to launch",
        DYNAMIC_IMPORT_RULE: "Untrusted input selects a module for dynamic import",
    }
    categories = {
        SHELL_RULE: "untrusted_code_execution",
        DYNAMIC_EXECUTABLE_RULE: "dynamic_executable_selection",
        DYNAMIC_IMPORT_RULE: "dynamic_module_loading",
    }
    return finding_dict(
        id=finding_id,
        title=titles[hit.rule_id],
        category=categories[hit.rule_id],
        severity="MEDIUM" if test_context else hit.severity,
        analyzer=ANALYZER_ID,
        location={"file": hit.relative_path, "line": hit.line},
        evidence=(
            f"verified_flow={','.join(evidence_codes)}; file={hit.relative_path}; "
            "raw_value_retained=false"
        ),
        description=(
            "A bounded static variable-flow trace links explicit external input or model output "
            "to a shell, dynamic-code, dynamic-module, or executable-selection sink. Fixed executable "
            "argument arrays do not trigger this rule family."
        ) + context_note,
        remediation=(
            "Replace dynamic execution with an allowlisted operation map; keep shell disabled, use a "
            "fixed executable and typed argv, validate every parameter, and require explicit approval "
            "for privileged actions."
        ),
        rule_id=hit.rule_id,
    )


def analyze_untrusted_exec_flows(skill_root: Path) -> tuple[list[dict], list[str]]:
    """Find explicit untrusted-input-to-execution flows without executing Skill code."""
    documents = _read_documents(skill_root)
    hits: list[FlowHit] = []
    for document in documents:
        if document.suffix in PYTHON_EXTENSIONS:
            hits.extend(_python_flow_hits(document))
        elif document.suffix in JAVASCRIPT_EXTENSIONS:
            hits.extend(_javascript_flow_hits(document))
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
