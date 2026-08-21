from __future__ import annotations

from pathlib import Path

from backend import app as gateway
from backend.adapters.process import AdapterResult
from backend.analyzers.untrusted_exec_flow import (
    ANALYZER_ID,
    analyze_untrusted_exec_flows,
)
from backend.models import ScanJob
from backend.policy import evaluate_findings


def write_skill(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def rule_map(findings: list[dict]) -> dict[str, dict]:
    return {str(item["rule_id"]): item for item in findings}


def test_tool_handler_parameter_to_os_system_is_critical(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: unsafe-tool\n---\n",
        "scripts/tool.py": "\n".join([
            "import os",
            "from framework import tool",
            "@tool",
            "def run_command(command: str):",
            "    os.system(command)",
        ]),
    })

    findings, analyzers = analyze_untrusted_exec_flows(root)
    finding = rule_map(findings)["AEGIS_UNTRUSTED_INPUT_TO_SHELL_OR_EVAL"]

    assert analyzers == [ANALYZER_ID]
    assert finding["severity"] == "CRITICAL"
    assert finding["location"] == {"file": "scripts/tool.py", "line": 5}
    assert "run_command" not in finding["evidence"]
    assert "unsafe-tool" not in finding["evidence"]
    assert "raw_value_retained=false" in finding["evidence"]
    assert evaluate_findings(findings).decision.value == "BLOCK"


def test_http_request_to_eval_is_critical(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: unsafe-api\n---\n",
        "scripts/api.py": "\n".join([
            "from flask import Flask, request",
            "app = Flask(__name__)",
            "@app.post('/calculate')",
            "def calculate():",
            "    expression = request.json.get('expression')",
            "    return str(eval(expression))",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert rule_map(findings)["AEGIS_UNTRUSTED_INPUT_TO_SHELL_OR_EVAL"]["severity"] == "CRITICAL"


def test_interprocedural_tool_input_to_shell_is_detected(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: unsafe-helper\n---\n",
        "scripts/tool.py": "\n".join([
            "import subprocess",
            "from framework import tool",
            "def execute(value):",
            "    subprocess.run(value, shell=True)",
            "@tool",
            "def operate(user_value):",
            "    return execute(user_value)",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert "AEGIS_UNTRUSTED_INPUT_TO_SHELL_OR_EVAL" in rule_map(findings)


def test_model_output_to_interpreter_command_flag_is_detected(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: model-shell\n---\n",
        "scripts/agent.py": "\n".join([
            "import subprocess",
            "response = llm.invoke('prepare a command')",
            "command = response.content",
            "subprocess.run(['bash', '-c', command])",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert rule_map(findings)["AEGIS_UNTRUSTED_INPUT_TO_SHELL_OR_EVAL"]["severity"] == "CRITICAL"


def test_cli_input_selecting_executable_is_high(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: dynamic-tool\n---\n",
        "scripts/cli.py": "\n".join([
            "import subprocess, sys",
            "program = sys.argv[1]",
            "subprocess.run([program, '--version'], check=False)",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)
    finding = rule_map(findings)["AEGIS_UNTRUSTED_DYNAMIC_EXECUTABLE"]

    assert finding["severity"] == "HIGH"
    assert evaluate_findings(findings).decision.value == "BLOCK"


def test_cli_input_to_dynamic_import_is_high(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: dynamic-import\n---\n",
        "scripts/plugin.py": "\n".join([
            "import argparse, importlib",
            "parser = argparse.ArgumentParser()",
            "args = parser.parse_args()",
            "module = importlib.import_module(args.plugin)",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert rule_map(findings)["AEGIS_UNTRUSTED_DYNAMIC_IMPORT"]["severity"] == "HIGH"


def test_fixed_executable_with_untrusted_argv_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: safe-argv\n---\n",
        "scripts/search.py": "\n".join([
            "import subprocess",
            "query = input('query: ')",
            "subprocess.run(['/usr/bin/grep', '--fixed-strings', query, 'index.txt'])",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert findings == []


def test_fixed_executable_list_through_helper_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: safe-helper\n---\n",
        "scripts/cli.py": "\n".join([
            "import argparse, subprocess",
            "def run(command):",
            "    subprocess.check_call(command)",
            "def main():",
            "    parser = argparse.ArgumentParser()",
            "    args = parser.parse_args()",
            "    command = ['python', 'approved.py', '--query', args.query]",
            "    run(command)",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert findings == []


def test_constant_shell_command_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: constant-command\n---\n",
        "scripts/status.py": "\n".join([
            "import os",
            "message = input('note: ')",
            "os.system('systemctl status approved-service')",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert findings == []


def test_source_and_sink_cooccurrence_without_flow_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: unrelated\n---\n",
        "scripts/status.py": "\n".join([
            "import subprocess",
            "note = input('note: ')",
            "subprocess.run(['echo', 'healthy'], check=False)",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert findings == []


def test_security_fixture_is_not_policy_changing(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: security-tests\n---\n",
        "tests/test_injection.py": "\n".join([
            "import os",
            "payload = input('payload: ')",
            "os.system(payload)",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert findings == []


def test_javascript_request_body_to_execsync_is_detected(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: js-shell\n---\n",
        "scripts/server.js": "\n".join([
            "const childProcess = require('child_process');",
            "const command = req.body.command;",
            "const result = childProcess.execSync(command);",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert rule_map(findings)["AEGIS_UNTRUSTED_INPUT_TO_SHELL_OR_EVAL"]["severity"] == "CRITICAL"


def test_javascript_fixed_spawn_with_untrusted_argument_does_not_trigger(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: js-safe-argv\n---\n",
        "scripts/server.js": "\n".join([
            "const childProcess = require('child_process');",
            "const query = req.body.query;",
            "const result = childProcess.spawn('/usr/bin/grep', ['--fixed-strings', query]);",
        ]),
    })

    findings, _ = analyze_untrusted_exec_flows(root)

    assert findings == []


def test_finding_ids_are_deterministic(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: deterministic\n---\n",
        "scripts/tool.py": "\n".join([
            "import os",
            "value = input('value: ')",
            "os.system(value)",
        ]),
    })

    first, _ = analyze_untrusted_exec_flows(root)
    second, _ = analyze_untrusted_exec_flows(root)

    assert first == second


def test_scan_skill_path_exposes_analyzer_and_blocks(tmp_path: Path, monkeypatch) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: integrated-shell\n---\n",
        "scripts/tool.py": "\n".join([
            "import os",
            "from framework import tool",
            "@tool",
            "def execute(command):",
            "    os.system(command)",
        ]),
    })
    report = {
        "results": [{
            "skill_name": "integrated-shell",
            "analyzers_used": ["static_analyzer"],
            "findings": [],
        }]
    }

    class FakeAdapter:
        def scan(self, _path: Path) -> AdapterResult:
            return AdapterResult(report=report, logs=["completed"])

    job = ScanJob(
        id="untrusted-exec-integration",
        created_at="2026-08-21T00:00:00+00:00",
        updated_at="2026-08-21T00:00:00+00:00",
        status="running",
        target_kind="skill",
        source_kind="upload",
        display_name="integrated-shell.zip",
    ).model_dump(mode="json")
    monkeypatch.setattr(gateway, "SKILL_ADAPTER", FakeAdapter())
    monkeypatch.setattr(gateway, "save_job", lambda _job: None)

    gateway.scan_skill_path(job, root)

    assert job["status"] == "completed"
    assert job["decision"] == "BLOCK"
    assert ANALYZER_ID in job["analyzers"]
    assert any(item["analyzer"] == ANALYZER_ID for item in job["findings"])
