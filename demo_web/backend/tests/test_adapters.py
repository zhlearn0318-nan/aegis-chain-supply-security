from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Callable, Sequence

import pytest

from backend.adapters import (
    DependencyAuditAdapter,
    McpScannerAdapter,
    ProcessRunner,
    SkillScannerAdapter,
)


class FakeRunner:
    def __init__(
        self, handler: Callable[[list[str]], subprocess.CompletedProcess[str]]
    ):
        self.handler = handler
        self.commands: list[list[str]] = []

    def run(
        self,
        command: Sequence[str],
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        captured = [str(part) for part in command]
        self.commands.append(captured)
        return self.handler(captured)


def touch(path: Path, content: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_process_runner_forces_safe_subprocess_options(monkeypatch, tmp_path) -> None:
    captured: dict[str, object] = {}
    first_path = tmp_path / "runtime" / "Library" / "bin"
    second_path = tmp_path / "runtime" / "Scripts"
    first_path.mkdir(parents=True)
    second_path.mkdir()
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "must-not-leak")

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = ProcessRunner(
        timeout_seconds=17,
        cache_root=tmp_path / "cache",
        extra_path=(first_path, second_path),
    )

    runner.run(["scanner", "--flag", "value"])

    assert captured["command"] == ["scanner", "--flag", "value"]
    assert captured["shell"] is False
    assert captured["timeout"] == 17
    assert captured["encoding"] == "utf-8"
    assert captured["check"] is False
    assert "OPENAI_API_KEY" not in captured["env"]
    assert "VIRUSTOTAL_API_KEY" not in captured["env"]
    assert captured["env"]["HF_HUB_OFFLINE"] == "1"
    assert captured["env"]["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"
    assert captured["env"]["PATH"].split(os.pathsep)[:2] == [
        str(first_path),
        str(second_path),
    ]


@pytest.mark.parametrize("invalid", ["scanner --flag", [], ["bad\0argument"]])
def test_process_runner_rejects_unsafe_command_shapes(tmp_path, invalid) -> None:
    runner = ProcessRunner(timeout_seconds=1, cache_root=tmp_path / "cache")
    with pytest.raises((TypeError, ValueError)):
        runner.run(invalid)


def test_skill_adapter_builds_command_and_parses_json(tmp_path) -> None:
    scanner = touch(tmp_path / "skill-scanner.exe")
    skill = tmp_path / "example-skill"
    touch(skill / "SKILL.md", "---\nname: example\n---\n")

    def handler(command: list[str]) -> subprocess.CompletedProcess[str]:
        output = Path(command[command.index("--output-json") + 1])
        output.write_text(
            json.dumps({"results": [{"skill_name": "example", "findings": []}]}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "scan complete", "")

    runner = FakeRunner(handler)
    result = SkillScannerAdapter(scanner=scanner, runner=runner).scan(skill)

    assert result.report["results"][0]["skill_name"] == "example"
    assert result.logs == ["skill-scanner completed: results=1 findings=0 exit_code=0"]
    assert str(skill) not in " ".join(result.logs)
    assert runner.commands[0][:3] == [str(scanner), "scan", str(skill)]
    assert "--output-json" in runner.commands[0]


def test_skill_adapter_fails_closed_when_output_is_missing(tmp_path) -> None:
    scanner = touch(tmp_path / "skill-scanner.exe")
    skill = tmp_path / "example-skill"
    touch(skill / "SKILL.md")
    runner = FakeRunner(lambda command: subprocess.CompletedProcess(command, 0, "", ""))

    with pytest.raises(RuntimeError, match="Skill Scanner failed"):
        SkillScannerAdapter(scanner=scanner, runner=runner).scan(skill)


def test_skill_adapter_counts_single_result_report_without_retaining_paths(
    tmp_path,
) -> None:
    scanner = touch(tmp_path / "skill-scanner.exe")
    skill = tmp_path / "single-result-skill"
    touch(skill / "SKILL.md", "---\nname: single-result\n---\n")

    def handler(command: list[str]) -> subprocess.CompletedProcess[str]:
        output = Path(command[command.index("--output-json") + 1])
        output.write_text(
            json.dumps({"skill_name": "single-result", "findings": [{"id": "one"}]}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, f"saved to {output}", "")

    result = SkillScannerAdapter(scanner=scanner, runner=FakeRunner(handler)).scan(
        skill
    )

    assert result.logs == ["skill-scanner completed: results=1 findings=1 exit_code=0"]
    assert str(skill) not in " ".join(result.logs)


def test_mcp_adapter_builds_wrapper_command_and_parses_json(tmp_path) -> None:
    python = touch(tmp_path / "python.exe")
    wrapper = touch(tmp_path / "run_mcp_static.py")
    scanner = touch(tmp_path / "mcp-scanner.exe")
    tools = touch(tmp_path / "tools.json", '{"tools": []}')
    prompts = touch(tmp_path / "prompts.json", '{"prompts": []}')
    resources = touch(tmp_path / "resources.json", '{"contents": []}')

    def handler(command: list[str]) -> subprocess.CompletedProcess[str]:
        output = Path(command[command.index("--output") + 1])
        output.write_text(
            json.dumps({"scan_results": [{"status": "completed"}]}), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "mcp complete", "")

    runner = FakeRunner(handler)
    result = McpScannerAdapter(python, wrapper, scanner, runner).scan(
        tools, prompts, resources
    )

    assert result.report["scan_results"][0]["status"] == "completed"
    assert result.logs == ["mcp-scanner completed: results=1 unsafe=1 exit_code=0"]
    assert str(tools) not in " ".join(result.logs)
    assert runner.commands[0][:3] == [str(python), str(wrapper), "--scanner"]
    assert runner.commands[0][runner.commands[0].index("--tools") + 1] == str(tools)


def test_dependency_adapter_accepts_pip_audit_risk_exit_code(tmp_path) -> None:
    executable = touch(tmp_path / "pip-audit.exe")
    requirements = touch(tmp_path / "requirements.txt", "urllib3==1.24.1\n")
    report = {"dependencies": [{"name": "urllib3", "version": "1.24.1", "vulns": []}]}
    runner = FakeRunner(
        lambda command: subprocess.CompletedProcess(
            command, 1, json.dumps(report), "risk found"
        )
    )

    result = DependencyAuditAdapter(executable, tmp_path / "cache", runner).scan(
        requirements
    )

    assert result.report == report
    assert (
        result.logs[0]
        == "pip-audit completed: dependencies=1 vulnerabilities=0 exit_code=1"
    )
    assert json.dumps(report) not in " ".join(result.logs)
    assert "--disable-pip" in runner.commands[0]
    assert "--cache-dir" in runner.commands[0]


@pytest.mark.parametrize(
    "completed",
    [
        subprocess.CompletedProcess(["pip-audit"], 2, "", "tool failed"),
        subprocess.CompletedProcess(["pip-audit"], 0, "not-json", ""),
        subprocess.CompletedProcess(["pip-audit"], 0, '{"unexpected": []}', ""),
    ],
)
def test_dependency_adapter_fails_closed_on_incomplete_output(
    tmp_path, completed
) -> None:
    executable = touch(tmp_path / "pip-audit.exe")
    requirements = touch(tmp_path / "requirements.txt", "example==1.0\n")
    runner = FakeRunner(lambda command: completed)

    with pytest.raises(RuntimeError):
        DependencyAuditAdapter(executable, tmp_path / "cache", runner).scan(
            requirements
        )
