from __future__ import annotations

from pathlib import Path
import json
import subprocess

from backend.install_policy_audit import read_recent_install_policy_audits, verify_install_policy_audit
from backend.mcp_server_admission import admit_mcp_server, analyze_mcp_server_definition


def configure_paths(monkeypatch, tmp_path: Path) -> Path:
    audit = tmp_path / "audit.db"
    monkeypatch.setenv("AEGIS_OPENCLAW_AUDIT_DB", str(audit))
    monkeypatch.setenv("AEGIS_CUSTOM_RULES_PATH", str(tmp_path / "rules.json"))
    return audit


def test_safe_https_definition_is_allowed_without_commit(monkeypatch, tmp_path: Path) -> None:
    audit = configure_paths(monkeypatch, tmp_path)
    result = admit_mcp_server(
        {
            "name": "internal-docs",
            "server": {
                "url": "https://mcp.example.com/mcp",
                "transport": "streamable-http",
                "auth": "oauth",
                "toolFilter": {"include": ["search", "read_*"]},
            },
        },
        commit=False,
    )
    assert result["decision"] == "ALLOW"
    assert result["accepted"] is True
    assert result["saved"] is False
    assert verify_install_policy_audit(audit)["valid"] is True
    row = read_recent_install_policy_audits(audit, limit=1)[0]
    assert row["target_type"] == "mcp"
    assert row["target_name"] == "internal-docs"


def test_runtime_downloader_and_literal_secret_are_blocked(monkeypatch, tmp_path: Path) -> None:
    audit = configure_paths(monkeypatch, tmp_path)
    result = admit_mcp_server(
        {
            "name": "unsafe-server",
            "server": {
                "command": "npx",
                "args": ["-y", "latest-package"],
                "env": {"API_KEY": "literal-secret"},
                "toolFilter": {"include": ["read"]},
            },
        },
        commit=False,
    )
    assert result["decision"] == "BLOCK"
    assert result["saved"] is False
    assert "AEGIS_MCP_RUNTIME_PACKAGE_FETCH" in result["finding_rule_ids"]
    assert "AEGIS_MCP_EMBEDDED_SECRET" in result["finding_rule_ids"]
    assert verify_install_policy_audit(audit)["rows"] == 1


def test_injection_environment_is_critical() -> None:
    findings, analyzers = analyze_mcp_server_definition(
        "local-tools",
        {"command": "node", "args": ["server.js"], "env": {"NODE_OPTIONS": "--require hook.js"}},
    )
    assert analyzers == ["aegis-openclaw-mcp-config-v1"]
    rules = {finding["rule_id"]: finding for finding in findings}
    assert rules["AEGIS_MCP_ENV_INJECTION"]["severity"] == "CRITICAL"


def test_non_https_remote_is_blocked() -> None:
    findings, _ = analyze_mcp_server_definition(
        "remote", {"url": "http://example.com/mcp", "toolFilter": {"include": ["search"]}}
    )
    assert "AEGIS_MCP_INSECURE_REMOTE" in {finding["rule_id"] for finding in findings}


def test_loopback_http_is_allowed_by_config_analyzer() -> None:
    findings, _ = analyze_mcp_server_definition(
        "local", {"url": "http://127.0.0.1:9000/mcp", "toolFilter": {"include": ["read"]}}
    )
    assert "AEGIS_MCP_INSECURE_REMOTE" not in {finding["rule_id"] for finding in findings}


def configure_fake_openclaw(monkeypatch, tmp_path: Path) -> None:
    node = tmp_path / "node.exe"
    module = tmp_path / "openclaw.mjs"
    node.write_bytes(b"node")
    module.write_text("// openclaw", encoding="utf-8")
    monkeypatch.setenv("AEGIS_OPENCLAW_NODE", str(node))
    monkeypatch.setenv("AEGIS_OPENCLAW_MJS", str(module))


def safe_commit_request() -> dict:
    return {
        "name": "internal-docs",
        "server": {
            "url": "https://mcp.example.com/mcp",
            "transport": "streamable-http",
            "auth": "oauth",
            "toolFilter": {"include": ["read_*"]},
        },
    }


def completed(command: list[str], returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_commit_snapshots_sets_and_verifies_exact_configuration(monkeypatch, tmp_path: Path) -> None:
    configure_paths(monkeypatch, tmp_path)
    configure_fake_openclaw(monkeypatch, tmp_path)
    request = safe_commit_request()
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        action = command[3]
        if action == "show" and len(calls) == 1:
            return completed(command, 1, stderr='No MCP server named "internal-docs"')
        if action == "set":
            return completed(command, 0)
        return completed(command, 0, json.dumps(request["server"]))

    result = admit_mcp_server(request, run_command=runner)
    assert result["accepted"] is True
    assert result["saved"] is True
    assert [call[3] for call in calls] == ["show", "set", "show"]


def test_verify_mismatch_restores_existing_configuration(monkeypatch, tmp_path: Path) -> None:
    configure_paths(monkeypatch, tmp_path)
    configure_fake_openclaw(monkeypatch, tmp_path)
    request = safe_commit_request()
    previous = {"url": "https://old.example.com/mcp", "toolFilter": {"include": ["old_read"]}}
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if len(calls) == 1:
            return completed(command, 0, json.dumps(previous))
        if len(calls) == 2:
            return completed(command, 0)
        if len(calls) == 3:
            return completed(command, 0, json.dumps({"url": "https://wrong.example.com"}))
        return completed(command, 0)

    result = admit_mcp_server(request, run_command=runner)
    assert result["decision"] == "BLOCK"
    assert result["saved"] is False
    assert "AEGIS_MCP_CONFIG_VERIFY_FAILED" in result["finding_rule_ids"]
    assert [call[3] for call in calls] == ["show", "set", "show", "set"]
    assert json.loads(calls[-1][5]) == previous


def test_snapshot_transport_failure_prevents_write(monkeypatch, tmp_path: Path) -> None:
    configure_paths(monkeypatch, tmp_path)
    configure_fake_openclaw(monkeypatch, tmp_path)
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return completed(command, 2, stderr="gateway unavailable")

    result = admit_mcp_server(safe_commit_request(), run_command=runner)
    assert result["decision"] == "BLOCK"
    assert "AEGIS_MCP_CONFIG_SNAPSHOT_FAILED" in result["finding_rule_ids"]
    assert [call[3] for call in calls] == ["show"]
