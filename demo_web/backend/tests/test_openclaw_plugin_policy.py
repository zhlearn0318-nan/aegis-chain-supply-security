from __future__ import annotations

import json
from pathlib import Path

from backend.analyzers.plugin_package import analyze_plugin_package
from backend.openclaw_install_policy import evaluate_install_request


ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "fixtures" / "openclaw_plugins"


def request_for(path: Path, name: str = "plugin-fixture", **overrides) -> dict:
    payload = {
        "protocolVersion": 1,
        "openclawVersion": "2026.8.1",
        "targetType": "plugin",
        "targetName": name,
        "sourcePath": str(path.resolve()),
        "sourcePathKind": "directory",
        "origin": {"type": "plugin-git"},
        "request": {"kind": "plugin-git", "mode": "install"},
        "plugin": {"contentType": "package", "pluginId": name},
    }
    payload.update(overrides)
    return payload


def rules(response: dict) -> set[str]:
    return {item["ruleId"] for item in response.get("findings", [])}


def test_benign_native_plugin_with_local_mcp_server_is_allowed() -> None:
    response = evaluate_install_request(
        request_for(FIXTURES / "benign_mcp_plugin", "aegis-benign-mcp")
    )

    assert response["decision"] == "allow"
    assert rules(response) == {"AEGIS_PLUGIN_COVERAGE_SUMMARY"}


def test_runtime_fetch_lifecycle_and_embedded_secret_plugin_is_blocked() -> None:
    response = evaluate_install_request(
        request_for(FIXTURES / "malicious_runtime_fetch", "aegis-malicious-runtime-fetch")
    )

    assert response["decision"] == "block"
    assert {
        "AEGIS_PLUGIN_MCP_RUNTIME_PACKAGE_FETCH",
        "AEGIS_PLUGIN_MCP_EMBEDDED_SECRET",
        "AEGIS_PLUGIN_LIFECYCLE_SCRIPT",
    }.issubset(rules(response))


def test_compatible_bundle_requires_review(tmp_path: Path) -> None:
    (tmp_path / "plugin.json").write_text('{"name":"compatible"}', encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"name":"compatible","version":"1.0.0"}', encoding="utf-8"
    )

    response = evaluate_install_request(request_for(tmp_path))

    assert response["decision"] == "warn"
    assert "AEGIS_PLUGIN_COMPATIBLE_BUNDLE_REVIEW" in rules(response)


def test_plugin_entry_escape_is_critical(tmp_path: Path) -> None:
    (tmp_path / "openclaw.plugin.json").write_text(
        '{"id":"escape","configSchema":{}}', encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "escape",
                "version": "1.0.0",
                "openclaw": {"extensions": ["../outside.js"]},
            }
        ),
        encoding="utf-8",
    )

    findings, _ = analyze_plugin_package(tmp_path)

    by_rule = {item["rule_id"]: item for item in findings}
    assert by_rule["AEGIS_PLUGIN_ENTRY_ESCAPE"]["severity"] == "CRITICAL"


def test_plugin_file_source_remains_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "plugin.mjs"
    source.write_text("export default function () {}", encoding="utf-8")

    response = evaluate_install_request(
        request_for(source, sourcePathKind="file")
    )

    assert response["decision"] == "block"
    assert response["findings"][0]["ruleId"] == "AEGIS_POLICY_INVALID_REQUEST"
