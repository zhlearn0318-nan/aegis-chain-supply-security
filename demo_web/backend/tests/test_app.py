from __future__ import annotations

import io
import json
import zipfile

import pytest

from backend import app as gateway


def make_zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (None, "ALLOW"),
        ("INFO", "ALLOW"),
        ("LOW", "REVIEW"),
        ("MEDIUM", "REVIEW"),
        ("HIGH", "BLOCK"),
        ("CRITICAL", "BLOCK"),
    ],
)
def test_decision_gate(severity: str | None, expected: str) -> None:
    findings = [] if severity is None else [{"severity": severity}]
    assert gateway.decision_from_findings(findings) == expected


def test_normalize_skill_preserves_auditable_evidence() -> None:
    report = {
        "results": [
            {
                "skill_name": "credential-exporter",
                "analyzers_used": ["static_analyzer", "bytecode"],
                "findings": [
                    {
                        "id": "DATA_EXFIL_HTTP_POST",
                        "title": "HTTP POST may exfiltrate data",
                        "category": "data_exfiltration",
                        "severity": "critical",
                        "analyzer": "static",
                        "file_path": "scripts/export.py",
                        "line_number": 13,
                        "snippet": "requests.post(endpoint, json=secrets)",
                        "rule_id": "DATA_EXFIL_HTTP_POST",
                    }
                ],
            }
        ]
    }

    findings, analyzers = gateway.normalize_skill(report)

    assert analyzers == ["bytecode", "static_analyzer"]
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["location"] == {
        "file": "scripts/export.py",
        "line": 13,
        "object": "credential-exporter",
    }
    assert findings[0]["evidence"] == "requests.post(endpoint, json=secrets)"
    assert findings[0]["rule_id"] == "DATA_EXFIL_HTTP_POST"


def test_normalize_skill_fails_closed_on_empty_report() -> None:
    with pytest.raises(RuntimeError, match="no result objects"):
        gateway.normalize_skill({})


def test_safe_extract_zip_accepts_one_skill(tmp_path) -> None:
    data = make_zip(
        {
            "example-skill/SKILL.md": "---\nname: example\n---\n",
            "example-skill/scripts/run.py": "print('safe fixture')\n",
        }
    )

    skill_path = gateway.safe_extract_zip(data, tmp_path)

    assert skill_path == tmp_path / "example-skill"
    assert (skill_path / "SKILL.md").is_file()


def test_safe_extract_zip_rejects_path_traversal(tmp_path) -> None:
    data = make_zip({"../outside/SKILL.md": "unsafe archive path"})

    with pytest.raises(ValueError, match="不安全的路径"):
        gateway.safe_extract_zip(data, tmp_path)


def test_write_mcp_parts_supports_contents_alias(tmp_path) -> None:
    payload = {
        "tools": [{"name": "search", "description": "Search public documents"}],
        "prompts": [],
        "contents": [{"uri": "policy://public", "text": "public policy"}],
    }

    tools, prompts, resources = gateway.write_mcp_parts(
        json.dumps(payload).encode("utf-8"), tmp_path
    )

    assert json.loads(tools.read_text(encoding="utf-8"))["tools"][0]["name"] == "search"
    assert json.loads(prompts.read_text(encoding="utf-8")) == {"prompts": []}
    assert json.loads(resources.read_text(encoding="utf-8"))["contents"][0]["uri"] == "policy://public"
