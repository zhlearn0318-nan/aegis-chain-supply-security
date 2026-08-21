from __future__ import annotations

from pathlib import Path

import pytest

from backend import app as gateway
from backend.adapters.process import AdapterResult
from backend.analyzers.static_coverage import ANALYZER_ID, analyze_static_coverage
from backend.models import ScanJob
from backend.policy import evaluate_findings


def write_skill(root: Path, files: dict[str, str | bytes]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    return root


def rule_map(findings: list[dict]) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    for finding in findings:
        result.setdefault(str(finding["rule_id"]), []).append(finding)
    return result


def test_valid_source_has_info_summary_and_allows(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: valid\n---\n",
        "scripts/main.py": "print('ready')\n",
        "config/settings.yaml": "mode: safe\n",
    })
    findings, analyzers = analyze_static_coverage(root)
    mapped = rule_map(findings)
    assert analyzers == [ANALYZER_ID]
    assert list(mapped) == ["AEGIS_STATIC_COVERAGE_SUMMARY"]
    assert "security_text_inspected:3" in findings[0]["evidence"]
    assert evaluate_findings(findings).decision.value == "ALLOW"


def test_large_code_file_requires_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: large-code\n---\n",
        "scripts/generated.py": "x = 1\n" + ("# padding\n" * 120_000),
    })
    findings, _ = analyze_static_coverage(root)
    assert "AEGIS_STATIC_CODE_FILE_SKIPPED_TOO_LARGE" in rule_map(findings)
    assert evaluate_findings(findings).decision.value == "REVIEW"


def test_large_non_code_data_is_counted_without_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: large-data\n---\n",
        "data/corpus.txt": "A" * (2 * 1024 * 1024),
    })
    findings, _ = analyze_static_coverage(root)
    assert list(rule_map(findings)) == ["AEGIS_STATIC_COVERAGE_SUMMARY"]
    assert "non_code_data_counted:1" in findings[0]["evidence"]


def test_nested_archive_requires_review_without_unpacking(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: nested\n---\n",
        "payload/archive.zip": b"PK\x03\x04not-opened",
    })
    findings, _ = analyze_static_coverage(root)
    assert "AEGIS_STATIC_NESTED_ARCHIVE_UNINSPECTED" in rule_map(findings)


def test_native_binary_requires_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: binary\n---\n",
        "bin/helper.exe": b"MZ\x00\x00",
    })
    findings, _ = analyze_static_coverage(root)
    assert "AEGIS_STATIC_NATIVE_EXECUTABLE_UNINSPECTED" in rule_map(findings)


def test_unsupported_notebook_requires_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: notebook\n---\n",
        "analysis.ipynb": "{}",
    })
    findings, _ = analyze_static_coverage(root)
    assert "AEGIS_STATIC_UNSUPPORTED_CODE_UNINSPECTED" in rule_map(findings)


def test_invalid_python_requires_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: invalid-python\n---\n",
        "scripts/broken.py": "def broken(:\n    pass\n",
    })
    findings, _ = analyze_static_coverage(root)
    assert "AEGIS_STATIC_PYTHON_PARSE_FAILED" in rule_map(findings)
    summary = rule_map(findings)["AEGIS_STATIC_COVERAGE_SUMMARY"][0]
    assert "python_parse_failed:1" in summary["evidence"]


def test_binary_content_in_text_extension_requires_review(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: disguised\n---\n",
        "scripts/disguised.py": b"MZ\x00payload",
    })
    findings, _ = analyze_static_coverage(root)
    assert "AEGIS_STATIC_TEXT_DECODE_LOSS" in rule_map(findings)


def test_missing_skill_manifest_fails_closed(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {"scripts/main.py": "pass\n"})
    with pytest.raises(ValueError, match="missing SKILL.md"):
        analyze_static_coverage(root)


def test_file_count_limit_fails_closed(tmp_path: Path, monkeypatch) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: many\n---\n",
        "scripts/a.py": "pass\n",
    })
    monkeypatch.setattr("backend.analyzers.static_coverage.MAX_FILES", 1)
    with pytest.raises(ValueError, match="more than 1 files"):
        analyze_static_coverage(root)


def test_summary_and_gap_ids_are_deterministic(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: stable\n---\n",
        "bin/helper.wasm": b"\x00asm",
    })
    first, _ = analyze_static_coverage(root)
    second, _ = analyze_static_coverage(root)
    assert first == second
    assert all("raw_value_retained=false" in item["evidence"] for item in first)


def test_scan_skill_path_exposes_coverage_analyzer(tmp_path: Path, monkeypatch) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: integrated-coverage\n---\n",
        "scripts/main.py": "print('ok')\n",
    })
    report = {"results": [{"skill_name": "integrated-coverage", "analyzers_used": ["static_analyzer"], "findings": []}]}

    class FakeAdapter:
        def scan(self, _path: Path) -> AdapterResult:
            return AdapterResult(report=report, logs=["completed"])

    job = ScanJob(
        id="coverage-integration",
        created_at="2026-08-21T00:00:00+00:00",
        updated_at="2026-08-21T00:00:00+00:00",
        status="running",
        target_kind="skill",
        source_kind="upload",
        display_name="integrated-coverage.zip",
    ).model_dump(mode="json")
    monkeypatch.setattr(gateway, "SKILL_ADAPTER", FakeAdapter())
    monkeypatch.setattr(gateway, "save_job", lambda _job: None)
    gateway.scan_skill_path(job, root)
    assert job["status"] == "completed"
    assert job["decision"] == "ALLOW"
    assert ANALYZER_ID in job["analyzers"]
    assert "AEGIS_STATIC_COVERAGE_SUMMARY" in {
        finding["rule_id"] for finding in job["findings"]
    }
