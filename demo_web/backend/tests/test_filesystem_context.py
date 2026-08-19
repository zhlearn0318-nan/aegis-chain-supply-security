from __future__ import annotations

import time
from pathlib import Path

from backend import app as gateway
from backend.adapters import AdapterResult
from backend.analyzers.filesystem_context import ANALYZER_ID, analyze_filesystem_context
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


def cisco_filesystem_finding(severity: str = "HIGH") -> dict:
    return {
        "id": "cisco-filesystem-1",
        "title": "Filesystem access",
        "category": "data_exfiltration",
        "severity": severity,
        "analyzer": "static",
        "location": {"file": "scripts/files.py", "line": 4},
        "evidence": "",
        "description": "",
        "remediation": "",
        "rule_id": "DATA_EXFIL_JS_FS_ACCESS",
    }


def test_declared_read_only_workspace_access_emits_supporting_info(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: reader\n---\nRead a local file inside the skill workspace.\n",
        "scripts/read.js": "const text = fs.readFileSync(path.join(__dirname, 'data/input.txt'), 'utf8');\n",
    })

    findings, analyzers = analyze_filesystem_context(root, [cisco_filesystem_finding()])
    rules = rule_map(findings)

    assert analyzers == [ANALYZER_ID]
    assert "AEGIS_CONTEXT_FILESYSTEM_CAPABILITY_DECLARED" in rules
    assert "AEGIS_CONTEXT_READ_ONLY_FILESYSTEM_BEHAVIOR" in rules
    assert "AEGIS_CONTEXT_WORKSPACE_OR_TEMP_PATH" in rules
    assert all(item["severity"] == "INFO" for item in findings)
    assert "DATA_EXFIL_JS_FS_ACCESS" in rules[
        "AEGIS_CONTEXT_FILESYSTEM_CAPABILITY_DECLARED"
    ]["evidence"]


def test_undeclared_filesystem_behavior_emits_review_context_only(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: notifier\n---\nSend a daily reminder.\n",
        "scripts/run.js": "const value = fs.readFileSync(userPath, 'utf8');\n",
    })

    findings, _ = analyze_filesystem_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_FILESYSTEM_BEHAVIOR_UNDECLARED" in rules
    assert rules["AEGIS_CONTEXT_FILESYSTEM_BEHAVIOR_UNDECLARED"]["severity"] == "INFO"


def test_declared_write_and_overwrite_capability_preserve_policy(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: exporter\n---\nWrite a local file to the output directory.\n",
        "scripts/export.js": "fs.writeFileSync(path.join(outputDir, 'report.json'), report);\n",
    })
    cisco = [cisco_filesystem_finding("MEDIUM")]
    before = evaluate_findings(cisco).decision.value

    context, _ = analyze_filesystem_context(root, cisco)
    rules = rule_map(context)
    after = evaluate_findings(cisco + context).decision.value

    assert "AEGIS_CONTEXT_FILE_WRITE_BEHAVIOR_DECLARED" in rules
    assert "AEGIS_CONTEXT_OVERWRITE_CAPABLE_FILE_WRITE" in rules
    assert before == after == "REVIEW"


def test_undeclared_write_is_advisory_only(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: formatter\n---\nFormat a document.\n",
        "run.py": "from pathlib import Path\nPath(destination).write_text(result)\n",
    })

    findings, _ = analyze_filesystem_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_FILE_WRITE_BEHAVIOR_NOT_EXPLICITLY_DECLARED" in rules
    assert evaluate_findings(findings).decision.value == "ALLOW"


def test_sensitive_path_access_does_not_claim_exact_binding(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: key-check\n---\nRead a credential file selected by the user.\n",
        "scripts/check.js": "const key = fs.readFileSync(path.join(home, '.ssh/id_rsa'), 'utf8');\n",
    })

    findings, _ = analyze_filesystem_context(root, [])
    finding = rule_map(findings)["AEGIS_CONTEXT_SENSITIVE_PATH_ACCESS"]

    assert finding["severity"] == "INFO"
    assert "path_binding_not_proven" in finding["evidence"]


def test_declared_recursive_delete_is_separate_mutation_context(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: cleaner\n---\nDelete files from the temporary output directory.\n",
        "scripts/clean.js": "fs.rmSync(target, { recursive: true, force: true });\n",
    })

    findings, _ = analyze_filesystem_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_DESTRUCTIVE_FILE_MUTATION_DECLARED" in rules
    assert "AEGIS_CONTEXT_RECURSIVE_FILESYSTEM_MUTATION" in rules
    assert all(item["severity"] == "INFO" for item in findings)


def test_path_containment_guard_is_recorded_as_unproven_mitigation(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: profile\n---\nRead and write a local profile file.\n",
        "scripts/profile.js": (
            "const resolved = path.resolve(root, name + '.json');\n"
            "if (!resolved.startsWith(path.resolve(root) + path.sep)) throw new Error('bad path');\n"
            "fs.writeFileSync(resolved, data);\n"
        ),
    })

    findings, _ = analyze_filesystem_context(root, [])
    finding = rule_map(findings)["AEGIS_CONTEXT_PATH_CONTAINMENT_GUARD"]

    assert finding["severity"] == "INFO"
    assert "guard_correctness_not_proven" in finding["evidence"]


def test_declared_sdk_filesystem_with_cisco_finding_has_declaration_only_context(
    tmp_path: Path,
) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: importer\n---\nRead a local file through the vendor document SDK.\n",
        "scripts/import.py": "document = vendor_sdk.load_document(source)\n",
    })

    findings, _ = analyze_filesystem_context(root, [cisco_filesystem_finding()])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_FILESYSTEM_CAPABILITY_DECLARED_NO_DIRECT_PRIMITIVE" in rules
    assert all(item["severity"] == "INFO" for item in findings)


def test_skill_without_filesystem_behavior_has_no_context_findings(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: calculator\n---\nCalculate a sum.\n",
        "run.py": "print(sum(values))\n",
    })

    findings, analyzers = analyze_filesystem_context(root, [])

    assert findings == []
    assert analyzers == [ANALYZER_ID]


def test_context_layer_preserves_allow_and_block_decisions(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: reader\n---\nRead a local file.\n",
        "run.py": "from pathlib import Path\ntext = Path(source).read_text()\n",
    })
    context, _ = analyze_filesystem_context(root, [])

    assert evaluate_findings([]).decision.value == "ALLOW"
    assert evaluate_findings(context).decision.value == "ALLOW"
    assert evaluate_findings([cisco_filesystem_finding()]).decision.value == "BLOCK"
    assert evaluate_findings([cisco_filesystem_finding(), *context]).decision.value == "BLOCK"


def test_repeated_filesystem_features_are_bounded(tmp_path: Path) -> None:
    repeated = "\n".join("const value = fs.readFileSync(source, 'utf8');" for _ in range(3000))
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: batch-reader\n---\nRead local files.\n",
        "run.js": repeated,
    })

    started = time.perf_counter()
    findings, _ = analyze_filesystem_context(root, [])

    assert time.perf_counter() - started < 2.0
    assert "AEGIS_CONTEXT_READ_ONLY_FILESYSTEM_BEHAVIOR" in rule_map(findings)


def test_scan_skill_path_exposes_filesystem_analyzer_and_preserves_block(
    tmp_path: Path, monkeypatch
) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: exporter\n---\nWrite a local file to the output directory.\n",
        "scripts/export.js": "fs.writeFileSync(path.join(outputDir, 'report.json'), report);\n",
    })
    report = {
        "results": [{
            "skill_name": "exporter",
            "analyzers_used": ["static_analyzer"],
            "findings": [{
                "id": "cisco-filesystem-1",
                "title": "Filesystem access",
                "category": "data_exfiltration",
                "severity": "high",
                "analyzer": "static",
                "file_path": "scripts/export.js",
                "line_number": 1,
                "rule_id": "DATA_EXFIL_JS_FS_ACCESS",
            }],
        }]
    }

    class FakeAdapter:
        def scan(self, _path: Path) -> AdapterResult:
            return AdapterResult(report=report, logs=["completed"])

    job = ScanJob(
        id="filesystem-context-integration",
        created_at="2026-08-18T00:00:00+00:00",
        updated_at="2026-08-18T00:00:00+00:00",
        status="running",
        target_kind="skill",
        source_kind="upload",
        display_name="exporter.zip",
    ).model_dump(mode="json")
    monkeypatch.setattr(gateway, "SKILL_ADAPTER", FakeAdapter())
    monkeypatch.setattr(gateway, "save_job", lambda _job: None)

    gateway.scan_skill_path(job, root)

    assert job["status"] == "completed"
    assert job["decision"] == "BLOCK"
    assert ANALYZER_ID in job["analyzers"]
    assert any(item["analyzer"] == ANALYZER_ID for item in job["findings"])
