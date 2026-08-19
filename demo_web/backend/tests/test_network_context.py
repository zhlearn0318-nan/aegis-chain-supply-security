from __future__ import annotations

import time
from pathlib import Path

from backend import app as gateway
from backend.adapters import AdapterResult
from backend.analyzers.network_context import ANALYZER_ID, analyze_network_context
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


def cisco_network_finding(severity: str = "MEDIUM") -> dict:
    return {
        "id": "cisco-network-1",
        "title": "Network request",
        "category": "data_exfiltration",
        "severity": severity,
        "analyzer": "static",
        "location": {"file": "scripts/fetch.py", "line": 4},
        "evidence": "",
        "description": "",
        "remediation": "",
        "rule_id": "DATA_EXFIL_NETWORK_REQUESTS",
    }


def test_declared_read_only_business_api_emits_supporting_info(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: weather\n---\nFetch live weather data from the public REST API.\n",
        "scripts/fetch.py": "import requests\nresult = requests.get(api_url).json()\n",
    })

    findings, analyzers = analyze_network_context(root, [cisco_network_finding()])
    rules = rule_map(findings)

    assert analyzers == [ANALYZER_ID]
    assert "AEGIS_CONTEXT_NETWORK_CAPABILITY_DECLARED" in rules
    assert "AEGIS_CONTEXT_READ_ONLY_NETWORK_BEHAVIOR" in rules
    assert all(item["severity"] == "INFO" for item in findings)
    assert "DATA_EXFIL_NETWORK_REQUESTS" in rules[
        "AEGIS_CONTEXT_NETWORK_CAPABILITY_DECLARED"
    ]["evidence"]


def test_undeclared_network_behavior_emits_review_context_only(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: formatter\n---\nFormat a local document.\n",
        "scripts/format.py": "import requests\ntext = requests.get(url).text\n",
    })

    findings, _ = analyze_network_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_NETWORK_BEHAVIOR_UNDECLARED" in rules
    assert rules["AEGIS_CONTEXT_NETWORK_BEHAVIOR_UNDECLARED"]["severity"] == "INFO"


def test_declared_outbound_behavior_is_recorded_without_policy_change(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: reporter\n---\nUpload the report to the configured webhook API.\n",
        "scripts/report.py": "import requests\nrequests.post(webhook_url, json=report)\n",
    })
    cisco = [cisco_network_finding()]
    before = evaluate_findings(cisco).decision.value

    context, _ = analyze_network_context(root, cisco)
    after = evaluate_findings(cisco + context).decision.value

    assert "AEGIS_CONTEXT_OUTBOUND_BEHAVIOR_DECLARED" in rule_map(context)
    assert before == after == "REVIEW"


def test_sensitive_source_and_outbound_sink_are_advisory_not_exfil_proof(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: sync\n---\nSend selected data to the remote sync API.\n",
        "scripts/sync.py": (
            "import os, requests\n"
            "token = os.getenv('ACCESS_TOKEN')\n"
            "requests.post(endpoint, json={'token': token})\n"
        ),
    })

    findings, _ = analyze_network_context(root, [])
    finding = rule_map(findings)["AEGIS_CONTEXT_SENSITIVE_SOURCE_WITH_OUTBOUND_SINK"]

    assert finding["severity"] == "INFO"
    assert "data_flow_not_proven" in finding["evidence"]
    assert evaluate_findings(findings).decision.value == "ALLOW"


def test_network_auth_context_is_distinct_from_sensitive_flow(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: client\n---\nCall the API using an authentication token.\n",
        "scripts/client.py": (
            "import os, requests\n"
            "token = os.getenv('API_TOKEN')\n"
            "headers = {'Authorization': 'Bearer ' + token}\n"
            "requests.post(endpoint, headers=headers, json=payload)\n"
        ),
    })

    findings, _ = analyze_network_context(root, [])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_CREDENTIAL_USED_FOR_NETWORK_AUTH" in rules
    assert rules["AEGIS_CONTEXT_CREDENTIAL_USED_FOR_NETWORK_AUTH"]["severity"] == "INFO"


def test_skill_without_network_behavior_has_no_context_findings(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: local-summary\n---\nSummarize a local text file.\n",
        "scripts/run.py": "print(document)\n",
    })

    findings, analyzers = analyze_network_context(root, [])

    assert findings == []
    assert analyzers == [ANALYZER_ID]


def test_declared_sdk_network_with_cisco_finding_has_declaration_only_context(
    tmp_path: Path,
) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: video\n---\nUse the vendor API through WangcutAPI SDK.\n",
        "scripts/client.py": "from vendor import WangcutAPI\nclient = WangcutAPI()\n",
    })

    findings, _ = analyze_network_context(root, [cisco_network_finding()])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_NETWORK_CAPABILITY_DECLARED_NO_DIRECT_PRIMITIVE" in rules
    assert all(item["severity"] == "INFO" for item in findings)


def test_mock_local_network_declaration_is_recorded_without_assuming_runtime(
    tmp_path: Path,
) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": (
            "---\nname: chart-tests\n---\n"
            "Mock HTTP interactions use localhost only. No external network access required.\n"
        ),
    })

    findings, _ = analyze_network_context(root, [cisco_network_finding()])
    rules = rule_map(findings)

    assert "AEGIS_CONTEXT_NETWORK_MOCK_OR_LOCAL_ONLY_DECLARED" in rules
    assert evaluate_findings(findings).decision.value == "ALLOW"


def test_context_layer_preserves_allow_and_block_decisions(tmp_path: Path) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: api\n---\nFetch data from a public API.\n",
        "run.py": "import requests\nrequests.get(url)\n",
    })
    context, _ = analyze_network_context(root, [])

    assert evaluate_findings([]).decision.value == "ALLOW"
    assert evaluate_findings(context).decision.value == "ALLOW"
    assert evaluate_findings([cisco_network_finding("CRITICAL")]).decision.value == "BLOCK"
    assert evaluate_findings([cisco_network_finding("CRITICAL"), *context]).decision.value == "BLOCK"


def test_repeated_network_features_are_bounded(tmp_path: Path) -> None:
    repeated = "\n".join("result = requests.get(url)" for _ in range(3000))
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: flood\n---\nFetch data from an API.\n",
        "run.py": repeated,
    })

    started = time.perf_counter()
    findings, _ = analyze_network_context(root, [])

    assert time.perf_counter() - started < 2.0
    assert "AEGIS_CONTEXT_READ_ONLY_NETWORK_BEHAVIOR" in rule_map(findings)


def test_scan_skill_path_exposes_context_analyzer_and_preserves_review(
    tmp_path: Path, monkeypatch
) -> None:
    root = write_skill(tmp_path / "skill", {
        "SKILL.md": "---\nname: weather\n---\nFetch weather from the public API.\n",
        "scripts/fetch.py": "import requests\nrequests.get(url)\n",
    })
    report = {
        "results": [{
            "skill_name": "weather",
            "analyzers_used": ["static_analyzer"],
            "findings": [{
                "id": "cisco-network-1",
                "title": "Network request",
                "category": "data_exfiltration",
                "severity": "medium",
                "analyzer": "static",
                "file_path": "scripts/fetch.py",
                "line_number": 2,
                "rule_id": "DATA_EXFIL_NETWORK_REQUESTS",
            }],
        }]
    }

    class FakeAdapter:
        def scan(self, _path: Path) -> AdapterResult:
            return AdapterResult(report=report, logs=["completed"])

    job = ScanJob(
        id="context-integration",
        created_at="2026-08-18T00:00:00+00:00",
        updated_at="2026-08-18T00:00:00+00:00",
        status="running",
        target_kind="skill",
        source_kind="upload",
        display_name="weather.zip",
    ).model_dump(mode="json")
    monkeypatch.setattr(gateway, "SKILL_ADAPTER", FakeAdapter())
    monkeypatch.setattr(gateway, "save_job", lambda _job: None)

    gateway.scan_skill_path(job, root)

    assert job["status"] == "completed"
    assert job["decision"] == "REVIEW"
    assert ANALYZER_ID in job["analyzers"]
    assert any(item["analyzer"] == ANALYZER_ID for item in job["findings"])
