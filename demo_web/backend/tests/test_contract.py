from __future__ import annotations

from backend import app as gateway
from backend.models import Finding, ScanJob
from backend.normalizers import finding_dict, normalize_pip_audit
from backend.policy import decision_from_findings, summarize


def test_unknown_severity_is_fail_closed() -> None:
    assert decision_from_findings([{"severity": "UNKNOWN"}]) == "UNKNOWN"
    assert decision_from_findings([{"severity": "vendor-new-level"}]) == "UNKNOWN"


def test_block_takes_precedence_over_unknown() -> None:
    findings = [{"severity": "UNKNOWN"}, {"severity": "CRITICAL"}]
    assert decision_from_findings(findings) == "BLOCK"


def test_summary_counts_unknown_findings() -> None:
    result = summarize([{"severity": "INFO"}, {"severity": "not-recognized"}])
    assert result == {
        "total_findings": 2,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 1,
        "unknown": 1,
    }


def test_normalized_finding_satisfies_versioned_model() -> None:
    finding = finding_dict(
        id="rule-1",
        title="Example",
        category="policy_violation",
        severity="medium",
        analyzer="unit-test",
        location={"file": "SKILL.md", "line": 8},
    )
    validated = Finding.model_validate(finding)
    assert validated.severity.value == "MEDIUM"
    assert finding["location"] == {"file": "SKILL.md", "line": 8}


def test_new_job_uses_scan_schema(monkeypatch) -> None:
    monkeypatch.setattr(gateway, "save_job", lambda job: None)

    job = gateway.new_job("skill", "upload", "example.zip")

    validated = ScanJob.model_validate(job)
    assert job["schema_version"] == "1.3"
    assert validated.summary.unknown == 0
    assert validated.decision.value == "UNKNOWN"
    assert validated.policy_trace.policy_id == "aegis-chain-local-default"
    assert validated.policy_trace.policy_version == "1.1.0"
    assert validated.policy_trace.rule_id == "PENDING_SCAN"


def test_legacy_job_without_policy_trace_remains_readable() -> None:
    legacy = {
        "schema_version": "1.0",
        "id": "legacy-job",
        "created_at": "2026-08-07T00:00:00+00:00",
        "updated_at": "2026-08-07T00:00:00+00:00",
        "status": "completed",
        "target_kind": "skill",
        "source_kind": "preset",
        "display_name": "legacy fixture",
        "decision": "ALLOW",
        "summary": {"total_findings": 0},
    }

    validated = gateway.validate_stored_job(legacy)

    assert validated["schema_version"] == "1.0"
    assert validated["policy_trace"]["policy_id"] == "unresolved"
    assert validated["policy_trace"]["rule_id"] == "PENDING_SCAN"


def test_duplicate_dependency_vulnerabilities_receive_unique_finding_ids() -> None:
    vulnerability = {
        "id": "PYSEC-EXAMPLE",
        "aliases": ["CVE-EXAMPLE"],
        "fix_versions": ["2.0"],
        "description": "duplicate upstream record",
    }
    report = {
        "dependencies": [
            {
                "name": "example",
                "version": "1.0",
                "vulns": [vulnerability, vulnerability.copy()],
            }
        ]
    }

    findings, _ = normalize_pip_audit(report)

    assert [item["id"] for item in findings] == [
        "dependency-example==1.0-PYSEC-EXAMPLE",
        "dependency-example==1.0-PYSEC-EXAMPLE-2",
    ]
