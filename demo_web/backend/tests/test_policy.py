from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from backend import app as gateway
from backend.models import ScanJob
from backend.normalizers import normalize_skill
from backend.policy import (
    PolicyConfigurationError,
    evaluate_findings,
    load_policy,
)


def write_policy(path: Path, decision_yaml: str) -> Path:
    path.write_text(
        "\n".join(
            [
                'schema_version: "1.0"',
                'policy_id: "test-policy"',
                'version: "9.9.9"',
                'description: "unit test"',
                "decision:",
                decision_yaml,
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_default_yaml_policy_is_valid_and_versioned() -> None:
    policy = load_policy()

    assert policy.policy_id == "aegis-chain-local-default"
    assert policy.version == "1.1.0"
    assert "YARA_jailbreak_generic" in (
        policy.decision.review_uncorroborated_cisco_skill_high_rules
    )
    assert policy.decision.fail_closed is True


@pytest.mark.parametrize(
    ("severity", "expected_decision", "expected_rule"),
    [
        (None, "ALLOW", "POLICY_ALLOW"),
        ("INFO", "ALLOW", "POLICY_ALLOW"),
        ("LOW", "REVIEW", "POLICY_REVIEW_SEVERITY"),
        ("MEDIUM", "REVIEW", "POLICY_REVIEW_SEVERITY"),
        ("HIGH", "BLOCK", "POLICY_BLOCK_SEVERITY"),
        ("CRITICAL", "BLOCK", "POLICY_BLOCK_SEVERITY"),
        ("UNKNOWN", "UNKNOWN", "POLICY_UNKNOWN_SEVERITY"),
        ("vendor-new-level", "UNKNOWN", "POLICY_UNKNOWN_SEVERITY"),
    ],
)
def test_default_policy_preserves_m12_decisions(
    severity: str | None, expected_decision: str, expected_rule: str
) -> None:
    findings = [] if severity is None else [{"id": "finding-1", "severity": severity}]

    result = evaluate_findings(findings)

    assert result.decision.value == expected_decision
    assert result.trace.rule_id == expected_rule
    assert result.trace.policy_version == "1.1.0"
    assert result.trace.fail_closed is True


def test_block_precedence_and_trace_are_auditable() -> None:
    findings = [
        {"id": "unknown-1", "severity": "UNKNOWN"},
        {"id": "critical-1", "severity": "CRITICAL"},
        {"id": "medium-1", "severity": "MEDIUM"},
    ]

    result = evaluate_findings(findings)

    assert result.decision.value == "BLOCK"
    assert result.trace.matched_severities == ["CRITICAL"]
    assert result.trace.matched_finding_ids == ["critical-1"]
    assert "CRITICAL" in result.trace.reason


def _normalized_cisco_finding(severity: str = "HIGH") -> dict:
    findings, _ = normalize_skill(
        {
            "skill_name": "candidate",
            "findings": [
                {
                    "id": "YARA_jailbreak_generic",
                    "rule_id": "YARA_jailbreak_generic",
                    "severity": severity,
                    "analyzer": "yara_analyzer",
                    "file_path": "SKILL.md",
                    "line_number": 7,
                    "description": "raw vendor text is hashed",
                }
            ],
        }
    )
    return findings[0]


def test_uncorroborated_normalized_cisco_high_requires_review() -> None:
    finding = _normalized_cisco_finding()

    result = evaluate_findings([finding])

    assert result.decision.value == "REVIEW"
    assert result.trace.rule_id == "POLICY_REVIEW_UNCORROBORATED_CISCO_HIGH"
    assert result.trace.matched_severities == ["HIGH"]
    assert result.trace.matched_finding_ids == [finding["id"]]
    assert finding["evidence_confidence"] == "POTENTIAL"
    assert finding["reachability"] == "UNKNOWN"
    assert finding["behavior_alignment"] == "UNKNOWN"
    assert finding["evidence_source"] == "CISCO"


def test_cisco_critical_and_malformed_vendor_high_remain_blocked() -> None:
    critical = evaluate_findings([_normalized_cisco_finding("CRITICAL")])
    malformed_high = evaluate_findings(
        [
            {
                "id": "vendor-skill-untrusted",
                "category": "vendor_skill_finding",
                "severity": "HIGH",
                "analyzer": "yara_analyzer",
            }
        ]
    )

    assert critical.decision.value == "BLOCK"
    assert malformed_high.decision.value == "BLOCK"


def test_non_candidate_cisco_high_remains_blocked() -> None:
    finding = _normalized_cisco_finding()
    finding["rule_id"] = "COMPOUND_EXTRACT_EXECUTE"

    result = evaluate_findings([finding])

    assert result.decision.value == "BLOCK"
    assert result.trace.rule_id == "POLICY_BLOCK_SEVERITY"


def test_independent_aegis_high_corroboration_keeps_block() -> None:
    vendor = _normalized_cisco_finding()
    aegis = {
        "id": "aegis-chain",
        "rule_id": "AEGIS_REMOTE_FETCH_PIPE_SHELL",
        "category": "remote_execution",
        "severity": "HIGH",
        "analyzer": "aegis-static-v1",
        "evidence_source": "AEGIS_STATIC",
        "evidence_confidence": "CORROBORATED",
    }

    result = evaluate_findings([vendor, aegis])

    assert result.decision.value == "BLOCK"
    assert result.trace.matched_finding_ids == ["aegis-chain"]


def test_unknown_still_fails_closed_with_cisco_high_candidate() -> None:
    result = evaluate_findings(
        [_normalized_cisco_finding(), {"id": "coverage-gap", "severity": "UNKNOWN"}]
    )

    assert result.decision.value == "UNKNOWN"
    assert result.trace.rule_id == "POLICY_UNKNOWN_SEVERITY"


def test_policy_rejects_overlapping_severity_sets(tmp_path: Path) -> None:
    path = write_policy(
        tmp_path / "overlap.yaml",
        "\n".join(
            [
                "  block_severities: [CRITICAL, HIGH]",
                "  review_severities: [HIGH, MEDIUM, LOW]",
                "  allow_severities: [INFO, SAFE]",
                "  fail_closed: true",
            ]
        ),
    )

    with pytest.raises(PolicyConfigurationError, match="不能重叠"):
        load_policy(path)


def test_policy_rejects_fail_open_configuration(tmp_path: Path) -> None:
    path = write_policy(
        tmp_path / "fail-open.yaml",
        "\n".join(
            [
                "  block_severities: [CRITICAL, HIGH]",
                "  review_severities: [MEDIUM, LOW]",
                "  allow_severities: [INFO, SAFE]",
                "  fail_closed: false",
            ]
        ),
    )

    with pytest.raises(PolicyConfigurationError, match="fail_closed"):
        load_policy(path)


def test_policy_configuration_failure_preserves_findings_and_fails_closed(monkeypatch) -> None:
    job = ScanJob(
        id="policy-error-job",
        created_at="2026-08-10T00:00:00+00:00",
        updated_at="2026-08-10T00:00:00+00:00",
        status="running",
        target_kind="skill",
        source_kind="upload",
        display_name="example.zip",
    ).model_dump(mode="json")
    findings = [{"id": "critical-1", "severity": "CRITICAL"}]

    def invalid_policy(_findings):
        raise PolicyConfigurationError("invalid test policy")

    monkeypatch.setattr(gateway, "evaluate_findings", invalid_policy)
    monkeypatch.setattr(gateway, "save_job", lambda updated: None)

    gateway.complete_scan_job(
        job,
        started=0.0,
        findings=findings,
        analyzers=["unit-test"],
        logs=["scanner completed"],
    )

    assert job["status"] == "failed"
    assert job["decision"] == "UNKNOWN"
    assert job["policy_trace"]["rule_id"] == "POLICY_CONFIGURATION_ERROR"
    assert job["summary"]["critical"] == 1
    assert job["findings"] == findings


@pytest.mark.parametrize(
    ("error", "expected_rule"),
    [
        (subprocess.TimeoutExpired(["scanner"], 1), "SCAN_TIMEOUT"),
        (RuntimeError("scanner crashed"), "SCAN_EXECUTION_FAILED"),
    ],
)
def test_worker_failure_records_fail_closed_policy_trace(
    monkeypatch, error: Exception, expected_rule: str
) -> None:
    job = ScanJob(
        id="worker-error-job",
        created_at="2026-08-10T00:00:00+00:00",
        updated_at="2026-08-10T00:00:00+00:00",
        status="queued",
        target_kind="skill",
        source_kind="upload",
        display_name="example.zip",
    ).model_dump(mode="json")

    def failing_worker(_job):
        raise error

    monkeypatch.setattr(gateway, "load_job", lambda _job_id: job)
    monkeypatch.setattr(gateway, "save_job", lambda updated: None)

    gateway.guarded_worker(job["id"], failing_worker)

    assert job["status"] == "failed"
    assert job["decision"] == "UNKNOWN"
    assert job["policy_trace"]["rule_id"] == expected_rule
    assert job["policy_trace"]["fail_closed"] is True


def test_markdown_export_contains_policy_identity_rule_and_reason(monkeypatch) -> None:
    evaluation = evaluate_findings([{"id": "medium-1", "severity": "MEDIUM"}])
    job = ScanJob(
        id="export-job",
        created_at="2026-08-10T00:00:00+00:00",
        updated_at="2026-08-10T00:00:00+00:00",
        status="completed",
        target_kind="skill",
        source_kind="upload",
        display_name="example.zip",
        decision=evaluation.decision,
        policy_trace=evaluation.trace,
    ).model_dump(mode="json")
    monkeypatch.setattr(gateway, "load_job", lambda _job_id: job)

    response = gateway.export_scan(job["id"], format="md")
    body = response.body.decode("utf-8")

    assert "aegis-chain-local-default@1.1.0" in body
    assert "POLICY_REVIEW_SEVERITY" in body
    assert "命中人工复核严重度" in body
