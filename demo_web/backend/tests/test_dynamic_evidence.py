from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.dynamic_audit.markers import (
    MarkerEvidenceError,
    create_marker,
    encode_marker,
    find_marker_witnesses,
)
from backend.dynamic_audit.planning import (
    build_trigger_plan,
    correlate_dynamic_evidence,
)
from backend.dynamic_audit.runner import run_safe_marker_flow_fixture


def make_marker():
    return create_marker(
        "official_document",
        seed="unit-test-seed",
        source_ref="decoys/official_document.txt",
    )


@pytest.mark.parametrize("transform", ["exact", "base64", "hex", "url_encoded"])
def test_marker_detector_recognizes_supported_transforms_without_raw_value(
    transform: str,
) -> None:
    marker = make_marker()
    payload = b"prefix:" + encode_marker(marker, transform) + b":suffix"
    witnesses = find_marker_witnesses(
        [payload],
        [marker],
        sink_kind="mcp_tool_output",
        sink_ref="fixture-tool",
    )

    assert len(witnesses) == 1
    public = witnesses[0].to_dict()
    assert public["marker_id"] == marker.marker_id
    assert public["transform"] == transform
    assert public["raw_marker_retained"] is False
    assert marker.token not in json.dumps(public, ensure_ascii=False)


def test_marker_detector_reassembles_bounded_chunks() -> None:
    marker = make_marker()
    payload = encode_marker(marker, "base64")
    split_at = len(payload) // 2
    witnesses = find_marker_witnesses(
        [payload[:split_at], payload[split_at:]],
        [marker],
        sink_kind="loopback_network",
        sink_ref="127.0.0.1:ephemeral",
    )

    assert len(witnesses) == 1
    assert witnesses[0].transform == "chunked_base64"
    assert witnesses[0].chunk_count == 2


def test_marker_detector_fails_closed_on_unbounded_chunk() -> None:
    marker = make_marker()
    with pytest.raises(MarkerEvidenceError, match="chunk exceeds"):
        find_marker_witnesses(
            [b"x" * (16 * 1024 + 1)],
            [marker],
            sink_kind="loopback_network",
            sink_ref="127.0.0.1:ephemeral",
        )


def test_static_finding_generates_bounded_skill_trigger_plan() -> None:
    plan = build_trigger_plan(
        target_id="controlled-skill",
        target_kind="skill",
        static_findings=[{
            "id": "finding-sensitive-flow",
            "rule_id": "AEGIS_SENSITIVE_DATA_TO_OUTBOUND_SINK",
            "category": "sensitive network credential flow",
            "title": "敏感凭据可能进入网络汇点",
        }],
    )
    actions = {step.action for step in plan.steps}

    assert "database_credential" in plan.marker_profiles
    assert "internal_endpoint" in plan.marker_profiles
    assert "official_document" in plan.marker_profiles
    assert "observe_sensitive_file_read" in actions
    assert "observe_loopback_sink" in actions
    assert "inventory_skill_runtime_closure" in actions
    assert plan.max_attempts == 3
    assert plan.policy_effect == "none"


def test_mcp_plan_uses_protocol_actions_and_is_deterministic() -> None:
    kwargs = {
        "target_id": "controlled-mcp",
        "target_kind": "mcp",
        "static_findings": [{
            "id": "mcp-finding",
            "rule_id": "AEGIS_MCP_SENSITIVE_RESOURCE_URI",
            "category": "mcp sensitive resource",
            "title": "Sensitive resource URI",
        }],
    }
    first = build_trigger_plan(**kwargs)
    second = build_trigger_plan(**kwargs)
    actions = {step.action for step in first.steps}

    assert first.plan_id == second.plan_id
    assert "enumerate_mcp_tools" in actions
    assert "invoke_schema_valid_tools" in actions
    assert "inventory_skill_runtime_closure" not in actions


def test_correlation_does_not_treat_runtime_failure_as_safe() -> None:
    plan = build_trigger_plan(
        target_id="failed-skill",
        target_kind="skill",
        static_findings=[{"id": "static-1", "category": "network"}],
    )
    result = correlate_dynamic_evidence(
        plan,
        execution_status="failed",
        observed_event_types=[],
        marker_witnesses=[],
    )

    assert result.status == "inconclusive"
    assert result.policy_effect == "none"
    assert result.to_dict()["static_decision_changed"] is False


def test_marker_witness_confirms_independent_dynamic_correlation() -> None:
    marker = make_marker()
    witness = find_marker_witnesses(
        [encode_marker(marker, "base64")],
        [marker],
        sink_kind="loopback_network",
        sink_ref="127.0.0.1:ephemeral",
    )[0].to_dict()
    plan = build_trigger_plan(
        target_id="controlled-skill",
        target_kind="skill",
        static_findings=[{"id": "static-1", "category": "sensitive network"}],
    )
    result = correlate_dynamic_evidence(
        plan,
        execution_status="completed",
        observed_event_types=["file_read", "network_connect"],
        marker_witnesses=[witness],
    )

    assert result.status == "confirmed"
    assert result.marker_witness_ids == (marker.marker_id,)
    assert result.to_dict()["static_decision_changed"] is False


def test_unplanned_marker_profile_is_observed_but_not_static_confirmed() -> None:
    marker = create_marker(
        "personal_identity",
        seed="unplanned-marker-seed",
        source_ref="decoys/personal_identity.txt",
    )
    witness = find_marker_witnesses(
        [encode_marker(marker, "exact")],
        [marker],
        sink_kind="loopback_network",
        sink_ref="127.0.0.1:ephemeral",
    )[0].to_dict()
    plan = build_trigger_plan(
        target_id="network-only-skill",
        target_kind="skill",
        static_findings=[{"id": "static-network", "category": "network endpoint"}],
    )
    result = correlate_dynamic_evidence(
        plan,
        execution_status="completed",
        observed_event_types=["network_connect"],
        marker_witnesses=[witness],
    )

    assert "personal_identity" not in plan.marker_profiles
    assert result.status == "observed"
    assert result.marker_witness_ids == ()


def test_controlled_marker_fixture_forms_redacted_source_to_sink_witness(
    tmp_path: Path,
) -> None:
    result = run_safe_marker_flow_fixture(tmp_path / "marker-workspaces")
    metrics = result["metrics"]

    assert result["success"] is True
    assert metrics["fixtures_completed"] == 1
    assert metrics["expected_checks_passed"] == metrics["expected_checks_total"] == 3
    assert metrics["marker_witnesses"] == 1
    assert metrics["source_to_sink_witness_rate"] == 1.0
    assert metrics["confirmed_transforms"] == ["base64"]
    assert metrics["policy_violations"] == 0
    assert metrics["timeouts"] == 0
    assert metrics["raw_marker_leaks"] == 0
    assert metrics["decision_changes"] == 0

    witness = result["marker_witnesses"][0]
    assert witness["profile"] == "official_document"
    assert witness["source_ref"] == "decoys/official_document.txt"
    assert witness["sink_kind"] == "loopback_network"
    assert witness["transform"] == "base64"
    assert witness["raw_marker_retained"] is False

    public = json.dumps(result, ensure_ascii=False)
    assert "AEGIS-CANARY:" not in public
