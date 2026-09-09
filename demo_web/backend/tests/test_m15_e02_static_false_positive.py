from __future__ import annotations

from types import SimpleNamespace

from tools.evaluation.run_m15_e02_static_false_positive import public_finding


def test_public_finding_retains_context_fields_without_raw_vendor_text() -> None:
    finding = {
        "id": "x",
        "rule_id": "R1",
        "title": "title",
        "category": "semantic",
        "severity": "MEDIUM",
        "analyzer": "aegis",
        "location": {"file": "SKILL.md", "line": 7, "raw": "drop"},
        "evidence": "semantic_features=example",
        "description": "description",
        "remediation": "remediation",
        "evidence_confidence": "CORROBORATED",
        "reachability": "EXAMPLE",
        "behavior_alignment": "DECLARED",
        "evidence_source": "AEGIS_STATIC",
        "vendor_raw": "drop",
    }
    result = public_finding(finding)
    assert result["location"] == {"file": "SKILL.md", "line": 7}
    assert result["reachability"] == "EXAMPLE"
    assert "vendor_raw" not in result


def test_external_model_analyzers_are_not_in_static_allowlist() -> None:
    from tools.evaluation.run_m15_e02_static_false_positive import ALLOWED_ANALYZERS

    assert all("llm" not in analyzer for analyzer in ALLOWED_ANALYZERS)


def test_policy_summary_is_already_a_plain_dictionary() -> None:
    from backend.policy import summarize

    result = summarize([])
    assert isinstance(result, dict)
    assert result["total_findings"] == 0


def test_scan_case_success_path_serializes_summary(tmp_path, monkeypatch) -> None:
    import tools.evaluation.run_m15_e02_static_false_positive as module

    case_root = tmp_path / "cases" / "case-a"
    case_root.mkdir(parents=True)
    (case_root / "SKILL.md").write_text("safe", encoding="utf-8")
    expected_hash = module.tree_sha256(case_root)
    monkeypatch.setattr(
        module,
        "run_skill_static_pipeline",
        lambda _root, _adapter: {
            "findings": [],
            "analyzers": ["static_analyzer", "aegis-static-v1"],
            "vendor_scans": 1,
        },
    )
    monkeypatch.setattr(
        module,
        "evaluate_findings",
        lambda _findings, _policy: SimpleNamespace(
            decision=SimpleNamespace(value="ALLOW"),
            trace=SimpleNamespace(model_dump=lambda **_kwargs: {"rule_id": "POLICY_ALLOW"}),
        ),
    )
    policy = SimpleNamespace(policy_id="test", version="1")
    result = module.scan_case(
        object(), policy, tmp_path,
        {"case_id": "case-a", "local_path": "cases/case-a", "source_kind": "test", "case_tree_sha256": expected_hash},
    )
    assert result["status"] == "completed"
    assert result["decision"] == "ALLOW"
    assert result["summary"]["total_findings"] == 0
