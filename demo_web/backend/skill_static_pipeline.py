from __future__ import annotations

from pathlib import Path
from typing import Any

from .analyzers.skill_semantic import SemanticProvider

from .adapters.skill import SkillScannerAdapter
from .analyzers import (
    analyze_command_context,
    analyze_custom_rules,
    analyze_enterprise_controls,
    analyze_filesystem_context,
    analyze_network_context,
    analyze_sensitive_flows,
    analyze_skill_tree,
    analyze_skill_semantics,
    analyze_skill_capability_alignment,
    analyze_static_coverage,
    analyze_untrusted_exec_flows,
)
from .normalizers import normalize_skill


def run_skill_static_pipeline(
    skill_path: Path,
    adapter: SkillScannerAdapter,
    *,
    semantic_provider: SemanticProvider | None = None,
) -> dict[str, Any]:
    """Run the same Cisco and Aegis Skill pipeline used by the admission API."""
    execution = adapter.scan(skill_path)
    cisco_findings, cisco_analyzers = normalize_skill(execution.report)
    aegis_findings, aegis_analyzers = analyze_skill_tree(skill_path)
    sensitive_findings, sensitive_analyzers = analyze_sensitive_flows(skill_path)
    exec_findings, exec_analyzers = analyze_untrusted_exec_flows(skill_path)
    enterprise_findings, enterprise_analyzers = analyze_enterprise_controls(skill_path)
    coverage_findings, coverage_analyzers = analyze_static_coverage(skill_path)
    network_findings, network_analyzers = analyze_network_context(skill_path, cisco_findings)
    filesystem_findings, filesystem_analyzers = analyze_filesystem_context(
        skill_path, cisco_findings
    )
    command_findings, command_analyzers = analyze_command_context(
        skill_path, cisco_findings
    )
    custom_findings, custom_analyzers = analyze_custom_rules(skill_path, "skill")
    semantic_findings, semantic_analyzers = analyze_skill_semantics(
        skill_path, provider=semantic_provider
    )
    alignment_findings, alignment_analyzers = analyze_skill_capability_alignment(skill_path)
    findings = (
        cisco_findings
        + aegis_findings
        + sensitive_findings
        + exec_findings
        + enterprise_findings
        + coverage_findings
        + network_findings
        + filesystem_findings
        + command_findings
        + custom_findings
        + semantic_findings
        + alignment_findings
    )
    analyzers = sorted(set(
        cisco_analyzers
        + aegis_analyzers
        + sensitive_analyzers
        + exec_analyzers
        + enterprise_analyzers
        + coverage_analyzers
        + network_analyzers
        + filesystem_analyzers
        + command_analyzers
        + custom_analyzers
        + semantic_analyzers
        + alignment_analyzers
    ))
    return {
        "findings": findings,
        "analyzers": analyzers,
        "logs": execution.logs[-4:],
        "vendor_scans": 1,
    }
