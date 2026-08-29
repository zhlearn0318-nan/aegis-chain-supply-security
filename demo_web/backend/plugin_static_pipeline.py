from __future__ import annotations

from pathlib import Path
from typing import Any

from .analyzers import (
    analyze_enterprise_controls,
    analyze_custom_rules,
    analyze_sensitive_flows,
    analyze_skill_tree,
    analyze_untrusted_exec_flows,
)
from .analyzers.plugin_package import analyze_plugin_package


def run_plugin_static_pipeline(plugin_path: Path) -> dict[str, Any]:
    package_findings, package_analyzers = analyze_plugin_package(plugin_path)
    generic_results = (
        analyze_skill_tree(plugin_path),
        analyze_sensitive_flows(plugin_path),
        analyze_untrusted_exec_flows(plugin_path),
        analyze_enterprise_controls(plugin_path),
    )
    findings = list(package_findings)
    analyzers = list(package_analyzers)
    for result_findings, result_analyzers in generic_results:
        findings.extend(result_findings)
        analyzers.extend(result_analyzers)
    custom_findings, custom_analyzers = analyze_custom_rules(plugin_path, "plugin")
    findings.extend(custom_findings)
    analyzers.extend(custom_analyzers)
    return {
        "findings": findings,
        "analyzers": sorted(set(analyzers)),
        "logs": ["openclaw plugin package completed: vendor_scans=0"],
        "vendor_scans": 0,
    }
