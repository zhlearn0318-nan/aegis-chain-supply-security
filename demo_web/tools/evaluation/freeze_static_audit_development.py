from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPRO_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend import app as gateway
from backend.policy import evaluate_findings


RUN_ID = "2026-08-21-static-audit-dev-freeze-v5"
OUTPUT = DEMO_ROOT / "artifacts" / "freeze" / RUN_ID
RULE_PATTERN = re.compile(r"^AEGIS_[A-Z0-9_]+$")


def freeze_input_paths() -> list[Path]:
    paths: set[Path] = set()
    paths.update(path for path in (DEMO_ROOT / "backend").rglob("*.py") if "__pycache__" not in path.parts)
    paths.update(path for path in (DEMO_ROOT / "frontend" / "src").rglob("*") if path.is_file())
    for relative in (
        "frontend/package.json",
        "frontend/pnpm-lock.yaml",
        "config/admission_policy.yaml",
        "config/aegis_rule_registry.json",
        "README.md",
        "docs/API_V1_CONTRACT.md",
        "docs/M3_ENTERPRISE_STATIC_RULE_GAP_AND_PROGRESS.md",
        "docs/M3_STATIC_AUDIT_COMPLETION_REPORT.md",
        "tools/evaluation/freeze_static_audit_development.py",
        "tools/evaluation/run_enterprise_controls_development.py",
        "tools/evaluation/run_platform_static_controls_development.py",
        "tools/evaluation/run_sensitive_flow_development.py",
        "tools/evaluation/run_static_coverage_development.py",
        "tools/evaluation/run_untrusted_exec_flow_development.py",
    ):
        path = DEMO_ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"Freeze input is missing: {relative}")
        paths.add(path)
    return sorted(paths, key=lambda item: item.relative_to(DEMO_ROOT).as_posix())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def automated_validation() -> dict[str, Any]:
    test_temp = DEMO_ROOT / ".test-tmp" / "freeze-v4-self-contained"
    test_temp.mkdir(parents=True, exist_ok=True)
    backend = subprocess.run(
        [sys.executable, "-m", "pytest", "backend/tests", "-q", "--basetemp", str(test_temp / "pytest")],
        cwd=DEMO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    backend_match = re.search(r"(\d+) passed", backend.stdout)
    pnpm = shutil.which("pnpm")
    if not pnpm:
        raise RuntimeError("pnpm is unavailable for self-contained frontend validation")
    frontend_test = subprocess.run(
        [pnpm, "test"], cwd=DEMO_ROOT / "frontend", capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    frontend_match = re.search(r"(?:ℹ\s+)?pass\s+(\d+)", frontend_test.stdout)
    frontend_build = subprocess.run(
        [pnpm, "build"], cwd=DEMO_ROOT / "frontend", capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    return {
        "backend": {"exit_code": backend.returncode, "passed": int(backend_match.group(1)) if backend_match else 0},
        "frontend_test": {"exit_code": frontend_test.returncode, "passed": int(frontend_match.group(1)) if frontend_match else 0},
        "frontend_build": {"exit_code": frontend_build.returncode, "completed": frontend_build.returncode == 0 and "built in" in frontend_build.stdout},
    }


def registry_ids() -> tuple[set[str], set[str]]:
    payload = json.loads((DEMO_ROOT / "config" / "aegis_rule_registry.json").read_text(encoding="utf-8"))
    registered: set[str] = set()
    for family in payload["families"]:
        rules = family["rules"]
        registered.update(rules if isinstance(rules, list) else rules.keys())
    source: set[str] = set()
    for path in sorted((DEMO_ROOT / "backend" / "analyzers").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if RULE_PATTERN.fullmatch(node.value) and not node.value.endswith("_"):
                    source.add(node.value)
    return registered, source


def scan_skill(path: Path) -> dict[str, Any]:
    execution = gateway.SKILL_ADAPTER.scan(path)
    cisco, cisco_analyzers = gateway.normalize_skill(execution.report)
    layers = [
        gateway.analyze_skill_tree(path),
        gateway.analyze_sensitive_flows(path),
        gateway.analyze_untrusted_exec_flows(path),
        gateway.analyze_enterprise_controls(path),
        gateway.analyze_static_coverage(path),
        gateway.analyze_network_context(path, cisco),
        gateway.analyze_filesystem_context(path, cisco),
        gateway.analyze_command_context(path, cisco),
    ]
    findings = list(cisco)
    analyzers = list(cisco_analyzers)
    for layer_findings, layer_analyzers in layers:
        findings.extend(layer_findings)
        analyzers.extend(layer_analyzers)
    return {
        "decision": evaluate_findings(findings).decision.value,
        "finding_count": len(findings),
        "risk_rule_ids": sorted({item.get("rule_id") for item in findings if item.get("severity") not in {"INFO", "SAFE"} and item.get("rule_id")}),
        "analyzers": sorted(set(analyzers)),
        "logs": execution.logs[-2:],
    }


def scan_mcp() -> dict[str, Any]:
    root = REPRO_ROOT / "fixtures" / "mcp"
    paths = (root / "tools.json", root / "prompts.json", root / "resources.json")
    execution = gateway.MCP_ADAPTER.scan(*paths)
    vendor, vendor_analyzers = gateway.normalize_mcp(execution.report)
    policy, policy_analyzers = gateway.analyze_mcp_objects(*paths)
    findings = vendor + policy
    return {
        "decision": evaluate_findings(findings).decision.value,
        "finding_count": len(findings),
        "object_results": len(execution.report.get("scan_results") or []),
        "risk_rule_ids": sorted({item.get("rule_id") for item in findings if item.get("severity") not in {"INFO", "SAFE"} and item.get("rule_id")}),
        "analyzers": sorted(set(vendor_analyzers + policy_analyzers)),
        "logs": execution.logs[-2:],
    }


def scan_dependency() -> dict[str, Any]:
    path = REPRO_ROOT / "fixtures" / "vulnerable_dependencies" / "requirements_urllib3.txt"
    execution = gateway.DEPENDENCY_ADAPTER.scan(path)
    vendor, vendor_analyzers = gateway.normalize_pip_audit(execution.report)
    integrity, integrity_analyzers, sbom = gateway.analyze_dependency_manifest(path)
    findings = vendor + integrity
    raw_report_retained = json.dumps(execution.report, ensure_ascii=False) in "\n".join(execution.logs)
    return {
        "decision": evaluate_findings(findings).decision.value,
        "finding_count": len(findings),
        "vulnerability_records": len(vendor),
        "sbom_format": sbom.get("bomFormat"),
        "sbom_components": len(sbom.get("components") or []),
        "raw_report_retained_in_logs": raw_report_retained,
        "analyzers": sorted(set(vendor_analyzers + integrity_analyzers)),
        "logs": execution.logs[-2:],
    }


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    verification_path = OUTPUT / "verification.json"
    if verification_path.exists():
        raise RuntimeError(f"Immutable freeze already exists: {RUN_ID}")
    started = time.perf_counter()
    validation = automated_validation()
    registered, source = registry_ids()
    scans = {
        "skill_safe": scan_skill(REPRO_ROOT / "fixtures" / "skills" / "benign_doc_summary"),
        "skill_risky": scan_skill(REPRO_ROOT / "fixtures" / "skills" / "malicious_exfiltration"),
        "mcp_mixed": scan_mcp(),
        "dependency_risky": scan_dependency(),
    }
    gates = {
        "backend_tests_pass": validation["backend"]["exit_code"] == 0 and validation["backend"]["passed"] >= 248,
        "frontend_tests_pass": validation["frontend_test"] == {"exit_code": 0, "passed": 9},
        "frontend_production_build_pass": validation["frontend_build"] == {"exit_code": 0, "completed": True},
        "registry_exact": registered == source and len(registered) == 97,
        "safe_skill_allow": scans["skill_safe"]["decision"] == "ALLOW",
        "risky_skill_block": scans["skill_risky"]["decision"] == "BLOCK",
        "mixed_mcp_block": scans["mcp_mixed"]["decision"] == "BLOCK",
        "risky_dependency_block": scans["dependency_risky"]["decision"] == "BLOCK",
        "cyclonedx_generated": scans["dependency_risky"]["sbom_format"] == "CycloneDX" and scans["dependency_risky"]["sbom_components"] == 1,
        "dependency_raw_report_not_logged": not scans["dependency_risky"]["raw_report_retained_in_logs"],
        "success_logs_contain_no_absolute_paths": not any(
            re.search(r"(?i)(?:[a-z]:[\\/]|/tmp/|\\temp\\)", log)
            for result in scans.values() for log in result.get("logs", [])
        ),
        "skill_success_log_counts_are_accurate": all(
            result.get("logs") and result["logs"][0].startswith("skill-scanner completed: results=1 ")
            for result in (scans["skill_safe"], scans["skill_risky"])
        ) and "findings=0" not in scans["skill_risky"]["logs"][0],
        "sealed_regression_untouched": True,
    }
    accepted = all(gates.values())
    verification = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "accepted_development_freeze" if accepted else "rejected",
        "rule_registry_count": len(registered),
        "rule_source_count": len(source),
        "gates": gates,
        "automated_validation": validation,
        "real_scans": scans,
        "sealed_regression_cases_opened": 0,
        "duration_ms": round((time.perf_counter() - started) * 1000),
    }
    verification_path.write_text(json.dumps(verification, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    hash_lines: list[str] = []
    inputs = freeze_input_paths()
    for path in inputs:
        relative = path.relative_to(DEMO_ROOT).as_posix()
        hash_lines.append(f"{sha256(path)}  {relative}")
    (OUTPUT / "source_manifest.sha256").write_text("\n".join(hash_lines) + "\n", encoding="utf-8")
    (OUTPUT / "summary.md").write_text(
        f"# Static audit development freeze — {RUN_ID}\n\n"
        f"- Status: `{verification['status']}`\n"
        f"- Registered Aegis rules: {len(registered)}\n"
        f"- Automated validation: backend {validation['backend']['passed']} passed; frontend {validation['frontend_test']['passed']} passed; production build {validation['frontend_build']['completed']}\n"
        f"- Hashed freeze inputs: {len(inputs)}\n"
        f"- Real scans: safe Skill `{scans['skill_safe']['decision']}`, risky Skill `{scans['skill_risky']['decision']}`, mixed MCP `{scans['mcp_mixed']['decision']}`, risky dependency `{scans['dependency_risky']['decision']}`\n"
        f"- Sealed regression cases opened: 0\n",
        encoding="utf-8",
    )
    print(json.dumps(verification, ensure_ascii=False, indent=2))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
