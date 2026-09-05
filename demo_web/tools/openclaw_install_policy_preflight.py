#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.adapters import build_scanner_environment  # noqa: E402
from backend.install_policy_audit import (  # noqa: E402
    record_install_policy_audit,
    verify_install_policy_audit,
)
from backend.openclaw_install_policy import (  # noqa: E402
    SKILL_RUNTIME,
    SKILL_SCANNER,
    evaluate_install_request,
)
from backend.policy import load_policy  # noqa: E402
from backend.runtime_paths import runtime_path_entries  # noqa: E402


EXPECTED_SKILL_SCANNER_VERSION = "2.0.13.dev3+g4dee90371"
ALLOWED_SCANNER_ENV_NAMES = {
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "PYTHONUTF8",
    "PYTHONIOENCODING",
    "HF_HUB_OFFLINE",
    "TRANSFORMERS_OFFLINE",
    "LITELLM_LOCAL_MODEL_COST_MAP",
    "PATH",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CACHE_HOME",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def request_for(path: Path, name: str, target_type: str = "skill") -> dict[str, Any]:
    return {
        "protocolVersion": 1,
        "openclawVersion": "deployment-preflight",
        "targetType": target_type,
        "targetName": name,
        "sourcePath": str(path.resolve()),
        "sourcePathKind": "directory",
        "source": {"kind": "local-path", "mutable": False},
        "origin": {"type": "aegis-preflight-fixture"},
        "request": {
            "kind": "skill-install" if target_type == "skill" else "plugin-dir",
            "mode": "preflight",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Aegis Chain readiness for OpenClaw Skill install admission."
    )
    parser.add_argument(
        "--skip-fixed-scans",
        action="store_true",
        help="Only verify files and contracts; do not run the two hash-fixed fixtures.",
    )
    args = parser.parse_args()
    checks: list[dict[str, Any]] = []

    def add(check_id: str, passed: bool, detail: Any) -> None:
        checks.append({"id": check_id, "passed": passed, "detail": detail})

    required_files = {
        "skill_scanner": SKILL_SCANNER,
        "policy_cli": DEMO_ROOT / "tools" / "openclaw_install_policy.py",
        "policy_proxy": DEMO_ROOT / "tools" / "openclaw_install_policy_proxy.mjs",
        "policy_config": DEMO_ROOT / "config" / "admission_policy.skill-evidence-v1.yaml",
        "stable_config_example": DEMO_ROOT
        / "config"
        / "openclaw.install-policy.windows-stable.example.json5",
    }
    missing = [name for name, path in required_files.items() if not path.is_file()]
    add("required_files", not missing, {"missing": missing})

    try:
        version = importlib.metadata.distribution("cisco-ai-skill-scanner").version
    except importlib.metadata.PackageNotFoundError:
        version = "unavailable-in-current-runtime"
    # This preflight normally runs in .runtime_mcp313, so read the Skill
    # distribution metadata from its own environment without executing a scan.
    skill_metadata = SKILL_RUNTIME / "Lib" / "site-packages"
    candidates = list(skill_metadata.glob("cisco_ai_skill_scanner-*.dist-info"))
    if candidates:
        version = candidates[0].name.removeprefix("cisco_ai_skill_scanner-").removesuffix(
            ".dist-info"
        )
    add(
        "skill_scanner_version",
        version == EXPECTED_SKILL_SCANNER_VERSION,
        {"actual": version, "expected": EXPECTED_SKILL_SCANNER_VERSION},
    )
    if SKILL_SCANNER.is_file():
        add("skill_scanner_sha256", True, sha256_file(SKILL_SCANNER))
    else:
        add("skill_scanner_sha256", False, "scanner missing")

    cache_root = DEMO_ROOT / "data" / "openclaw-install-policy" / "preflight-cache"
    scanner_env = build_scanner_environment(
        cache_root, runtime_path_entries(SKILL_RUNTIME)
    )
    unexpected_names = sorted(set(scanner_env) - ALLOWED_SCANNER_ENV_NAMES)
    add(
        "scanner_environment_allowlist",
        not unexpected_names,
        {
            "passed_names": sorted(scanner_env),
            "unexpected_names": unexpected_names,
            "inherited_service_environment": False,
        },
    )

    try:
        policy = load_policy()
        add("admission_policy", True, f"{policy.policy_id}@{policy.version}")
    except Exception as exc:
        add("admission_policy", False, type(exc).__name__)

    if args.skip_fixed_scans:
        add(
            "fixed_safe_and_risky_scans",
            False,
            "skipped by explicit operator flag; result is diagnostic-only, not deployment-ready",
        )
    else:
        safe = REPOSITORY_ROOT / "fixtures" / "skills" / "benign_doc_summary"
        risky = REPOSITORY_ROOT / "fixtures" / "skills" / "malicious_exfiltration"
        safe_plugin = REPOSITORY_ROOT / "fixtures" / "openclaw_plugins" / "benign_mcp_plugin"
        blocked_plugin = REPOSITORY_ROOT / "fixtures" / "openclaw_plugins" / "blocked_runtime_fetch_only"
        with tempfile.TemporaryDirectory(
            prefix="openclaw-preflight-", dir=DEMO_ROOT / "data"
        ) as temporary:
            audit_db = Path(temporary) / "admission_audit.db"

            def recorder(payload, response, digest, duration):
                return record_install_policy_audit(
                    payload,
                    response,
                    digest,
                    duration,
                    database=audit_db,
                )

            safe_response = evaluate_install_request(
                request_for(safe, "aegis-preflight-safe"), audit_recorder=recorder
            )
            risky_response = evaluate_install_request(
                request_for(risky, "aegis-preflight-risky"), audit_recorder=recorder
            )
            safe_plugin_response = evaluate_install_request(
                request_for(safe_plugin, "aegis-preflight-plugin-safe", "plugin"),
                audit_recorder=recorder,
            )
            blocked_plugin_response = evaluate_install_request(
                request_for(blocked_plugin, "aegis-preflight-plugin-blocked", "plugin"),
                audit_recorder=recorder,
            )
            audit_verification = verify_install_policy_audit(audit_db)
        scans_passed = (
            safe_response.get("decision") == "allow"
            and risky_response.get("decision") == "block"
            and safe_plugin_response.get("decision") == "allow"
            and blocked_plugin_response.get("decision") == "block"
            and audit_verification.get("valid") is True
            and audit_verification.get("rows") == 4
        )
        add(
            "fixed_safe_and_risky_scans",
            scans_passed,
            {
                "safe_decision": safe_response.get("decision"),
                "risky_decision": risky_response.get("decision"),
                "safe_plugin_decision": safe_plugin_response.get("decision"),
                "blocked_plugin_decision": blocked_plugin_response.get("decision"),
                "audit_chain_valid": audit_verification.get("valid"),
                "audit_rows": audit_verification.get("rows"),
            },
        )

    ready = all(check["passed"] for check in checks)
    output = {
        "schema_version": "1.0",
        "ready": ready,
        "target": "openclaw_skill_and_plugin_install_admission",
        "checks": checks,
        "manual_boundary": (
            "OpenClaw deployment config absolute paths and Windows ACLs must still be "
            "verified on the target machine; this preflight does not modify OpenClaw."
        ),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
