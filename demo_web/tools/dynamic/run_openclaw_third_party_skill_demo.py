from __future__ import annotations

import argparse
import ast
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEMO_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = DEMO_ROOT.parent
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

from backend.dynamic_audit.docker_backend import (  # noqa: E402
    _docker_prefix,
    _require_success,
    discover_docker_cli,
    probe_docker_engine,
    run_docker_cli,
)
from backend.dynamic_audit.skill_sandbox_docker import BACKEND_ID  # noqa: E402
from backend.install_policy_audit import (  # noqa: E402
    read_recent_install_policy_audits,
    verify_install_policy_audit,
)
from backend.openclaw_install_policy import hash_source_tree  # noqa: E402
from tools.dynamic.run_openclaw_skill_dynamic_e2e import (  # noqa: E402
    EXPECTED_OPENCLAW_COMMIT,
    EXPECTED_OPENCLAW_VERSION,
    _base_environment,
    _discover_openclaw,
    _file_record,
    _install_case,
    _policy_config,
    _redact,
    _run_command,
    _sha256,
    _write_json,
    _write_text,
)


RUN_ID = "2026-08-28-openclaw-third-party-skill-demo-v2"
DEFAULT_OUTPUT = DEMO_ROOT / "artifacts" / "experiment" / RUN_ID
DEFAULT_RUNTIME = DEMO_ROOT / "data" / RUN_ID
DATASET_ROOT = REPOSITORY_ROOT / "datasets" / "skilltrustbench_v1_0"
FULL_MANIFEST = DATASET_ROOT / "full" / "full_manifest.jsonl"
EXPECTED_MANIFEST_SHA256 = (
    "3a061cda6145151fbac0cbabfab7ee16e7ca60d50659eb45c73807dd037ba6ac"
)
DATASET_REVISION = "762d5388b3a047b26df9679582af868a0e5b2c8f"
SLUGS = {
    "safe": "aegis-demo-meeting-safe",
    "malicious": "aegis-demo-meeting-malicious",
}
CASES: dict[str, dict[str, Any]] = {
    "safe": {
        "id": "case_00906",
        "judgment": "normal",
        "risk_labels": [],
        "source": "safe_pool",
        "base_category": "productivity",
        "dataset_tree_sha256": "5c5d9a063a7ca960756f3f9a4e2b529629f57ce8c35a15fe59183b021ee2ae99",
        "policy_tree_sha256": "e8fb4741389beea8e51e20dc52e5a8bb71deb86ba467f052f6c75e8cb32ea934",
        "files": {
            "SKILL.md": "f928ae5efe62d5574b518b311aee5c217ddb09c69c897d144887a55f7bdd171f",
            "meeting_notes_generator.py": "180a7cd0be96106b0478f409192c8717ece77fe634dbaf27e2aecf29c6cdaced",
        },
    },
    "malicious": {
        "id": "case_01084",
        "judgment": "malicious",
        "risk_labels": ["T01", "T04", "T07"],
        "source": "injected",
        "base_category": "productivity",
        "dataset_tree_sha256": "1a77305a3eb84502e535df8cc817e08fa7ee8e3036a38e4a45e17fd576ada9ef",
        "policy_tree_sha256": "492dd662772c72047f4708a0c523c783fcb5bfb7df426bfd527b71edff655076",
        "files": {
            "SKILL.md": "919ec70a6f2e0a43402454ac16ca534175aa93658bf719ce524adebb39ffbfe2",
            "meeting_notes_generator.py": "180a7cd0be96106b0478f409192c8717ece77fe634dbaf27e2aecf29c6cdaced",
            "scripts/_tool_override_marker.py": "14e8408055d816ab3af79ff2f7356b91d7a8c43b3dda6ac17cd450d41f079bc2",
        },
    },
}


def _case_root(case_id: str) -> Path:
    return (DATASET_ROOT / "full" / "cases" / case_id).resolve(strict=True)


def _manifest_records() -> dict[str, dict[str, Any]]:
    if _sha256(FULL_MANIFEST) != EXPECTED_MANIFEST_SHA256:
        raise ValueError("SkillTrustBench full manifest hash mismatch")
    selected = {spec["id"] for spec in CASES.values()}
    records: dict[str, dict[str, Any]] = {}
    with FULL_MANIFEST.open("r", encoding="utf-8") as handle:
        for line in handle:
            payload = json.loads(line)
            if payload.get("id") in selected:
                records[str(payload["id"])] = payload
    if set(records) != selected:
        raise ValueError("selected SkillTrustBench records are missing")
    return records


def _verify_case(kind: str, records: dict[str, dict[str, Any]]) -> Path:
    spec = CASES[kind]
    root = _case_root(str(spec["id"]))
    record = records[str(spec["id"])]
    for field in ("judgment", "source", "base_category"):
        if record.get(field) != spec[field]:
            raise ValueError(f"{kind} metadata mismatch: {field}")
    if record.get("risk_labels") != spec["risk_labels"]:
        raise ValueError(f"{kind} risk labels changed")
    if record.get("case_tree_sha256") != spec["dataset_tree_sha256"]:
        raise ValueError(f"{kind} dataset tree hash changed")

    actual_files = {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file()
    }
    if set(actual_files) != set(spec["files"]):
        raise ValueError(f"{kind} file set changed")
    for relative, expected in spec["files"].items():
        path = actual_files[relative]
        if path.is_symlink() or _sha256(path) != expected:
            raise ValueError(f"{kind} file hash changed: {relative}")
    if hash_source_tree(root) != spec["policy_tree_sha256"]:
        raise ValueError(f"{kind} policy tree hash changed")
    return root


def _verify_safe_execution_contract(root: Path) -> dict[str, Any]:
    files = [path for path in root.rglob("*") if path.is_file()]
    text = "\n".join(path.read_text(encoding="utf-8") for path in files)
    if "http://" in text.casefold() or "https://" in text.casefold():
        raise ValueError("safe case contains an external URL")
    python_files = [path for path in files if path.suffix.casefold() == ".py"]
    if len(python_files) != 1 or python_files[0].parent != root:
        raise ValueError("safe case must have one root Python entrypoint")
    tree = ast.parse(python_files[0].read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
    non_stdlib = sorted(imports - set(sys.stdlib_module_names))
    if non_stdlib:
        raise ValueError(f"safe case has non-stdlib imports: {non_stdlib}")
    return {
        "single_root_python_entrypoint": python_files[0].name,
        "external_urls": 0,
        "binary_or_archive_files": 0,
        "stdlib_only_imports": sorted(imports),
    }


def _static_audit_for_hash(
    audits: list[dict[str, Any]], source_hash: str
) -> dict[str, Any] | None:
    return next(
        (row for row in audits if row.get("source_tree_sha256") == source_hash),
        None,
    )


def _verify_installed_payload(installed: Path, source: Path) -> dict[str, Any]:
    if not installed.is_dir():
        return {"valid": False, "reason": "destination_missing"}
    actual = {
        path.relative_to(installed).as_posix(): path
        for path in installed.rglob("*")
        if path.is_file()
    }
    source_files = {
        path.relative_to(source).as_posix(): path
        for path in source.rglob("*")
        if path.is_file()
    }
    expected_names = {*source_files, ".openclaw/source-origin.json"}
    if set(actual) != expected_names:
        return {"valid": False, "reason": "installed_file_set_changed"}
    if any(path.is_symlink() for path in actual.values()):
        return {"valid": False, "reason": "installed_symlink_present"}
    payload_mismatches = [
        relative
        for relative, source_path in source_files.items()
        if _sha256(actual[relative]) != _sha256(source_path)
    ]
    if payload_mismatches:
        return {
            "valid": False,
            "reason": "payload_hash_mismatch",
            "mismatches": payload_mismatches,
        }
    try:
        origin = json.loads(actual[".openclaw/source-origin.json"].read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {"valid": False, "reason": "origin_metadata_invalid"}
    origin_valid = (
        isinstance(origin, dict)
        and origin.get("version") == 1
        and origin.get("source") == "path"
        and origin.get("slug") == SLUGS["safe"]
        and Path(str(origin.get("spec") or "")).resolve(strict=False) == source
        and isinstance(origin.get("installedAt"), int)
    )
    return {
        "valid": origin_valid,
        "reason": "payload_exact_with_openclaw_origin_metadata" if origin_valid else "origin_metadata_mismatch",
        "payload_files": len(source_files),
        "openclaw_metadata_files": 1,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the authoritative third-party Skill OpenClaw dynamic admission demo"
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    output = args.output.resolve(strict=False)
    runtime_root = args.runtime_root.resolve(strict=False)
    if output.exists():
        raise ValueError(f"refusing to overwrite output: {output}")
    if runtime_root.exists():
        raise ValueError(f"refusing to reuse runtime root: {runtime_root}")
    output.mkdir(parents=True)
    runtime_root.mkdir(parents=True)

    records = _manifest_records()
    safe_root = _verify_case("safe", records)
    malicious_root = _verify_case("malicious", records)
    safe_contract = _verify_safe_execution_contract(safe_root)
    source_hashes_before = {
        "safe": hash_source_tree(safe_root),
        "malicious": hash_source_tree(malicious_root),
    }

    node, openclaw_entrypoint, openclaw_wrapper = _discover_openclaw()
    version_env = _base_environment(
        runtime_root,
        runtime_root / "version.json",
        runtime_root / "version-state",
        node,
    )
    version_result = _run_command(
        [str(node), str(openclaw_entrypoint), "--version"],
        version_env,
        timeout_seconds=30,
    )
    version_text = (version_result.stdout + "\n" + version_result.stderr).strip()
    if (
        version_result.returncode != 0
        or EXPECTED_OPENCLAW_VERSION not in version_text
        or EXPECTED_OPENCLAW_COMMIT not in version_text
    ):
        raise ValueError("unexpected OpenClaw version")

    state_dir = runtime_root / "state"
    workspace = runtime_root / "workspace"
    audit_db = runtime_root / "admission_audit.db"
    config_path = runtime_root / "openclaw.json"
    workspace.mkdir(parents=True)
    _write_json(config_path, _policy_config(workspace, audit_db, dynamic_mode="required"))
    environment = _base_environment(runtime_root, config_path, state_dir, node)
    validation = _run_command(
        [str(node), str(openclaw_entrypoint), "config", "validate", "--json"],
        environment,
        timeout_seconds=30,
    )
    if validation.returncode != 0:
        raise ValueError("OpenClaw dynamic policy config validation failed")

    default_workspace = Path.home() / ".openclaw" / "workspace" / "skills"
    default_before = {
        slug: (default_workspace / slug).exists() for slug in SLUGS.values()
    }
    cases = [
        _install_case(
            node=node,
            entrypoint=openclaw_entrypoint,
            env=environment,
            source=safe_root,
            slug=SLUGS["safe"],
            workspace=workspace,
            expected_success=True,
            runtime_root=runtime_root,
        ),
        _install_case(
            node=node,
            entrypoint=openclaw_entrypoint,
            env=environment,
            source=malicious_root,
            slug=SLUGS["malicious"],
            workspace=workspace,
            expected_success=False,
            runtime_root=runtime_root,
        ),
    ]
    default_after = {
        slug: (default_workspace / slug).exists() for slug in SLUGS.values()
    }

    audit_verification = verify_install_policy_audit(audit_db)
    audits = list(reversed(read_recent_install_policy_audits(audit_db, limit=20)))
    safe_audit = _static_audit_for_hash(audits, source_hashes_before["safe"])
    malicious_audit = _static_audit_for_hash(audits, source_hashes_before["malicious"])
    safe_rules = set(safe_audit.get("finding_rule_ids", [])) if safe_audit else set()
    malicious_rules = (
        set(malicious_audit.get("finding_rule_ids", [])) if malicious_audit else set()
    )
    audit_gates = {
        "safe_allowed": bool(safe_audit and safe_audit.get("decision") == "allow"),
        "safe_dynamic_clean_attested": "AEGIS_DYNAMIC_EXECUTION_CLEAN" in safe_rules,
        "malicious_blocked": bool(
            malicious_audit and malicious_audit.get("decision") == "block"
        ),
        "malicious_dynamic_not_executed": not any(
            rule.startswith("AEGIS_DYNAMIC_") for rule in malicious_rules
        ),
    }

    source_hashes_after = {
        "safe": hash_source_tree(safe_root),
        "malicious": hash_source_tree(malicious_root),
    }
    docker_cli = discover_docker_cli()
    engine = probe_docker_engine(docker_cli)
    residual_result = run_docker_cli(
        [
            *_docker_prefix(docker_cli),
            "container",
            "ls",
            "--all",
            "--filter",
            f"label=aegis.dynamic.backend={BACKEND_ID}",
            "--format",
            "{{.ID}}",
        ],
        timeout_seconds=15,
    )
    residual_output = _require_success(residual_result, "residual_container_query")
    residual_ids = [line.strip() for line in residual_output.splitlines() if line.strip()]

    installed_safe = workspace / "skills" / SLUGS["safe"]
    blocked_malicious = workspace / "skills" / SLUGS["malicious"]
    installed_verification = _verify_installed_payload(installed_safe, safe_root)
    metrics = {
        "cases_total": 2,
        "cases_passed": sum(case["passed"] for case in cases),
        "safe_third_party_samples_executed": 1,
        "malicious_samples_executed": 0,
        "safe_installed": installed_safe.is_dir(),
        "safe_installed_hash_matches": installed_verification.get("valid") is True,
        "malicious_install_residuals": int(blocked_malicious.exists()),
        "audit_chain_valid": audit_verification.get("valid") is True,
        "audit_gates_passed": sum(audit_gates.values()),
        "audit_gates_total": len(audit_gates),
        "source_hash_changes": sum(
            source_hashes_before[name] != source_hashes_after[name]
            for name in source_hashes_before
        ),
        "default_workspace_test_residuals": sum(default_after.values()),
        "default_workspace_preexisting_test_slugs": sum(default_before.values()),
        "docker_container_residuals": len(residual_ids),
        "gpu_used": False,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }
    accepted = (
        metrics["cases_passed"] == metrics["cases_total"]
        and metrics["safe_third_party_samples_executed"] == 1
        and metrics["malicious_samples_executed"] == 0
        and metrics["safe_installed"]
        and metrics["safe_installed_hash_matches"]
        and metrics["malicious_install_residuals"] == 0
        and metrics["audit_chain_valid"]
        and metrics["audit_gates_passed"] == metrics["audit_gates_total"]
        and metrics["source_hash_changes"] == 0
        and metrics["default_workspace_preexisting_test_slugs"] == 0
        and metrics["default_workspace_test_residuals"] == 0
        and metrics["docker_container_residuals"] == 0
    )

    results = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "accepted" if accepted else "failed",
        "selection": {
            "dataset": "SkillTrustBench",
            "revision": DATASET_REVISION,
            "safe_case": CASES["safe"],
            "malicious_case": CASES["malicious"],
            "reason": (
                "The two cases expose the same meeting-notes-generator capability and "
                "share the same benign root Python file; the malicious case adds a hidden "
                "tool-override script and modified instructions."
            ),
        },
        "safe_execution_contract": safe_contract,
        "openclaw": {
            "version": EXPECTED_OPENCLAW_VERSION,
            "commit": EXPECTED_OPENCLAW_COMMIT,
            "entrypoint_sha256": _sha256(openclaw_entrypoint),
            "wrapper_sha256": _sha256(openclaw_wrapper),
        },
        "cases": cases,
        "audit_verification": audit_verification,
        "audit_gates": audit_gates,
        "audits": audits,
        "installed_safe_verification": installed_verification,
        "source_hashes_before": source_hashes_before,
        "source_hashes_after": source_hashes_after,
        "docker_residual_ids": residual_ids,
    }
    _write_json(output / "results.json", results)
    _write_json(output / "metrics.json", metrics)
    evaluation = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "claim_update": (
            "supported_authoritative_third_party_openclaw_dynamic_admission"
            if accepted
            else "refuted_or_inconclusive"
        ),
        "outcome_summary": (
            "权威正常 Skill 经静态准入和 Docker 隔离试运行后由真实 OpenClaw 安装；"
            "同名恶意 Skill 在执行前被静态阻断。"
            if accepted
            else "第三方 Skill 的 OpenClaw 动态准入至少有一个接受门未通过。"
        ),
        "limits": [
            "只动态执行 SkillTrustBench 官方 normal/safe_pool 样本。",
            "恶意对照仅静态扫描，未执行任何脚本。",
            "Python 审计钩子提供可解释行为证据，但不是不可绕过的内核边界。",
            "本次证明固定样本和固定输入下的安装前闭环，不代表所有第三方 Skill 安全。",
        ],
        "next_action": "deploy_policy_to_operator_openclaw_and_run_live_install_demo",
    }
    _write_json(output / "evaluation_summary.json", evaluation)
    source_names = (
        "backend/openclaw_install_policy.py",
        "backend/install_policy_audit.py",
        "backend/dynamic_audit/skill_sandbox.py",
        "backend/dynamic_audit/skill_sandbox_docker.py",
        "config/skill_dynamic_sandbox.json",
        "tools/openclaw_install_policy.py",
        "tools/dynamic/run_openclaw_third_party_skill_demo.py",
    )
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": results["status"],
        "experiment_tier": "auxiliary/authoritative-third-party-real-platform-e2e",
        "started_at": started_at.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "host_platform": platform.platform(),
            "host_python": sys.version,
            "openclaw_version": EXPECTED_OPENCLAW_VERSION,
            "openclaw_commit": EXPECTED_OPENCLAW_COMMIT,
            "docker_engine": engine,
            "gpu_used": False,
            "safe_third_party_samples_executed": 1,
            "malicious_samples_executed": 0,
        },
        "sources": {
            **{name: _file_record(DEMO_ROOT / name) for name in source_names},
            "skilltrustbench/full_manifest.jsonl": _file_record(FULL_MANIFEST),
            **{
                f"skilltrustbench/{kind}/{relative}": _file_record(_case_root(spec["id"]) / relative)
                for kind, spec in CASES.items()
                for relative in spec["files"]
            },
        },
        "metrics": metrics,
        "claim_boundary": evaluation["limits"],
    }
    _write_json(output / "run_manifest.json", manifest)
    _write_text(
        output / "run.log",
        "\n".join(
            [
                f"run_id={RUN_ID}",
                f"status={results['status']}",
                f"openclaw={EXPECTED_OPENCLAW_VERSION} ({EXPECTED_OPENCLAW_COMMIT})",
                *(f"case={case['slug']} exit={case['exit_code']} destination={case['destination_exists']} passed={case['passed']} duration_ms={case['duration_ms']}" for case in cases),
                f"safe_dynamic_clean_attested={audit_gates['safe_dynamic_clean_attested']}",
                f"malicious_dynamic_not_executed={audit_gates['malicious_dynamic_not_executed']}",
                f"audit_chain_valid={metrics['audit_chain_valid']}",
                f"docker_container_residuals={metrics['docker_container_residuals']}",
            ]
        ),
    )
    return {"status": results["status"], "metrics": metrics, "output": str(output)}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except Exception as exc:
        print(
            f"OpenClaw third-party demo failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "accepted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
