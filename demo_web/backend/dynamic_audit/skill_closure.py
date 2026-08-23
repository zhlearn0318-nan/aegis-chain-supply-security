from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from ..adapters import ProcessRunner, SkillScannerAdapter
from ..policy import evaluate_findings
from ..skill_static_pipeline import run_skill_static_pipeline
from .docker_backend import (
    CONTAINER_ID_PATTERN,
    DEMO_ROOT,
    DOCKER_CONTEXT,
    EXPECTED_SECURITY,
    FIXTURE_CONTAINER_PATH,
    IMAGE_ID,
    IMAGE_REFERENCE,
    DockerBackendConfig,
    DockerBackendError,
    DockerCommandResult,
    _cleanup_container,
    _docker_prefix,
    _parse_json_object,
    _require_mapping,
    _require_success,
    build_create_command,
    discover_docker_cli,
    inspect_image_identity,
    probe_docker_engine,
    redact_docker_command,
    run_docker_cli,
    sha256_bytes,
    sha256_file,
    validate_container_inspect,
    validate_runtime_probe,
)


SKILL_CLOSURE_SCHEMA_VERSION = "1.0"
SKILL_CLOSURE_BACKEND_ID = "aegis-docker-skill-closure-v1"
SKILL_CLOSURE_FIXTURE_ID = "skill_runtime_closure"
SKILL_CLOSURE_RUNTIME_ID = "aegis-skill-runtime-closure-v1"
SKILL_CLOSURE_FIXTURE_RELATIVE_PATH = (
    "tools/dynamic/docker/fixtures/skill_runtime_closure.py"
)
SKILL_CLOSURE_FIXTURE_SHA256 = (
    "6a2a52ee893884b1e124b180cd979be3fb8821952fc0feac27829b165c937bff"
)
EXPECTED_INITIAL_PATHS = ("README.txt", "SKILL.md")
EXPECTED_MATERIALIZED_PATHS = (
    "runtime/generated_action.py",
    "runtime/instructions.md",
    "runtime/policy.json",
)
EXPECTED_CATEGORIES = {
    "runtime/generated_action.py": "script",
    "runtime/instructions.md": "instruction",
    "runtime/policy.json": "config",
}
MAX_FILES = 8
MAX_FILE_BYTES = 16 * 1024
MAX_TOTAL_BYTES = 64 * 1024
StaticScan = Callable[[Path], dict[str, Any]]


@dataclass(frozen=True)
class SkillClosureConfig:
    config_path: Path
    config_sha256: str
    docker: DockerBackendConfig
    initial_paths: tuple[str, ...]
    materialized_paths: tuple[str, ...]
    categories: dict[str, str]
    max_files: int
    max_file_bytes: int
    max_total_bytes: int


def load_skill_closure_config(config_path: Path) -> SkillClosureConfig:
    config_path = config_path.resolve(strict=True)
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DockerBackendError("SKILL_CLOSURE_CONFIG_READ_FAILED", "config_load") from exc
    payload = _require_mapping(payload, "config")
    if set(payload) != {
        "schema_version", "backend_id", "docker_context", "pull_policy",
        "image", "fixture", "closure", "security",
    }:
        raise DockerBackendError("SKILL_CLOSURE_CONFIG_FIELDS_DENIED", "config_load")
    if payload.get("schema_version") != SKILL_CLOSURE_SCHEMA_VERSION:
        raise DockerBackendError("SKILL_CLOSURE_CONFIG_SCHEMA_DENIED", "config_load")
    if payload.get("backend_id") != SKILL_CLOSURE_BACKEND_ID:
        raise DockerBackendError("SKILL_CLOSURE_CONFIG_BACKEND_DENIED", "config_load")
    if payload.get("docker_context") != DOCKER_CONTEXT:
        raise DockerBackendError("SKILL_CLOSURE_CONFIG_CONTEXT_DENIED", "config_load")
    if payload.get("pull_policy") != "never":
        raise DockerBackendError("SKILL_CLOSURE_CONFIG_PULL_DENIED", "config_load")

    image = _require_mapping(payload.get("image"), "image")
    if image != {
        "reference": IMAGE_REFERENCE,
        "id": IMAGE_ID,
        "os": "linux",
        "architecture": "amd64",
    }:
        raise DockerBackendError("SKILL_CLOSURE_CONFIG_IMAGE_DENIED", "config_load")
    fixture = _require_mapping(payload.get("fixture"), "fixture")
    if fixture != {
        "id": SKILL_CLOSURE_FIXTURE_ID,
        "path": SKILL_CLOSURE_FIXTURE_RELATIVE_PATH,
        "sha256": SKILL_CLOSURE_FIXTURE_SHA256,
        "container_path": FIXTURE_CONTAINER_PATH,
        "timeout_seconds": 10,
    }:
        raise DockerBackendError("SKILL_CLOSURE_CONFIG_FIXTURE_DENIED", "config_load")
    fixture_path = (DEMO_ROOT / SKILL_CLOSURE_FIXTURE_RELATIVE_PATH).resolve(strict=True)
    fixture_root = (DEMO_ROOT / "tools" / "dynamic" / "docker" / "fixtures").resolve(
        strict=True
    )
    try:
        fixture_path.relative_to(fixture_root)
    except ValueError as exc:
        raise DockerBackendError("SKILL_CLOSURE_FIXTURE_PATH_DENIED", "config_load") from exc
    if fixture_path.is_symlink() or sha256_file(fixture_path) != SKILL_CLOSURE_FIXTURE_SHA256:
        raise DockerBackendError("SKILL_CLOSURE_FIXTURE_HASH_MISMATCH", "config_load")

    closure = _require_mapping(payload.get("closure"), "closure")
    if closure != {
        "runtime_id": SKILL_CLOSURE_RUNTIME_ID,
        "initial_paths": list(EXPECTED_INITIAL_PATHS),
        "materialized_paths": list(EXPECTED_MATERIALIZED_PATHS),
        "categories": EXPECTED_CATEGORIES,
        "max_files": MAX_FILES,
        "max_file_bytes": MAX_FILE_BYTES,
        "max_total_bytes": MAX_TOTAL_BYTES,
    }:
        raise DockerBackendError("SKILL_CLOSURE_CONTRACT_DENIED", "config_load")
    security = _require_mapping(payload.get("security"), "security")
    if security != EXPECTED_SECURITY:
        raise DockerBackendError("SKILL_CLOSURE_SECURITY_RELAXATION_DENIED", "config_load")
    docker = DockerBackendConfig(
        config_path=config_path,
        config_sha256=sha256_file(config_path),
        image_reference=IMAGE_REFERENCE,
        image_id=IMAGE_ID,
        fixture_path=fixture_path,
        fixture_sha256=SKILL_CLOSURE_FIXTURE_SHA256,
        fixture_timeout_seconds=10.0,
        security=security,
    )
    return SkillClosureConfig(
        config_path=config_path,
        config_sha256=docker.config_sha256,
        docker=docker,
        initial_paths=EXPECTED_INITIAL_PATHS,
        materialized_paths=EXPECTED_MATERIALIZED_PATHS,
        categories=dict(EXPECTED_CATEGORIES),
        max_files=MAX_FILES,
        max_file_bytes=MAX_FILE_BYTES,
        max_total_bytes=MAX_TOTAL_BYTES,
    )


def _safe_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 240:
        raise DockerBackendError("SKILL_CLOSURE_PATH_DENIED", label)
    if "\\" in value or "\0" in value:
        raise DockerBackendError("SKILL_CLOSURE_PATH_DENIED", label)
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise DockerBackendError("SKILL_CLOSURE_PATH_DENIED", label)
    return path.as_posix()


def _manifest(
    value: Any,
    label: str,
    config: SkillClosureConfig,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > config.max_files:
        raise DockerBackendError("SKILL_CLOSURE_MANIFEST_BOUNDS_DENIED", label)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    for index, raw in enumerate(value):
        row = _require_mapping(raw, f"{label}_{index}")
        if set(row) != {"path", "bytes", "sha256", "category"}:
            raise DockerBackendError("SKILL_CLOSURE_MANIFEST_FIELDS_DENIED", label)
        path = _safe_relative_path(row.get("path"), label)
        key = path.casefold()
        if key in seen:
            raise DockerBackendError("SKILL_CLOSURE_DUPLICATE_PATH", label)
        seen.add(key)
        size = row.get("bytes")
        digest = row.get("sha256")
        category = row.get("category")
        if not isinstance(size, int) or size < 1 or size > config.max_file_bytes:
            raise DockerBackendError("SKILL_CLOSURE_FILE_BOUNDS_DENIED", label)
        if not isinstance(digest, str) or len(digest) != 64:
            raise DockerBackendError("SKILL_CLOSURE_HASH_DENIED", label)
        if category not in {"initial", "instruction", "script", "config"}:
            raise DockerBackendError("SKILL_CLOSURE_CATEGORY_DENIED", label)
        total_bytes += size
        rows.append({"path": path, "bytes": size, "sha256": digest, "category": category})
    if total_bytes > config.max_total_bytes:
        raise DockerBackendError("SKILL_CLOSURE_TOTAL_BOUNDS_DENIED", label)
    return sorted(rows, key=lambda item: item["path"])


def _decode_bundle(
    value: Any,
    label: str,
    expected_paths: tuple[str, ...],
    manifest_by_path: dict[str, dict[str, Any]],
    config: SkillClosureConfig,
) -> tuple[dict[str, bytes], list[str]]:
    if not isinstance(value, list) or len(value) != len(expected_paths):
        raise DockerBackendError("SKILL_CLOSURE_BUNDLE_COUNT_DENIED", label)
    decoded: dict[str, bytes] = {}
    texts: list[str] = []
    total_bytes = 0
    for index, raw in enumerate(value):
        row = _require_mapping(raw, f"{label}_{index}")
        if set(row) != {"path", "bytes", "sha256", "content_b64"}:
            raise DockerBackendError("SKILL_CLOSURE_BUNDLE_FIELDS_DENIED", label)
        path = _safe_relative_path(row.get("path"), label)
        if path in decoded:
            raise DockerBackendError("SKILL_CLOSURE_DUPLICATE_PATH", label)
        encoded = row.get("content_b64")
        if not isinstance(encoded, str) or len(encoded) > config.max_file_bytes * 2:
            raise DockerBackendError("SKILL_CLOSURE_BUNDLE_BOUNDS_DENIED", label)
        try:
            content = base64.b64decode(encoded.encode("ascii"), validate=True)
            text = content.decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error) as exc:
            raise DockerBackendError("SKILL_CLOSURE_BUNDLE_DECODE_FAILED", label) from exc
        digest = sha256_bytes(content)
        if (
            not content
            or len(content) > config.max_file_bytes
            or row.get("bytes") != len(content)
            or row.get("sha256") != digest
            or manifest_by_path.get(path) != {
                **manifest_by_path.get(path, {}),
                "bytes": len(content),
                "sha256": digest,
            }
        ):
            raise DockerBackendError("SKILL_CLOSURE_BUNDLE_INTEGRITY_FAILED", label)
        decoded[path] = content
        texts.append(text)
        total_bytes += len(content)
    if tuple(sorted(decoded)) != tuple(sorted(expected_paths)) or total_bytes > config.max_total_bytes:
        raise DockerBackendError("SKILL_CLOSURE_BUNDLE_IDENTITY_DENIED", label)
    return decoded, texts


def _write_tree(root: Path, files: dict[str, bytes]) -> None:
    resolved_root = root.resolve(strict=True)
    for relative_path, content in files.items():
        target = root / PurePosixPath(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        resolved_parent = target.parent.resolve(strict=True)
        if resolved_parent != resolved_root and resolved_root not in resolved_parent.parents:
            raise DockerBackendError("SKILL_CLOSURE_WRITE_PATH_DENIED", "workspace")
        target.write_bytes(content)


def _canonical_file(value: Any, allowed_paths: set[str]) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("\\", "/")
    for path in sorted(allowed_paths, key=len, reverse=True):
        if normalized == path or normalized.endswith("/" + path):
            return path
    return None


def _sanitize_findings(
    findings: list[dict[str, Any]],
    allowed_paths: set[str],
) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for finding in findings:
        location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
        public_location = {
            "file": _canonical_file(location.get("file"), allowed_paths),
            "line": location.get("line") if isinstance(location.get("line"), int) else None,
        }
        identity = {
            "rule_id": finding.get("rule_id"),
            "analyzer": finding.get("analyzer"),
            "severity": str(finding.get("severity")),
            "file": public_location["file"],
            "line": public_location["line"],
        }
        sanitized.append({
            "id": hashlib.sha256(
                json.dumps(identity, sort_keys=True).encode("utf-8")
            ).hexdigest()[:20],
            "rule_id": finding.get("rule_id"),
            "analyzer": finding.get("analyzer"),
            "severity": str(finding.get("severity")),
            "category": finding.get("category"),
            "location": {key: value for key, value in public_location.items() if value is not None},
            "evidence_sha256": sha256_bytes(
                str(finding.get("evidence") or "").encode("utf-8", errors="replace")
            ),
            "raw_content_retained": False,
        })
    return sorted(
        sanitized,
        key=lambda item: (
            item["location"].get("file", ""),
            item["location"].get("line", 0),
            item.get("rule_id") or "",
            item["id"],
        ),
    )


def _finding_identity(finding: dict[str, Any]) -> tuple[Any, ...]:
    location = finding.get("location") or {}
    return (
        finding.get("rule_id"), finding.get("analyzer"), finding.get("severity"),
        location.get("file"), location.get("line"),
    )


def _default_static_scan(workspace_root: Path) -> StaticScan:
    repository_root = DEMO_ROOT.parent
    scanner = repository_root / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
    runner = ProcessRunner(
        timeout_seconds=150,
        cache_root=workspace_root / "scanner-cache",
        extra_path=repository_root / ".runtime_mcp313" / "Scripts",
    )
    adapter = SkillScannerAdapter(scanner=scanner, runner=runner)
    return lambda path: run_skill_static_pipeline(path, adapter)


def evaluate_skill_closure_payload(
    payload: dict[str, Any],
    config: SkillClosureConfig,
    workspace_root: Path,
    static_scan: StaticScan | None = None,
) -> dict[str, Any]:
    if payload.get("fixture_id") != SKILL_CLOSURE_FIXTURE_ID:
        raise DockerBackendError("SKILL_CLOSURE_FIXTURE_ID_DENIED", "closure_evaluation")
    if payload.get("runtime_id") != SKILL_CLOSURE_RUNTIME_ID:
        raise DockerBackendError("SKILL_CLOSURE_RUNTIME_ID_DENIED", "closure_evaluation")
    pre_manifest = _manifest(payload.get("pre_manifest"), "pre_manifest", config)
    post_manifest = _manifest(payload.get("post_manifest"), "post_manifest", config)
    pre_by_path = {row["path"]: row for row in pre_manifest}
    post_by_path = {row["path"]: row for row in post_manifest}
    if tuple(sorted(pre_by_path)) != config.initial_paths:
        raise DockerBackendError("SKILL_CLOSURE_PRE_IDENTITY_DENIED", "closure_evaluation")
    if tuple(sorted(post_by_path)) != tuple(sorted((*config.initial_paths, *config.materialized_paths))):
        raise DockerBackendError("SKILL_CLOSURE_POST_IDENTITY_DENIED", "closure_evaluation")
    if any(pre_by_path[path] != post_by_path[path] for path in config.initial_paths):
        raise DockerBackendError("SKILL_CLOSURE_INITIAL_FILE_CHANGED", "closure_evaluation")
    if any(
        post_by_path[path]["category"] != config.categories[path]
        for path in config.materialized_paths
    ):
        raise DockerBackendError("SKILL_CLOSURE_CATEGORY_MISMATCH", "closure_evaluation")

    initial_files, initial_texts = _decode_bundle(
        payload.get("initial_bundle"), "initial_bundle", config.initial_paths,
        pre_by_path, config,
    )
    generated_files, generated_texts = _decode_bundle(
        payload.get("materialized_bundle"), "materialized_bundle",
        config.materialized_paths, post_by_path, config,
    )
    if payload.get("materialized_files_expected") != len(config.materialized_paths):
        raise DockerBackendError("SKILL_CLOSURE_EXPECTED_COUNT_DENIED", "closure_evaluation")
    if payload.get("generated_content_executed") is not False:
        raise DockerBackendError("SKILL_CLOSURE_GENERATED_EXECUTION_DENIED", "closure_evaluation")

    workspace_root.mkdir(parents=True, exist_ok=True)
    scan = static_scan or _default_static_scan(workspace_root)
    with tempfile.TemporaryDirectory(prefix="skill-closure-", dir=workspace_root) as temp:
        temp_root = Path(temp)
        pre_root = temp_root / "pre"
        post_root = temp_root / "post"
        pre_root.mkdir()
        post_root.mkdir()
        _write_tree(pre_root, initial_files)
        _write_tree(post_root, {**initial_files, **generated_files})
        pre_scan = scan(pre_root)
        post_scan = scan(post_root)

    pre_raw = list(pre_scan.get("findings") or [])
    post_raw = list(post_scan.get("findings") or [])
    all_paths = set(pre_by_path) | set(post_by_path)
    pre_findings = _sanitize_findings(pre_raw, all_paths)
    post_findings = _sanitize_findings(post_raw, all_paths)
    pre_identities = {_finding_identity(item) for item in pre_findings}
    new_findings = [
        item for item in post_findings if _finding_identity(item) not in pre_identities
    ]
    risk_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    runtime_risk_findings = [
        item for item in new_findings
        if item.get("severity") in risk_severities
        and (item.get("location") or {}).get("file") in config.materialized_paths
    ]
    vendor_scans = int(pre_scan.get("vendor_scans") or 0) + int(
        post_scan.get("vendor_scans") or 0
    )
    pre_decision = evaluate_findings(pre_raw).decision.value
    post_decision = evaluate_findings(post_raw).decision.value
    runtime_gates = validate_runtime_probe(payload)
    closure_gates = {
        "fixture_identity_confirmed": True,
        "runtime_identity_confirmed": True,
        "pre_manifest_complete": len(pre_manifest) == len(config.initial_paths),
        "post_manifest_complete": len(post_manifest) == len(config.initial_paths) + len(config.materialized_paths),
        "materialized_count_exact": len(generated_files) == len(config.materialized_paths),
        "initial_files_unchanged": True,
        "deleted_files_absent": True,
        "materialized_hashes_verified": all(
            sha256_bytes(generated_files[path]) == post_by_path[path]["sha256"]
            for path in config.materialized_paths
        ),
        "instruction_classified": sum(
            row["category"] == "instruction" for row in post_manifest
        ) == 1,
        "script_classified": sum(row["category"] == "script" for row in post_manifest) == 1,
        "config_classified": sum(row["category"] == "config" for row in post_manifest) == 1,
        "generated_content_not_executed": True,
        "all_materialized_files_lifted": len(generated_files) == len(config.materialized_paths),
        "vendor_scanned_pre_and_post": vendor_scans == 2,
        "aegis_pipeline_ran_pre_and_post": bool(pre_scan.get("analyzers")) and bool(post_scan.get("analyzers")),
        "runtime_only_risk_recovered": len(runtime_risk_findings) >= 1,
        "raw_generated_content_not_retained": True,
        "policy_effect_none": True,
    }
    public = {
        "pre_manifest": pre_manifest,
        "post_manifest": post_manifest,
        "delta": {
            "added": list(config.materialized_paths),
            "modified": [],
            "deleted": [],
        },
        "static_lift": {
            "pre_findings_total": len(pre_findings),
            "post_findings_total": len(post_findings),
            "new_findings_total": len(new_findings),
            "runtime_risk_findings": runtime_risk_findings,
            "pre_analyzers": sorted(set(pre_scan.get("analyzers") or [])),
            "post_analyzers": sorted(set(post_scan.get("analyzers") or [])),
            "vendor_scans": vendor_scans,
            "pre_policy_recommendation": pre_decision,
            "post_policy_recommendation": post_decision,
            "policy_effect": "none",
        },
        "runtime_probe": {
            key: value for key, value in payload.items()
            if key in {
                "probe_id", "uid", "gid", "cap_eff", "no_new_privs", "seccomp",
                "rootfs_write", "input_write", "workspace_write", "temp_write",
                "network_interfaces", "cwd",
            }
        },
        "runtime_gates": runtime_gates,
        "closure_gates": closure_gates,
    }
    public_json = json.dumps(public, ensure_ascii=False, sort_keys=True)
    raw_content_leaks = sum(text in public_json for text in [*initial_texts, *generated_texts])
    closure_gates["raw_generated_content_not_retained"] = raw_content_leaks == 0
    public["privacy"] = {
        "raw_content_retained": False,
        "raw_content_leaks": raw_content_leaks,
        "content_bundles_retained": False,
    }
    public["closure_coverage_rate"] = len(generated_files) / len(config.materialized_paths)
    return public


def run_skill_closure_probe(
    config_path: Path,
    workspace_root: Path,
    static_scan: StaticScan | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    config = load_skill_closure_config(config_path)
    docker_cli = discover_docker_cli()
    container_name = f"aegis-dyn-{secrets.token_hex(8)}"
    container_id = ""
    error: dict[str, str] | None = None
    engine: dict[str, Any] = {}
    image: dict[str, Any] = {}
    image_gates: dict[str, bool] = {}
    inspect_gates: dict[str, bool] = {}
    runtime_gates: dict[str, bool] = {}
    closure_gates: dict[str, bool] = {}
    evaluated: dict[str, Any] = {}
    raw_stdout_leaks = 0
    start_result: DockerCommandResult | None = None
    command_plan = build_create_command(docker_cli, config.docker, container_name)
    cleanup = {"attempted": False, "removed": False, "residual": False}
    try:
        engine = probe_docker_engine(docker_cli)
        image, image_gates = inspect_image_identity(docker_cli, config.docker)
        if not all(image_gates.values()):
            raise DockerBackendError("DOCKER_IMAGE_GATE_FAILED", "image_inspect")
        create_result = run_docker_cli(command_plan, timeout_seconds=20.0)
        container_id = _require_success(create_result, "container_create")
        if not CONTAINER_ID_PATTERN.fullmatch(container_id):
            raise DockerBackendError("CONTAINER_ID_INVALID", "container_create")
        inspect_result = run_docker_cli(
            [*_docker_prefix(docker_cli), "container", "inspect", container_id, "--format", "{{json .}}"],
            timeout_seconds=15.0,
        )
        inspect_payload = _parse_json_object(
            _require_success(inspect_result, "container_inspect"),
            "CONTAINER_INSPECT_PARSE_FAILED", "container_inspect",
        )
        inspect_gates = validate_container_inspect(
            inspect_payload, config.docker, container_name=container_name,
        )
        if not all(inspect_gates.values()):
            raise DockerBackendError("CONTAINER_INSPECT_GATE_FAILED", "container_inspect")
        start_result = run_docker_cli(
            [*_docker_prefix(docker_cli), "container", "start", "--attach", container_id],
            timeout_seconds=config.docker.fixture_timeout_seconds,
        )
        runtime_payload = _parse_json_object(
            _require_success(start_result, "container_start"),
            "SKILL_CLOSURE_RUNTIME_PARSE_FAILED", "container_start",
        )
        for row in [*(runtime_payload.get("initial_bundle") or []), *(runtime_payload.get("materialized_bundle") or [])]:
            encoded = row.get("content_b64") if isinstance(row, dict) else None
            if isinstance(encoded, str):
                try:
                    raw = base64.b64decode(encoded.encode("ascii"), validate=True).decode("utf-8")
                except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error):
                    continue
                raw_stdout_leaks += int(raw in start_result.stdout)
        evaluated = evaluate_skill_closure_payload(
            runtime_payload, config, workspace_root, static_scan=static_scan,
        )
        runtime_gates = evaluated["runtime_gates"]
        closure_gates = evaluated["closure_gates"]
        closure_gates["raw_content_absent_from_container_stdout"] = raw_stdout_leaks == 0
        if not all(runtime_gates.values()):
            raise DockerBackendError("SKILL_CLOSURE_RUNTIME_GATE_FAILED", "container_start")
        if not all(closure_gates.values()):
            raise DockerBackendError("SKILL_CLOSURE_GATE_FAILED", "closure_evaluation")
    except DockerBackendError as exc:
        error = {"code": exc.code, "operation": exc.operation}
    finally:
        if container_id:
            try:
                cleanup = _cleanup_container(docker_cli, container_id)
            except DockerBackendError as exc:
                cleanup = {
                    "attempted": True, "removed": False, "residual": True,
                    "error_code": exc.code,
                }

    all_gates = {**image_gates, **inspect_gates, **runtime_gates, **closure_gates}
    success = (
        error is None and bool(all_gates) and all(all_gates.values())
        and cleanup.get("removed") is True and cleanup.get("residual") is False
    )
    lift = evaluated.get("static_lift") or {}
    delta = evaluated.get("delta") or {}
    metrics = {
        "schema_version": SKILL_CLOSURE_SCHEMA_VERSION,
        "backend_id": SKILL_CLOSURE_BACKEND_ID,
        "engine_ready": bool(engine.get("engine_version")),
        "image_gates_total": len(image_gates),
        "image_gates_passed": sum(image_gates.values()),
        "inspect_gates_total": len(inspect_gates),
        "inspect_gates_passed": sum(inspect_gates.values()),
        "runtime_gates_total": len(runtime_gates),
        "runtime_gates_passed": sum(runtime_gates.values()),
        "closure_gates_total": len(closure_gates),
        "closure_gates_passed": sum(closure_gates.values()),
        "all_gates_total": len(all_gates),
        "all_gates_passed": sum(all_gates.values()),
        "pre_files_total": len(evaluated.get("pre_manifest") or []),
        "post_files_total": len(evaluated.get("post_manifest") or []),
        "materialized_files_expected": len(config.materialized_paths),
        "materialized_files_observed": len(delta.get("added") or []),
        "materialized_files_lifted": len(delta.get("added") or []),
        "materialized_hashes_verified": len(config.materialized_paths) if closure_gates.get("materialized_hashes_verified") else 0,
        "instruction_files": sum(row.get("category") == "instruction" for row in evaluated.get("post_manifest") or []),
        "script_files": sum(row.get("category") == "script" for row in evaluated.get("post_manifest") or []),
        "config_files": sum(row.get("category") == "config" for row in evaluated.get("post_manifest") or []),
        "closure_coverage_rate": evaluated.get("closure_coverage_rate", 0.0),
        "pre_static_findings": int(lift.get("pre_findings_total") or 0),
        "post_static_findings": int(lift.get("post_findings_total") or 0),
        "new_static_findings": int(lift.get("new_findings_total") or 0),
        "runtime_risk_findings": len(lift.get("runtime_risk_findings") or []),
        "runtime_only_risk_recovered": int(closure_gates.get("runtime_only_risk_recovered") is True),
        "vendor_scans": int(lift.get("vendor_scans") or 0),
        "unsafe_paths": 0,
        "symlinks": 0,
        "oversized_files": 0,
        "unsupported_files": 0,
        "raw_content_leaks": int((evaluated.get("privacy") or {}).get("raw_content_leaks") or 0) + raw_stdout_leaks,
        "third_party_samples_executed": 0,
        "internet_used": 0,
        "image_pull_used": 0,
        "gpu_used": 0,
        "decision_changes": 0,
        "container_residuals": int(cleanup.get("residual") is True),
        "timeouts": int((error or {}).get("code") == "DOCKER_COMMAND_TIMEOUT"),
        "duration_ms": round((time.perf_counter() - started) * 1000),
    }
    return {
        "success": success,
        "error": error,
        "engine": engine,
        "image": image,
        "create_command": redact_docker_command(command_plan),
        "image_gates": image_gates,
        "inspect_gates": inspect_gates,
        "runtime_gates": runtime_gates,
        "closure_gates": closure_gates,
        "closure": evaluated,
        "cleanup": cleanup,
        "metrics": metrics,
        "claim_boundary": (
            "仅证明自建哈希锁定 Skill fixture 的运行时目录闭包与静态再扫描机制；"
            "不证明任意第三方 Skill 可安全执行，也不替代系统调用级沙箱。"
        ),
    }
