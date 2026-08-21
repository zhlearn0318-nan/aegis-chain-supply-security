from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
import zipfile
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .adapters import DependencyAuditAdapter, McpScannerAdapter, ProcessRunner, SkillScannerAdapter
from .analyzers import (
    ANALYZER_ID as AEGIS_STATIC_ANALYZER_ID,
    COMMAND_CONTEXT_ANALYZER_ID,
    DEPENDENCY_INTEGRITY_ANALYZER_ID,
    ENTERPRISE_CONTROLS_ANALYZER_ID,
    FILESYSTEM_CONTEXT_ANALYZER_ID,
    MCP_POLICY_ANALYZER_ID,
    NETWORK_CONTEXT_ANALYZER_ID,
    SENSITIVE_FLOW_ANALYZER_ID,
    STATIC_COVERAGE_ANALYZER_ID,
    UNTRUSTED_EXEC_FLOW_ANALYZER_ID,
    analyze_command_context,
    analyze_dependency_manifest,
    analyze_enterprise_controls,
    analyze_filesystem_context,
    analyze_mcp_objects,
    analyze_network_context,
    analyze_sensitive_flows,
    analyze_static_coverage,
    analyze_skill_tree,
    analyze_untrusted_exec_flows,
)
from .api_contract import ErrorCode, GatewayHTTPException
from .api_v1 import ApiV1Operations, install_api_v1
from .dynamic_audit.runner import run_safe_fixture_set
from .models import SCHEMA_VERSION, DynamicAuditJob, ScanJob
from .normalizers import normalize_mcp, normalize_pip_audit, normalize_skill
from .policy import (
    PolicyConfigurationError,
    decision_from_findings,
    evaluate_findings,
    failure_policy_trace,
    load_policy,
    pending_policy_trace,
    summarize,
)


ROOT = Path(__file__).resolve().parents[2]
DEMO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = DEMO_ROOT / "data"
DB_PATH = DATA_DIR / "scan_history.db"
FRONTEND_DIST = DEMO_ROOT / "frontend" / "dist"
DYNAMIC_FIXTURE_CONFIG = DEMO_ROOT / "config" / "safe_dynamic_fixtures.json"
DYNAMIC_FIXTURE_ROOT = DEMO_ROOT / "tools" / "dynamic" / "fixtures"
DYNAMIC_JOB_ROOT = DATA_DIR / "dynamic-audit-jobs"
ADMIN_TOKEN_ENV = "AEGIS_ADMIN_TOKEN"
MIN_ADMIN_TOKEN_LENGTH = 16

SKILL_SCANNER = ROOT / ".runtime_skill" / "Scripts" / "skill-scanner.exe"
SKILL_PYTHON = ROOT / ".runtime_skill" / "Scripts" / "python.exe"
MCP_SCRIPTS = ROOT / ".runtime_mcp313" / "Scripts"
MCP_SCANNER = MCP_SCRIPTS / "mcp-scanner.exe"
MCP_PYTHON = MCP_SCRIPTS / "python.exe"
PIP_AUDIT = MCP_SCRIPTS / "pip-audit.exe"
MCP_WRAPPER = ROOT / "scripts" / "run_mcp_static.py"

MAX_UPLOAD_BYTES = 15 * 1024 * 1024
MAX_ZIP_MEMBERS = 500
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 200
ZIP_COPY_CHUNK_BYTES = 64 * 1024
SCAN_TIMEOUT_SECONDS = 150

PROCESS_RUNNER = ProcessRunner(
    timeout_seconds=SCAN_TIMEOUT_SECONDS,
    cache_root=DATA_DIR / "cache",
    extra_path=MCP_SCRIPTS,
)
SKILL_ADAPTER = SkillScannerAdapter(scanner=SKILL_SCANNER, runner=PROCESS_RUNNER)
MCP_ADAPTER = McpScannerAdapter(
    python=MCP_PYTHON,
    wrapper=MCP_WRAPPER,
    scanner=MCP_SCANNER,
    runner=PROCESS_RUNNER,
)
DEPENDENCY_ADAPTER = DependencyAuditAdapter(
    executable=PIP_AUDIT,
    cache_dir=DATA_DIR / "cache" / "pip-audit",
    runner=PROCESS_RUNNER,
)

PRESETS = {
    "skill-safe": {
        "id": "skill-safe",
        "kind": "skill",
        "name": "安全文档摘要 Skill",
        "description": "结构完整、不读取凭据、不访问外部服务的基础样本。",
        "path": ROOT / "fixtures" / "skills" / "benign_doc_summary",
        "tone": "safe",
    },
    "skill-risky": {
        "id": "skill-risky",
        "kind": "skill",
        "name": "数据外传 Skill",
        "description": "包含凭据读取和向外部地址发送数据的高风险样本。",
        "path": ROOT / "fixtures" / "skills" / "malicious_exfiltration",
        "tone": "risk",
    },
    "mcp-mixed": {
        "id": "mcp-mixed",
        "kind": "mcp",
        "name": "MCP 混合对象集",
        "description": "同时包含安全与恶意 Tool、Prompt、Resource 的离线对象集。",
        "paths": {
            "tools": ROOT / "fixtures" / "mcp" / "tools.json",
            "prompts": ROOT / "fixtures" / "mcp" / "prompts.json",
            "resources": ROOT / "fixtures" / "mcp" / "resources.json",
        },
        "tone": "mixed",
    },
    "dependency-risky": {
        "id": "dependency-risky",
        "kind": "dependency",
        "name": "易受攻击依赖",
        "description": "使用旧版 urllib3，用于演示已知供应链漏洞检测。",
        "path": ROOT / "fixtures" / "vulnerable_dependencies" / "requirements_urllib3.txt",
        "tone": "risk",
    },
}

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="Agent Supply Chain Security Demo", version="1.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with closing(connect_db()) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                display_name TEXT NOT NULL,
                artifact_sha256 TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS dynamic_audits (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                fixture_set_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        db.commit()


def save_job(job: dict[str, Any]) -> None:
    validated = ScanJob.model_validate(job).model_dump(mode="json")
    job.clear()
    job.update(validated)
    with closing(connect_db()) as db:
        db.execute(
            """
            INSERT INTO scans(id, created_at, updated_at, status, target_kind, source_kind,
                              display_name, artifact_sha256, payload_json)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                updated_at=excluded.updated_at,
                status=excluded.status,
                artifact_sha256=excluded.artifact_sha256,
                payload_json=excluded.payload_json
            """,
            (
                job["id"], job["created_at"], job["updated_at"], job["status"],
                job["target_kind"], job["source_kind"], job["display_name"],
                job.get("artifact_sha256"), json.dumps(job, ensure_ascii=False),
            ),
        )
        db.commit()


def validate_stored_job(payload: dict[str, Any]) -> dict[str, Any]:
    payload.setdefault("schema_version", SCHEMA_VERSION)
    payload.setdefault("summary", {}).setdefault("unknown", 0)
    return ScanJob.model_validate(payload).model_dump(mode="json")


def load_job(job_id: str) -> dict[str, Any] | None:
    with closing(connect_db()) as db:
        row = db.execute("SELECT payload_json FROM scans WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return None
    return validate_stored_job(json.loads(row["payload_json"]))


def new_job(target_kind: str, source_kind: str, display_name: str) -> dict[str, Any]:
    now = utc_now()
    job = ScanJob(
        id=uuid.uuid4().hex,
        created_at=now,
        updated_at=now,
        status="queued",
        target_kind=target_kind,
        source_kind=source_kind,
        display_name=display_name,
        policy_trace=pending_policy_trace(),
    ).model_dump(mode="json")
    save_job(job)
    return job


def update_job(job: dict[str, Any], **changes: Any) -> None:
    job.update(changes)
    job["updated_at"] = utc_now()
    save_job(job)


def save_dynamic_audit_job(job: dict[str, Any]) -> None:
    validated = DynamicAuditJob.model_validate(job).model_dump(mode="json")
    job.clear()
    job.update(validated)
    with closing(connect_db()) as db:
        db.execute(
            """
            INSERT INTO dynamic_audits(
                id, created_at, updated_at, status, fixture_set_id, payload_json
            )
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                updated_at=excluded.updated_at,
                status=excluded.status,
                payload_json=excluded.payload_json
            """,
            (
                job["id"],
                job["created_at"],
                job["updated_at"],
                job["status"],
                job["fixture_set_id"],
                json.dumps(job, ensure_ascii=False),
            ),
        )
        db.commit()


def load_dynamic_audit_job(job_id: str) -> dict[str, Any] | None:
    with closing(connect_db()) as db:
        row = db.execute(
            "SELECT payload_json FROM dynamic_audits WHERE id = ?", (job_id,)
        ).fetchone()
    if not row:
        return None
    return DynamicAuditJob.model_validate(
        json.loads(row["payload_json"])
    ).model_dump(mode="json")


def new_dynamic_audit_job() -> dict[str, Any]:
    now = utc_now()
    job = DynamicAuditJob(
        id=uuid.uuid4().hex,
        created_at=now,
        updated_at=now,
        status="queued",
        fixture_set_sha256=sha256_bytes(DYNAMIC_FIXTURE_CONFIG.read_bytes()),
    ).model_dump(mode="json")
    save_dynamic_audit_job(job)
    return job


def update_dynamic_audit_job(job: dict[str, Any], **changes: Any) -> None:
    job.update(changes)
    job["updated_at"] = utc_now()
    save_dynamic_audit_job(job)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_tree(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(item.read_bytes())
    return digest.hexdigest()


def complete_scan_job(
    job: dict[str, Any],
    *,
    started: float,
    findings: list[dict[str, Any]],
    analyzers: list[str],
    logs: list[str],
    sbom: dict[str, Any] | None = None,
) -> None:
    duration_ms = round((time.perf_counter() - started) * 1000)
    try:
        evaluation = evaluate_findings(findings)
    except PolicyConfigurationError as exc:
        update_job(
            job,
            status="failed",
            decision="UNKNOWN",
            policy_trace=failure_policy_trace("POLICY_CONFIGURATION_ERROR", str(exc)).model_dump(mode="json"),
            summary=summarize(findings),
            findings=findings,
            analyzers=analyzers,
            duration_ms=duration_ms,
            error=str(exc),
            logs=logs,
            sbom=sbom,
        )
        return
    update_job(
        job,
        status="completed",
        decision=evaluation.decision.value,
        policy_trace=evaluation.trace.model_dump(mode="json"),
        summary=summarize(findings),
        findings=findings,
        analyzers=analyzers,
        duration_ms=duration_ms,
        error=None,
        logs=logs,
        sbom=sbom,
    )


def scan_skill_path(job: dict[str, Any], skill_path: Path) -> None:
    started = time.perf_counter()
    execution = SKILL_ADAPTER.scan(skill_path)
    cisco_findings, cisco_analyzers = normalize_skill(execution.report)
    aegis_findings, aegis_analyzers = analyze_skill_tree(skill_path)
    sensitive_flow_findings, sensitive_flow_analyzers = analyze_sensitive_flows(skill_path)
    untrusted_exec_findings, untrusted_exec_analyzers = analyze_untrusted_exec_flows(skill_path)
    enterprise_findings, enterprise_analyzers = analyze_enterprise_controls(skill_path)
    coverage_findings, coverage_analyzers = analyze_static_coverage(skill_path)
    network_findings, network_analyzers = analyze_network_context(skill_path, cisco_findings)
    filesystem_findings, filesystem_analyzers = analyze_filesystem_context(
        skill_path, cisco_findings
    )
    command_findings, command_analyzers = analyze_command_context(
        skill_path, cisco_findings
    )
    findings = (
        cisco_findings + aegis_findings + sensitive_flow_findings + untrusted_exec_findings
        + enterprise_findings + coverage_findings + network_findings
        + filesystem_findings + command_findings
    )
    analyzers = sorted(set(
        cisco_analyzers + aegis_analyzers + sensitive_flow_analyzers + untrusted_exec_analyzers
        + enterprise_analyzers + coverage_analyzers + network_analyzers
        + filesystem_analyzers + command_analyzers
    ))
    complete_scan_job(
        job,
        started=started,
        findings=findings,
        analyzers=analyzers,
        logs=execution.logs[-4:],
    )


def scan_mcp_paths(job: dict[str, Any], tools: Path, prompts: Path, resources: Path) -> None:
    started = time.perf_counter()
    execution = MCP_ADAPTER.scan(tools, prompts, resources)
    findings, analyzers = normalize_mcp(execution.report)
    policy_findings, policy_analyzers = analyze_mcp_objects(tools, prompts, resources)
    complete_scan_job(
        job,
        started=started,
        findings=findings + policy_findings,
        analyzers=sorted(set(analyzers + policy_analyzers)),
        logs=execution.logs[-4:],
    )


def scan_dependency_path(job: dict[str, Any], requirements: Path) -> None:
    started = time.perf_counter()
    execution = DEPENDENCY_ADAPTER.scan(requirements)
    findings, analyzers = normalize_pip_audit(execution.report)
    integrity_findings, integrity_analyzers, sbom = analyze_dependency_manifest(requirements)
    complete_scan_job(
        job,
        started=started,
        findings=findings + integrity_findings,
        analyzers=sorted(set(analyzers + integrity_analyzers)),
        logs=execution.logs[-4:],
        sbom=sbom,
    )


def scan_mcp_bundle(job: dict[str, Any], tools: Path, prompts: Path, resources: Path, requirements: Path) -> None:
    started = time.perf_counter()
    static_execution = MCP_ADAPTER.scan(tools, prompts, resources)
    dependency_execution = DEPENDENCY_ADAPTER.scan(requirements)
    static_findings, static_analyzers = normalize_mcp(static_execution.report)
    dependency_findings, dependency_analyzers = normalize_pip_audit(dependency_execution.report)
    policy_findings, policy_analyzers = analyze_mcp_objects(tools, prompts, resources)
    integrity_findings, integrity_analyzers, sbom = analyze_dependency_manifest(requirements)
    findings = static_findings + policy_findings + dependency_findings + integrity_findings
    analyzers = sorted(set(static_analyzers + policy_analyzers + dependency_analyzers + integrity_analyzers))
    logs = static_execution.logs + dependency_execution.logs
    complete_scan_job(
        job,
        started=started,
        findings=findings,
        analyzers=analyzers,
        logs=logs[-6:],
        sbom=sbom,
    )


def guarded_worker(job_id: str, worker, *args) -> None:
    job = load_job(job_id)
    if not job:
        return
    update_job(job, status="running", error=None)
    try:
        worker(job, *args)
    except subprocess.TimeoutExpired:
        reason = "扫描超时，结果不完整，已按失败闭锁处理。"
        update_job(
            job,
            status="failed",
            decision="UNKNOWN",
            policy_trace=failure_policy_trace("SCAN_TIMEOUT", reason).model_dump(mode="json"),
            error=reason,
        )
    except Exception as exc:
        reason = str(exc)
        update_job(
            job,
            status="failed",
            decision="UNKNOWN",
            policy_trace=failure_policy_trace("SCAN_EXECUTION_FAILED", reason).model_dump(mode="json"),
            error=reason,
        )
    finally:
        for path in args:
            if isinstance(path, Path) and str(path).startswith(tempfile.gettempdir()) and path.exists():
                root = path if path.is_dir() else path.parent
                shutil.rmtree(root, ignore_errors=True)


def admin_token_is_configured() -> bool:
    configured = os.environ.get(ADMIN_TOKEN_ENV)
    return configured is not None and len(configured) >= MIN_ADMIN_TOKEN_LENGTH


def verify_admin_token(presented: str | None) -> None:
    configured = os.environ.get(ADMIN_TOKEN_ENV)
    if configured is None or len(configured) < MIN_ADMIN_TOKEN_LENGTH:
        raise GatewayHTTPException(
            503,
            ErrorCode.ADMIN_TOKEN_NOT_CONFIGURED,
            "管理员动态验证尚未安全配置。请先设置服务端环境变量 AEGIS_ADMIN_TOKEN。",
        )
    if not secrets.compare_digest(presented or "", configured):
        raise GatewayHTTPException(
            401,
            ErrorCode.ADMIN_TOKEN_INVALID,
            "管理员凭据无效。",
        )


def dynamic_fixture_is_ready() -> bool:
    return DYNAMIC_FIXTURE_CONFIG.is_file() and DYNAMIC_FIXTURE_ROOT.is_dir()


def guarded_dynamic_audit_worker(job_id: str) -> None:
    job = load_dynamic_audit_job(job_id)
    if not job:
        return
    update_dynamic_audit_job(job, status="running", error_code=None, error=None)
    started = time.perf_counter()
    job_root = DYNAMIC_JOB_ROOT / job_id
    try:
        result = run_safe_fixture_set(
            DYNAMIC_FIXTURE_CONFIG,
            job_root / "workspaces",
        )
        info_events = [
            event for event in result["events"] if event.get("severity") == "INFO"
        ]
        completed = bool(result["success"])
        update_dynamic_audit_job(
            job,
            status="completed" if completed else "failed",
            metrics=result["metrics"],
            fixture_results=result["fixture_results"],
            events=info_events,
            duration_ms=round((time.perf_counter() - started) * 1000),
            error_code=None if completed else "DYNAMIC_FIXTURE_VALIDATION_FAILED",
            error=None if completed else "内置动态验证未满足全部预期机制，请检查任务指标。",
        )
    except Exception:
        update_dynamic_audit_job(
            job,
            status="failed",
            duration_ms=round((time.perf_counter() - started) * 1000),
            error_code="DYNAMIC_AUDIT_EXECUTION_FAILED",
            error="内置动态验证执行失败，未产生可用于准入决策的结论。",
        )
    finally:
        if job_root.exists():
            shutil.rmtree(job_root, ignore_errors=True)


def safe_extract_zip(data: bytes, destination: Path) -> Path:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if len(members) > MAX_ZIP_MEMBERS:
            raise ValueError("ZIP 文件数量超过演示环境限制")
        root = destination.resolve()
        validated: list[tuple[zipfile.ZipInfo, Path]] = []
        target_keys: set[str] = set()
        file_target_keys: set[str] = set()
        total_uncompressed = 0
        for member in members:
            target = (destination / member.filename).resolve()
            if root not in target.parents and target != root:
                raise ValueError("ZIP 包含不安全的路径")
            target_key = str(target).casefold()
            if target_key in target_keys:
                raise ValueError("ZIP 包含重复或大小写冲突的路径")
            target_keys.add(target_key)
            if member.flag_bits & 0x1:
                raise ValueError("ZIP 包含加密成员，无法进行完整静态检查")
            unix_mode = (member.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(unix_mode)
            if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError("ZIP 包含链接、设备或其他特殊文件")
            if member.file_size > MAX_UPLOAD_BYTES:
                raise ValueError("ZIP 内单个文件过大")
            total_uncompressed += member.file_size
            if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
                raise ValueError("ZIP 累计展开大小超过演示环境限制")
            if (
                member.file_size > 0
                and member.file_size / max(member.compress_size, 1) > MAX_ZIP_COMPRESSION_RATIO
            ):
                raise ValueError("ZIP 成员压缩比异常，疑似压缩炸弹")
            if not member.is_dir():
                file_target_keys.add(target_key)
            validated.append((member, target))

        for _, target in validated:
            parent = target.parent
            while parent != root and root in parent.parents:
                if str(parent).casefold() in file_target_keys:
                    raise ValueError("ZIP 文件与目录路径发生冲突")
                parent = parent.parent

        actual_total = 0
        for member, target in validated:
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            member_written = 0
            try:
                with archive.open(member, "r") as source, target.open("xb") as destination_file:
                    while block := source.read(ZIP_COPY_CHUNK_BYTES):
                        member_written += len(block)
                        actual_total += len(block)
                        if member_written > member.file_size:
                            raise ValueError("ZIP 成员实际展开大小与目录声明不一致")
                        if actual_total > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
                            raise ValueError("ZIP 实际累计展开大小超过演示环境限制")
                        destination_file.write(block)
                if member_written != member.file_size:
                    raise ValueError("ZIP 成员实际展开大小与目录声明不一致")
            except Exception:
                target.unlink(missing_ok=True)
                raise
    candidates = list(destination.rglob("SKILL.md"))
    if len(candidates) != 1:
        raise ValueError("ZIP 必须且只能包含一个 SKILL.md")
    return candidates[0].parent


def write_mcp_parts(data: bytes, destination: Path) -> tuple[Path, Path, Path]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"MCP JSON 无法解析：{exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("MCP JSON 顶层必须是对象")
    nested = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    tools = payload.get("tools", nested.get("tools", []))
    prompts = payload.get("prompts", nested.get("prompts", []))
    resources = payload.get("resources", payload.get("contents", nested.get("resources", nested.get("contents", []))))
    if not any([tools, prompts, resources]):
        raise ValueError("MCP JSON 中没有 tools、prompts、resources 或 contents")
    paths = (destination / "tools.json", destination / "prompts.json", destination / "resources.json")
    paths[0].write_text(json.dumps({"tools": tools}, ensure_ascii=False), encoding="utf-8")
    paths[1].write_text(json.dumps({"prompts": prompts}, ensure_ascii=False), encoding="utf-8")
    paths[2].write_text(json.dumps({"contents": resources}, ensure_ascii=False), encoding="utf-8")
    return paths


def version_output(command: list[str], fallback: str) -> str:
    try:
        result = PROCESS_RUNNER.run(command)
        text = (result.stdout or result.stderr).strip().splitlines()
        return text[-1] if result.returncode == 0 and text else fallback
    except Exception:
        return fallback


@app.get("/api/health")
def health() -> dict[str, Any]:
    skill_ready = SKILL_SCANNER.exists() and SKILL_PYTHON.exists()
    mcp_ready = MCP_SCANNER.exists() and MCP_PYTHON.exists() and MCP_WRAPPER.exists()
    dependency_ready = mcp_ready and PIP_AUDIT.exists()
    dynamic_ready = dynamic_fixture_is_ready() and admin_token_is_configured()
    try:
        selected_policy = load_policy()
        policy_status = {
            "ready": True,
            "id": selected_policy.policy_id,
            "version": selected_policy.version,
            "fail_closed": selected_policy.decision.fail_closed,
        }
    except PolicyConfigurationError as exc:
        policy_status = {
            "ready": False,
            "id": "unavailable",
            "version": "unavailable",
            "fail_closed": True,
            "error": str(exc),
        }
    skill_version = version_output([str(SKILL_PYTHON), "-c", "import importlib.metadata as m; print(m.version('cisco-ai-skill-scanner'))"], "unavailable") if skill_ready else "missing"
    mcp_version = version_output([
        str(MCP_PYTHON), "-c", "import importlib.metadata as m; print(m.version('cisco-ai-mcp-scanner'))"
    ], "unavailable") if mcp_ready else "missing"
    return {
        "status": "ready" if skill_ready and mcp_ready and dependency_ready and dynamic_ready and policy_status["ready"] else "degraded",
        "mode": "LOCAL_STATIC_PLUS_TRUSTED_FIXTURE_DYNAMIC",
        "policy": policy_status,
        "engines": [
            {"id": "skill", "name": "Skill Scanner + Aegis Static/Context", "ready": skill_ready, "version": skill_version, "analyzers": ["static", "bytecode", "pipeline", AEGIS_STATIC_ANALYZER_ID, SENSITIVE_FLOW_ANALYZER_ID, UNTRUSTED_EXEC_FLOW_ANALYZER_ID, ENTERPRISE_CONTROLS_ANALYZER_ID, STATIC_COVERAGE_ANALYZER_ID, NETWORK_CONTEXT_ANALYZER_ID, FILESYSTEM_CONTEXT_ANALYZER_ID, COMMAND_CONTEXT_ANALYZER_ID]},
            {"id": "mcp", "name": "MCP Scanner + Capability Policy", "ready": mcp_ready, "version": mcp_version, "analyzers": ["yara", "offline objects", MCP_POLICY_ANALYZER_ID]},
            {"id": "dependency", "name": "Dependency Audit + Integrity/SBOM", "ready": dependency_ready, "version": "pip-audit+aegis-v1", "analyzers": ["CVE", "GHSA", "PYSEC", DEPENDENCY_INTEGRITY_ANALYZER_ID]},
            {"id": "dynamic-fixture", "name": "管理员可信样本动态验证", "ready": dynamic_ready, "version": "aegis-safe-dynamic-fixtures-v1", "analyzers": ["Python audit hook", "hash lock", "loopback only", "INFO only"]},
        ],
        "privacy": "上传样本和动态验证工作区在任务结束后删除；历史仅保存脱敏结果，管理员令牌不持久化。",
    }


@app.get("/api/presets")
def presets() -> list[dict[str, Any]]:
    return [{key: value for key, value in preset.items() if key not in {"path", "paths"}} for preset in PRESETS.values()]


@app.post("/api/scans/preset/{preset_id}")
def start_preset(preset_id: str, background: BackgroundTasks) -> dict[str, Any]:
    preset = PRESETS.get(preset_id)
    if not preset:
        raise GatewayHTTPException(404, ErrorCode.PRESET_NOT_FOUND, "未找到预置样本")
    job = new_job(preset["kind"], "preset", preset["name"])
    if preset["kind"] == "skill":
        job["artifact_sha256"] = sha256_tree(preset["path"])
        save_job(job)
        background.add_task(guarded_worker, job["id"], scan_skill_path, preset["path"])
    elif preset["kind"] == "mcp":
        combined = b"".join(p.read_bytes() for p in preset["paths"].values())
        job["artifact_sha256"] = sha256_bytes(combined)
        save_job(job)
        background.add_task(guarded_worker, job["id"], scan_mcp_paths, *preset["paths"].values())
    else:
        job["artifact_sha256"] = sha256_bytes(preset["path"].read_bytes())
        save_job(job)
        background.add_task(guarded_worker, job["id"], scan_dependency_path, preset["path"])
    return job


@app.post("/api/scans/skill")
async def upload_skill(background: BackgroundTasks, file: UploadFile = File(...)) -> dict[str, Any]:
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise GatewayHTTPException(
            400,
            ErrorCode.SKILL_FILE_TYPE_INVALID,
            "Skill 必须上传 ZIP 文件",
            details={"field": "file", "accepted_extension": ".zip"},
        )
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise GatewayHTTPException(
            413,
            ErrorCode.UPLOAD_TOO_LARGE,
            "上传文件超过 15 MB",
            details={"field": "file", "limit_bytes": MAX_UPLOAD_BYTES},
        )
    temp_root = Path(tempfile.mkdtemp(prefix="skill-upload-"))
    try:
        skill_path = safe_extract_zip(data, temp_root)
    except Exception as exc:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise GatewayHTTPException(
            400,
            ErrorCode.SKILL_ARCHIVE_INVALID,
            str(exc),
            details={"field": "file"},
        ) from exc
    job = new_job("skill", "upload", Path(file.filename).name)
    job["artifact_sha256"] = sha256_bytes(data)
    save_job(job)
    background.add_task(guarded_worker, job["id"], scan_skill_path, skill_path)
    return job


@app.post("/api/scans/mcp")
async def upload_mcp(
    background: BackgroundTasks,
    mcp_json: UploadFile = File(...),
    requirements: UploadFile | None = File(None),
) -> dict[str, Any]:
    if not mcp_json.filename or not mcp_json.filename.lower().endswith(".json"):
        raise GatewayHTTPException(
            400,
            ErrorCode.MCP_FILE_TYPE_INVALID,
            "MCP 对象必须上传 JSON 文件",
            details={"field": "mcp_json", "accepted_extension": ".json"},
        )
    data = await mcp_json.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise GatewayHTTPException(
            413,
            ErrorCode.UPLOAD_TOO_LARGE,
            "上传文件超过 15 MB",
            details={"field": "mcp_json", "limit_bytes": MAX_UPLOAD_BYTES},
        )
    temp_root = Path(tempfile.mkdtemp(prefix="mcp-upload-"))
    try:
        tools, prompts, resources = write_mcp_parts(data, temp_root)
    except Exception as exc:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise GatewayHTTPException(
            400,
            ErrorCode.MCP_PAYLOAD_INVALID,
            str(exc),
            details={"field": "mcp_json"},
        ) from exc
    job = new_job("mcp", "upload", Path(mcp_json.filename).name)
    job["artifact_sha256"] = sha256_bytes(data)
    req_path = None
    if requirements and requirements.filename:
        req_data = await requirements.read(MAX_UPLOAD_BYTES + 1)
        if len(req_data) > MAX_UPLOAD_BYTES:
            shutil.rmtree(temp_root, ignore_errors=True)
            raise GatewayHTTPException(
                413,
                ErrorCode.UPLOAD_TOO_LARGE,
                "依赖文件超过 15 MB",
                details={"field": "requirements", "limit_bytes": MAX_UPLOAD_BYTES},
            )
        req_path = temp_root / "requirements.txt"
        req_path.write_bytes(req_data)
        job["display_name"] += " + requirements.txt"
        job["artifact_sha256"] = sha256_bytes(data + req_data)
    save_job(job)
    if req_path:
        background.add_task(guarded_worker, job["id"], scan_mcp_bundle, tools, prompts, resources, req_path)
    else:
        background.add_task(guarded_worker, job["id"], scan_mcp_paths, tools, prompts, resources)
    return job


@app.post("/api/scans/dependency")
async def upload_dependency(background: BackgroundTasks, requirements: UploadFile = File(...)) -> dict[str, Any]:
    data = await requirements.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise GatewayHTTPException(
            413,
            ErrorCode.UPLOAD_TOO_LARGE,
            "依赖文件超过 15 MB",
            details={"field": "requirements", "limit_bytes": MAX_UPLOAD_BYTES},
        )
    temp_root = Path(tempfile.mkdtemp(prefix="dependency-upload-"))
    path = temp_root / "requirements.txt"
    path.write_bytes(data)
    job = new_job("dependency", "upload", Path(requirements.filename or "requirements.txt").name)
    job["artifact_sha256"] = sha256_bytes(data)
    save_job(job)
    background.add_task(guarded_worker, job["id"], scan_dependency_path, path)
    return job


@app.get("/api/scans")
def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    limit = min(max(limit, 1), 100)
    with closing(connect_db()) as db:
        rows = db.execute("SELECT payload_json FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [validate_stored_job(json.loads(row["payload_json"])) for row in rows]


@app.get("/api/scans/{job_id}")
def get_scan(job_id: str) -> dict[str, Any]:
    job = load_job(job_id)
    if not job:
        raise GatewayHTTPException(404, ErrorCode.SCAN_NOT_FOUND, "扫描任务不存在")
    return job


@app.get("/api/scans/{job_id}/export")
def export_scan(job_id: str, format: str = "json"):
    job = load_job(job_id)
    if not job:
        raise GatewayHTTPException(404, ErrorCode.SCAN_NOT_FOUND, "扫描任务不存在")
    if format == "json":
        response = JSONResponse(job)
        response.headers["Content-Disposition"] = f'attachment; filename="scan-{job_id}.json"'
        return response
    if format in {"sbom", "cyclonedx"}:
        sbom = job.get("sbom")
        if not isinstance(sbom, dict):
            raise GatewayHTTPException(
                400,
                ErrorCode.SBOM_UNAVAILABLE,
                "该扫描任务没有依赖清单；仅依赖扫描或带 requirements 的 MCP 扫描可导出 SBOM。",
                details={"target_kind": job.get("target_kind")},
            )
        response = JSONResponse(sbom, media_type="application/vnd.cyclonedx+json")
        response.headers["Content-Disposition"] = f'attachment; filename="scan-{job_id}.cdx.json"'
        return response
    if format not in {"md", "markdown"}:
        raise GatewayHTTPException(
            400,
            ErrorCode.EXPORT_FORMAT_UNSUPPORTED,
            "仅支持 json、md 或 sbom",
            details={"accepted_formats": ["json", "md", "sbom"]},
        )
    policy_trace = job.get("policy_trace") or {}
    lines = [
        f"# 扫描技术汇报摘要：{job['display_name']}", "",
        f"- 任务编号：`{job['id']}`",
        f"- 类型：{job['target_kind']}",
        f"- 状态：{job['status']}",
        f"- 决策：**{job['decision']}**",
        f"- 制品 SHA-256：`{job.get('artifact_sha256') or 'N/A'}`",
        f"- 分析器：{', '.join(job.get('analyzers') or []) or 'N/A'}",
        f"- 扫描耗时：{job.get('duration_ms') or 0} ms", "",
        "## 准入策略", "",
        f"- 策略：`{policy_trace.get('policy_id', 'unresolved')}@{policy_trace.get('policy_version', 'unresolved')}`",
        f"- 命中规则：`{policy_trace.get('rule_id', 'PENDING_SCAN')}`",
        f"- 失败闭锁：{policy_trace.get('fail_closed', True)}",
        f"- 判定原因：{policy_trace.get('reason') or 'N/A'}", "",
        "## 风险发现", "",
    ]
    if not job.get("findings"):
        lines.append("没有产生风险发现；该结论仅适用于本次已成功执行的静态分析器。")
    for finding in job.get("findings") or []:
        lines.extend([
            f"### [{finding.get('severity')}] {finding.get('title')}",
            f"- 类别：{finding.get('category')}",
            f"- 分析器：{finding.get('analyzer')}",
            f"- 位置：{json.dumps(finding.get('location'), ensure_ascii=False)}",
            f"- 证据：{finding.get('evidence') or 'N/A'}", "",
        ])
    sbom = job.get("sbom")
    if isinstance(sbom, dict):
        components = sbom.get("components") if isinstance(sbom.get("components"), list) else []
        properties = ((sbom.get("metadata") or {}).get("properties") or [])
        property_map = {
            item.get("name"): item.get("value")
            for item in properties if isinstance(item, dict)
        }
        lines.extend([
            "## 依赖清单（SBOM）", "",
            f"- 格式：{sbom.get('bomFormat', 'N/A')} {sbom.get('specVersion', '')}".rstrip(),
            f"- 已声明直接组件：{len(components)}",
            f"- 清单范围：{property_map.get('aegis:inventory-scope', 'N/A')}",
            f"- 是否执行传递依赖解析：{property_map.get('aegis:transitive-resolution-performed', 'false')}",
            f"- 声明安装集合的哈希完整性是否齐全：{property_map.get('aegis:declared-component-integrity-complete', 'false')}",
            f"- 传递依赖图完整性：{property_map.get('aegis:transitive-graph-completeness', 'not-proven')}", "",
        ])
    response = PlainTextResponse("\n".join(lines), media_type="text/markdown; charset=utf-8")
    response.headers["Content-Disposition"] = f'attachment; filename="scan-{job_id}.md"'
    return response


def start_dynamic_audit(
    admin_token: str | None, background: BackgroundTasks
) -> dict[str, Any]:
    verify_admin_token(admin_token)
    if not dynamic_fixture_is_ready():
        raise GatewayHTTPException(
            503,
            ErrorCode.DYNAMIC_AUDIT_NOT_READY,
            "内置动态验证样本集不可用。",
        )
    job = new_dynamic_audit_job()
    background.add_task(guarded_dynamic_audit_worker, job["id"])
    return job


def list_dynamic_audits(
    admin_token: str | None, limit: int = 20
) -> list[dict[str, Any]]:
    verify_admin_token(admin_token)
    limit = min(max(limit, 1), 100)
    with closing(connect_db()) as db:
        rows = db.execute(
            "SELECT payload_json FROM dynamic_audits ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        DynamicAuditJob.model_validate(json.loads(row["payload_json"])).model_dump(
            mode="json"
        )
        for row in rows
    ]


def get_dynamic_audit(
    admin_token: str | None, job_id: str
) -> dict[str, Any]:
    verify_admin_token(admin_token)
    job = load_dynamic_audit_job(job_id)
    if not job:
        raise GatewayHTTPException(
            404,
            ErrorCode.DYNAMIC_AUDIT_NOT_FOUND,
            "动态验证任务不存在。",
        )
    return job


API_V1_OPERATIONS = ApiV1Operations(
    health=lambda: health(),
    presets=lambda: presets(),
    start_preset=lambda preset_id, background: start_preset(preset_id, background),
    upload_skill=lambda background, file: upload_skill(background, file),
    upload_mcp=lambda background, mcp_json, requirements: upload_mcp(
        background, mcp_json, requirements
    ),
    upload_dependency=lambda background, requirements: upload_dependency(
        background, requirements
    ),
    list_scans=lambda limit: list_scans(limit),
    get_scan=lambda job_id: get_scan(job_id),
    export_scan=lambda job_id, format: export_scan(job_id, format),
    start_dynamic_audit=lambda admin_token, background: start_dynamic_audit(
        admin_token, background
    ),
    list_dynamic_audits=lambda admin_token, limit: list_dynamic_audits(
        admin_token, limit
    ),
    get_dynamic_audit=lambda admin_token, job_id: get_dynamic_audit(
        admin_token, job_id
    ),
)
install_api_v1(app, API_V1_OPERATIONS)


if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{path:path}")
    def frontend(path: str):
        candidate = (FRONTEND_DIST / path).resolve()
        if path and FRONTEND_DIST.resolve() in candidate.parents and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")

