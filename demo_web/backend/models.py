from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


SCHEMA_VERSION = "1.2"


class Severity(str, Enum):
    SAFE = "SAFE"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class DynamicAuditStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TargetKind(str, Enum):
    SKILL = "skill"
    MCP = "mcp"
    DEPENDENCY = "dependency"


class SourceKind(str, Enum):
    PRESET = "preset"
    UPLOAD = "upload"


class FindingLocation(BaseModel):
    model_config = ConfigDict(extra="allow")

    file: str | None = None
    line: int | None = None
    object: str | None = None
    type: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    category: str
    severity: Severity
    analyzer: str
    location: FindingLocation = Field(default_factory=FindingLocation)
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    rule_id: str | None = None


class ScanSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0


class PolicyTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = "unresolved"
    policy_version: str = "unresolved"
    rule_id: str = "PENDING_SCAN"
    reason: str = "扫描尚未完成，暂未执行准入策略。"
    matched_severities: list[Severity] = Field(default_factory=list)
    matched_finding_ids: list[str] = Field(default_factory=list)
    fail_closed: bool = True


class ScanJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    created_at: str
    updated_at: str
    status: ScanStatus
    target_kind: TargetKind
    source_kind: SourceKind
    display_name: str
    artifact_sha256: str | None = None
    decision: Decision = Decision.UNKNOWN
    policy_trace: PolicyTrace = Field(default_factory=PolicyTrace)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: list[Finding] = Field(default_factory=list)
    analyzers: list[str] = Field(default_factory=list)
    sbom: dict[str, Any] | None = None
    duration_ms: int | None = None
    error: str | None = None
    logs: list[str] = Field(default_factory=list)


class DynamicAuditSafetyBoundary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_trust: Literal["self_built_hash_locked_only"] = "self_built_hash_locked_only"
    accepts_user_code: Literal[False] = False
    accepts_user_paths: Literal[False] = False
    accepts_custom_commands: Literal[False] = False
    workspace_write_only: Literal[True] = True
    network_allowance: Literal["127.0.0.1_ephemeral_only", "none"] = "127.0.0.1_ephemeral_only"
    raw_values_retained: Literal[False] = False
    evidence_severity: Literal["INFO", "STATIC_FINDINGS_ONLY"] = "INFO"
    policy_effect: Literal["none"] = "none"
    decision_changes: Literal[0] = 0


class DynamicAuditJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    id: str
    created_at: str
    updated_at: str
    status: DynamicAuditStatus
    audit_type: Literal["mechanism_fixture", "skill_runtime_closure"] = "mechanism_fixture"
    fixture_set_id: Literal[
        "aegis-safe-dynamic-fixtures-v1",
        "aegis-skill-runtime-closure-v1",
    ] = "aegis-safe-dynamic-fixtures-v1"
    display_name: str = "内置可信动态验证样本集"
    fixture_set_sha256: str | None = None
    safety_boundary: DynamicAuditSafetyBoundary = Field(default_factory=DynamicAuditSafetyBoundary)
    metrics: dict[str, Any] | None = None
    fixture_results: list[dict[str, Any]] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)
    closure: dict[str, Any] | None = None
    duration_ms: int | None = None
    error_code: str | None = None
    error: str | None = None
