from __future__ import annotations

from enum import Enum
from typing import Any, Generic, Literal, TypeVar

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .models import TargetKind


API_VERSION = "v1"
DataT = TypeVar("DataT")


class ErrorCode(str, Enum):
    API_ROUTE_NOT_FOUND = "API_ROUTE_NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    HTTP_ERROR = "HTTP_ERROR"
    PRESET_NOT_FOUND = "PRESET_NOT_FOUND"
    SKILL_FILE_TYPE_INVALID = "SKILL_FILE_TYPE_INVALID"
    SKILL_ARCHIVE_INVALID = "SKILL_ARCHIVE_INVALID"
    MCP_FILE_TYPE_INVALID = "MCP_FILE_TYPE_INVALID"
    MCP_PAYLOAD_INVALID = "MCP_PAYLOAD_INVALID"
    UPLOAD_TOO_LARGE = "UPLOAD_TOO_LARGE"
    SCAN_NOT_FOUND = "SCAN_NOT_FOUND"
    ADMIN_TOKEN_NOT_CONFIGURED = "ADMIN_TOKEN_NOT_CONFIGURED"
    ADMIN_TOKEN_INVALID = "ADMIN_TOKEN_INVALID"
    DYNAMIC_AUDIT_NOT_READY = "DYNAMIC_AUDIT_NOT_READY"
    DYNAMIC_AUDIT_NOT_FOUND = "DYNAMIC_AUDIT_NOT_FOUND"
    DYNAMIC_AUDIT_BODY_NOT_ALLOWED = "DYNAMIC_AUDIT_BODY_NOT_ALLOWED"
    EXPORT_FORMAT_UNSUPPORTED = "EXPORT_FORMAT_UNSUPPORTED"
    REQUEST_VALIDATION_ERROR = "REQUEST_VALIDATION_ERROR"
    INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"


class ApiResponse(BaseModel, Generic[DataT]):
    model_config = ConfigDict(extra="forbid")

    api_version: Literal["v1"] = API_VERSION
    data: DataT


class ApiErrorDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: ErrorCode
    message: str
    details: Any | None = None


class ApiErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_version: Literal["v1"] = API_VERSION
    error: ApiErrorDetail


class EngineHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    ready: bool
    version: str
    analyzers: list[str] = Field(default_factory=list)


class PolicyHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ready: bool
    id: str
    version: str
    fail_closed: bool
    error: str | None = None


class HealthData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ready", "degraded"]
    mode: str
    policy: PolicyHealth
    engines: list[EngineHealth]
    privacy: str


class PresetData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: TargetKind
    name: str
    description: str
    tone: str


class GatewayHTTPException(HTTPException):
    def __init__(
        self,
        status_code: int,
        code: ErrorCode,
        message: str,
        *,
        details: Any | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message)
        self.code = code
        self.details = details


ERROR_RESPONSE_DOCS: dict[int, dict[str, Any]] = {
    400: {"model": ApiErrorResponse, "description": "请求内容或文件格式无效"},
    401: {"model": ApiErrorResponse, "description": "管理员身份验证失败"},
    404: {"model": ApiErrorResponse, "description": "指定资源不存在"},
    405: {"model": ApiErrorResponse, "description": "请求方法不受支持"},
    413: {"model": ApiErrorResponse, "description": "上传内容超过限制"},
    422: {"model": ApiErrorResponse, "description": "请求字段校验失败"},
    500: {"model": ApiErrorResponse, "description": "网关内部错误"},
    503: {"model": ApiErrorResponse, "description": "动态验证能力尚未安全配置"},
}


def v1_error_responses(*status_codes: int) -> dict[int, dict[str, Any]]:
    return {status: ERROR_RESPONSE_DOCS[status].copy() for status in status_codes}


def success_payload(data: Any) -> dict[str, Any]:
    return {"api_version": API_VERSION, "data": data}


def error_response(
    status_code: int,
    code: ErrorCode,
    message: str,
    *,
    details: Any | None = None,
) -> JSONResponse:
    payload = ApiErrorResponse(
        error=ApiErrorDetail(code=code, message=message, details=details)
    )
    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))
