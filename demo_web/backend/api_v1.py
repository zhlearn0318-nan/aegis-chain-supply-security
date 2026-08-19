from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from fastapi import BackgroundTasks, FastAPI, File, Header, Query, Request, UploadFile
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api_contract import (
    ApiResponse,
    ErrorCode,
    GatewayHTTPException,
    HealthData,
    PresetData,
    error_response,
    success_payload,
    v1_error_responses,
)
from .models import DynamicAuditJob, ScanJob


LOGGER = logging.getLogger("aegis_chain.api.v1")


@dataclass
class ApiV1Operations:
    health: Callable[..., Any]
    presets: Callable[..., Any]
    start_preset: Callable[..., Any]
    upload_skill: Callable[..., Any]
    upload_mcp: Callable[..., Any]
    upload_dependency: Callable[..., Any]
    list_scans: Callable[..., Any]
    get_scan: Callable[..., Any]
    export_scan: Callable[..., Any]
    start_dynamic_audit: Callable[..., Any]
    list_dynamic_audits: Callable[..., Any]
    get_dynamic_audit: Callable[..., Any]


def is_v1_request(request: Request) -> bool:
    return request.url.path == "/api/v1" or request.url.path.startswith("/api/v1/")


def install_api_v1(app: FastAPI, operations: ApiV1Operations) -> None:
    async def gateway_http_exception_handler(
        request: Request, exc: GatewayHTTPException
    ):
        if is_v1_request(request):
            return error_response(
                exc.status_code,
                exc.code,
                str(exc.detail),
                details=exc.details,
            )
        return await http_exception_handler(request, exc)

    async def gateway_validation_exception_handler(
        request: Request, exc: RequestValidationError
    ):
        if not is_v1_request(request):
            return await request_validation_exception_handler(request, exc)
        details = [
            {
                "location": list(error.get("loc") or []),
                "message": error.get("msg") or "Invalid request field",
                "type": error.get("type") or "validation_error",
            }
            for error in exc.errors()
        ]
        return error_response(
            422,
            ErrorCode.REQUEST_VALIDATION_ERROR,
            "请求字段校验失败。",
            details=details,
        )

    async def gateway_starlette_http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ):
        if not is_v1_request(request):
            return await http_exception_handler(request, exc)
        if exc.status_code == 404:
            code = ErrorCode.API_ROUTE_NOT_FOUND
            message = "API v1 路径不存在。"
        elif exc.status_code == 405:
            code = ErrorCode.METHOD_NOT_ALLOWED
            message = "该 API v1 路径不支持当前请求方法。"
        else:
            code = ErrorCode.HTTP_ERROR
            message = str(exc.detail)
        return error_response(exc.status_code, code, message)

    async def v1_internal_error_boundary(request: Request, call_next):
        try:
            return await call_next(request)
        except Exception:
            if not is_v1_request(request):
                raise
            LOGGER.exception("Unhandled API v1 error: %s", request.url.path)
            return error_response(
                500,
                ErrorCode.INTERNAL_SERVER_ERROR,
                "网关内部错误，未产生可用的扫描结论。",
            )

    app.add_exception_handler(GatewayHTTPException, gateway_http_exception_handler)
    app.add_exception_handler(RequestValidationError, gateway_validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, gateway_starlette_http_exception_handler)
    app.middleware("http")(v1_internal_error_boundary)

    @app.get(
        "/api/v1/health",
        response_model=ApiResponse[HealthData],
        response_model_exclude_none=True,
        responses=v1_error_responses(500),
    )
    def health_v1() -> dict[str, Any]:
        return success_payload(operations.health())

    @app.get(
        "/api/v1/presets",
        response_model=ApiResponse[list[PresetData]],
        responses=v1_error_responses(500),
    )
    def presets_v1() -> dict[str, Any]:
        return success_payload(operations.presets())

    @app.post(
        "/api/v1/scans/preset/{preset_id}",
        status_code=202,
        response_model=ApiResponse[ScanJob],
        responses=v1_error_responses(404, 422, 500),
    )
    def start_preset_v1(
        preset_id: str, background: BackgroundTasks
    ) -> dict[str, Any]:
        return success_payload(operations.start_preset(preset_id, background))

    @app.post(
        "/api/v1/scans/skill",
        status_code=202,
        response_model=ApiResponse[ScanJob],
        responses=v1_error_responses(400, 413, 422, 500),
    )
    async def upload_skill_v1(
        background: BackgroundTasks, file: UploadFile = File(...)
    ) -> dict[str, Any]:
        return success_payload(await operations.upload_skill(background, file))

    @app.post(
        "/api/v1/scans/mcp",
        status_code=202,
        response_model=ApiResponse[ScanJob],
        responses=v1_error_responses(400, 413, 422, 500),
    )
    async def upload_mcp_v1(
        background: BackgroundTasks,
        mcp_json: UploadFile = File(...),
        requirements: UploadFile | None = File(None),
    ) -> dict[str, Any]:
        return success_payload(
            await operations.upload_mcp(background, mcp_json, requirements)
        )

    @app.post(
        "/api/v1/scans/dependency",
        status_code=202,
        response_model=ApiResponse[ScanJob],
        responses=v1_error_responses(413, 422, 500),
    )
    async def upload_dependency_v1(
        background: BackgroundTasks, requirements: UploadFile = File(...)
    ) -> dict[str, Any]:
        return success_payload(
            await operations.upload_dependency(background, requirements)
        )

    @app.get(
        "/api/v1/scans",
        response_model=ApiResponse[list[ScanJob]],
        responses=v1_error_responses(422, 500),
    )
    def list_scans_v1(limit: int = Query(20, ge=1, le=100)) -> dict[str, Any]:
        return success_payload(operations.list_scans(limit))

    @app.get(
        "/api/v1/scans/{job_id}/export",
        response_model=None,
        responses=v1_error_responses(400, 404, 422, 500),
    )
    def export_scan_v1(job_id: str, format: str = "json"):
        return operations.export_scan(job_id, format)

    @app.get(
        "/api/v1/scans/{job_id}",
        response_model=ApiResponse[ScanJob],
        responses=v1_error_responses(404, 422, 500),
    )
    def get_scan_v1(job_id: str) -> dict[str, Any]:
        return success_payload(operations.get_scan(job_id))

    @app.post(
        "/api/v1/admin/dynamic-audits",
        status_code=202,
        response_model=ApiResponse[DynamicAuditJob],
        responses=v1_error_responses(400, 401, 503, 500),
    )
    async def start_dynamic_audit_v1(
        request: Request,
        background: BackgroundTasks,
        admin_token: str | None = Header(None, alias="X-Aegis-Admin-Token"),
    ) -> dict[str, Any]:
        if await request.body():
            raise GatewayHTTPException(
                400,
                ErrorCode.DYNAMIC_AUDIT_BODY_NOT_ALLOWED,
                "该接口只运行固定内置样本，不接受请求体或自定义执行参数。",
            )
        return success_payload(operations.start_dynamic_audit(admin_token, background))

    @app.get(
        "/api/v1/admin/dynamic-audits",
        response_model=ApiResponse[list[DynamicAuditJob]],
        responses=v1_error_responses(401, 422, 503, 500),
    )
    def list_dynamic_audits_v1(
        limit: int = Query(20, ge=1, le=100),
        admin_token: str | None = Header(None, alias="X-Aegis-Admin-Token"),
    ) -> dict[str, Any]:
        return success_payload(operations.list_dynamic_audits(admin_token, limit))

    @app.get(
        "/api/v1/admin/dynamic-audits/{job_id}",
        response_model=ApiResponse[DynamicAuditJob],
        responses=v1_error_responses(401, 404, 503, 500),
    )
    def get_dynamic_audit_v1(
        job_id: str,
        admin_token: str | None = Header(None, alias="X-Aegis-Admin-Token"),
    ) -> dict[str, Any]:
        return success_payload(operations.get_dynamic_audit(admin_token, job_id))

    @app.api_route(
        "/api/v1/{path:path}", methods=["GET", "POST"], include_in_schema=False
    )
    def unknown_v1_route(path: str) -> None:
        raise GatewayHTTPException(
            404,
            ErrorCode.API_ROUTE_NOT_FOUND,
            "API v1 路径不存在。",
            details={"path": f"/api/v1/{path}"},
        )

    @app.api_route(
        "/api/{path:path}", methods=["GET", "POST"], include_in_schema=False
    )
    def unknown_legacy_api_route(path: str) -> None:
        raise GatewayHTTPException(
            404,
            ErrorCode.API_ROUTE_NOT_FOUND,
            "API 路径不存在。",
            details={"path": f"/api/{path}"},
        )
