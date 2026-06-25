from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from argus_img.core.exceptions import (
    ArtifactAccessDenied,
    ArtifactNotReleased,
    ArgusError,
    ConfigurationError,
    IntakeRejected,
    ResourceLimitExceeded,
)


def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": code, "message": message}})


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return error_response(422, "invalid_request", "request validation failed")


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {
        404: "not_found",
        413: "payload_too_large",
        422: "invalid_request",
    }.get(exc.status_code, "http_error")
    detail = exc.detail if isinstance(exc.detail, str) else code
    return error_response(exc.status_code, code, detail)


async def argus_exception_handler(request: Request, exc: ArgusError) -> JSONResponse:
    if isinstance(exc, ArtifactNotReleased):
        return error_response(403, "artifact_not_released", "artifact is not released")
    if isinstance(exc, ArtifactAccessDenied):
        return error_response(404, "not_found", "resource not found")
    if isinstance(exc, ResourceLimitExceeded):
        return error_response(413, "resource_limit_exceeded", str(exc))
    if isinstance(exc, IntakeRejected):
        message = str(exc)
        if "exceed" in message or "too large" in message or "maximum byte" in message:
            return error_response(413, "payload_too_large", message)
        return error_response(400, "intake_rejected", message)
    if isinstance(exc, ConfigurationError):
        return error_response(500, "configuration_error", "invalid server configuration")
    return error_response(400, "argus_error", str(exc))


def to_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ArtifactAccessDenied):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ArgusError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="internal error")
