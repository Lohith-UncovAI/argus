from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from argus_img.api.errors import argus_exception_handler, http_exception_handler, validation_exception_handler
from argus_img.api.middleware import BodySizeLimitMiddleware
from argus_img.api.routes import artifacts, attestation, capabilities, health, scans
from argus_img.core.config import load_config
from argus_img.core.exceptions import ArgusError


def create_app(max_body_bytes: int = 0) -> FastAPI:
    if max_body_bytes <= 0:
        try:
            max_body_bytes = load_config().limits.max_input_bytes
        except Exception:
            max_body_bytes = 25_000_000
    app = FastAPI(title="ARGUS-IMG", version="0.1.0")
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_body_bytes)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(ArgusError, argus_exception_handler)
    app.include_router(health.router)
    app.include_router(capabilities.router)
    app.include_router(attestation.router)
    app.include_router(scans.router)
    app.include_router(artifacts.router)
    return app


app = create_app()
