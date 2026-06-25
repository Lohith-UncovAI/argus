from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from argus_img.api.errors import argus_exception_handler, http_exception_handler, validation_exception_handler
from argus_img.api.routes import artifacts, attestation, capabilities, health, scans
from argus_img.core.exceptions import ArgusError


def create_app() -> FastAPI:
    app = FastAPI(title="ARGUS-IMG", version="0.1.0")
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
