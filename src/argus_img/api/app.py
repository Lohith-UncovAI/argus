from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from argus_img.api.errors import argus_exception_handler, http_exception_handler, validation_exception_handler
from argus_img.api.middleware import BodySizeLimitMiddleware, ConcurrencyLimitMiddleware
from argus_img.api.routes import artifacts, attestation, capabilities, health, scans
from argus_img.core.config import load_config
from argus_img.core.exceptions import ArgusError


def _run_startup_lifecycle(config) -> None:
    """Run storage lifecycle checks at startup."""
    from argus_img.artifacts.store import ArtifactStore
    try:
        store = ArtifactStore(Path(config.data_dir))
        # Integrity check, orphan recovery, expired job cleanup
        store.recover_orphans()
        store.cleanup_job_dirs(older_than_seconds=config.storage.job_directory_retention_seconds)
        store.garbage_collect(retention_seconds=config.storage.orphan_grace_period_seconds)
        # Per-category retention: expire old reports and revoke expired grants
        store.expire_old_reports(config.storage.report_retention_seconds)
        store.revoke_expired_grants(config.storage.released_artifact_retention_seconds)
        # Forensic evidence has its own independent retention period.
        store.cleanup_forensic_evidence(config.storage.forensic_evidence_retention_seconds)
        # Quota check: fail startup if already over quota
        store.enforce_storage_quota(config.storage.maximum_total_store_bytes)
    except ArgusError:
        raise
    except Exception:
        # Non-fatal at startup — log and continue
        pass


@asynccontextmanager
async def _lifespan(app: FastAPI):
    try:
        config = load_config()
        _run_startup_lifecycle(config)
    except Exception:
        pass
    yield


def create_app(max_body_bytes: int = 0) -> FastAPI:
    if max_body_bytes <= 0:
        try:
            max_body_bytes = load_config().limits.max_input_bytes
        except Exception:
            max_body_bytes = 25_000_000
    app = FastAPI(title="ARGUS-IMG", version="0.1.0", lifespan=_lifespan)
    try:
        max_concurrent = load_config().limits.max_concurrent_scans
    except Exception:
        max_concurrent = 4
    app.add_middleware(ConcurrencyLimitMiddleware, max_concurrent=max_concurrent)
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
