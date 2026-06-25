import uuid
from pathlib import Path

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.config import AppConfig, config_hash
from argus_img.core.models import ScanContext, ScanRequest


def create_scan_context(store: ArtifactStore, request: ScanRequest, config: AppConfig) -> ScanContext:
    scan_id = "scan-" + uuid.uuid4().hex[:12]
    job_dir = store.create_job_dir(scan_id)
    return ScanContext(
        scan_id=scan_id,
        mode=request.mode,
        use_profile=request.use_profile,
        sanitize=request.sanitize,
        redact=request.redact,
        include_raw_text=request.include_raw_text,
        job_dir=str(job_dir),
        data_dir=str(Path(config.data_dir)),
        config_hash=config_hash(config),
    )

