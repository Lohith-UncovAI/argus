from pathlib import Path

from fastapi import APIRouter

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.config import load_config

router = APIRouter()


@router.get("/v1/health")
def health():
    config = load_config()
    store = ArtifactStore(Path(config.data_dir))
    storage = store.storage_status(config.storage.maximum_total_store_bytes)
    return {
        "status": "degraded" if storage["over_quota"] else "ok",
        "offline_mode": True,
        "gpu_required": False,
        "storage": storage,
    }
