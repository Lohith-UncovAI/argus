from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.config import load_config

router = APIRouter()


@router.get("/v1/artifacts/{artifact_id:path}")
def get_artifact(artifact_id: str):
    store = ArtifactStore(Path(load_config().data_dir))
    artifact = store.get_artifact(artifact_id, release_only=True)
    return FileResponse(store.resolve_path(artifact), media_type=artifact.media_type, filename=artifact.role)

