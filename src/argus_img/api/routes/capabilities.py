import shutil
from pathlib import Path

from fastapi import APIRouter

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.config import load_config
from argus_img.core.enums import ScanMode, UseProfile
from argus_img.intake.format_policy import ALLOWED_RASTER_FORMATS

router = APIRouter()


@router.get("/v1/capabilities")
def capabilities():
    optional_tools = {
        "tesseract": bool(shutil.which("tesseract")),
        "exiftool": bool(shutil.which("exiftool")),
        "clamav": bool(shutil.which("clamscan")),
        "yara": bool(shutil.which("yara")),
        "binwalk": bool(shutil.which("binwalk")),
        "zsteg": bool(shutil.which("zsteg")),
        "c2pa": bool(shutil.which("c2patool")),
    }
    config = load_config()
    store = ArtifactStore(Path(config.data_dir))
    return {
        "formats": sorted(ALLOWED_RASTER_FORMATS),
        "modes": [mode.value for mode in ScanMode],
        "profiles": [profile.value for profile in UseProfile],
        "optional_tools": optional_tools,
        "storage": store.storage_status(config.storage.maximum_total_store_bytes),
        "runtime_network_dependency": False,
        "gpu_required": False,
    }
