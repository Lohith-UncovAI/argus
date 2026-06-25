import shutil

from fastapi import APIRouter

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
    return {
        "formats": sorted(ALLOWED_RASTER_FORMATS),
        "modes": [mode.value for mode in ScanMode],
        "profiles": [profile.value for profile in UseProfile],
        "optional_tools": optional_tools,
        "runtime_network_dependency": False,
        "gpu_required": False,
    }

