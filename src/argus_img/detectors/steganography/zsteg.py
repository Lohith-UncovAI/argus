import shutil

from argus_img.core.enums import EpistemicState
from argus_img.core.models import ModuleStatus


def zsteg_status() -> ModuleStatus:
    return ModuleStatus(
        name="zsteg",
        status=EpistemicState.NOT_TESTED if shutil.which("zsteg") else EpistemicState.UNSUPPORTED,
        reason=None if shutil.which("zsteg") else "tool_not_installed",
    )

