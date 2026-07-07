import shutil

from argus_img.core.enums import EpistemicState
from argus_img.core.models import ModuleStatus


def zsteg_status() -> ModuleStatus:
    path = shutil.which("zsteg")
    return ModuleStatus(
        name="zsteg",
        status=EpistemicState.CONFIRMED if path else EpistemicState.UNSUPPORTED,
        reason=path or "tool_not_installed",
    )
