import shutil

from argus_img.core.enums import EpistemicState
from argus_img.core.models import ModuleStatus


def provenance_status() -> ModuleStatus:
    return ModuleStatus(
        name="c2pa",
        status=EpistemicState.NOT_TESTED if shutil.which("c2patool") else EpistemicState.UNSUPPORTED,
        reason=None if shutil.which("c2patool") else "tool_not_installed",
    )

