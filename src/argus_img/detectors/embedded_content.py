import shutil

from argus_img.core.enums import EpistemicState
from argus_img.core.models import ModuleStatus


def embedded_tool_statuses():
    return {
        "binwalk": ModuleStatus(
            name="binwalk",
            status=EpistemicState.NOT_TESTED if shutil.which("binwalk") else EpistemicState.UNSUPPORTED,
            reason=None if shutil.which("binwalk") else "tool_not_installed",
        )
    }

