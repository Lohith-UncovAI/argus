from argus_img.core.enums import EpistemicState
from argus_img.core.models import ModuleStatus


def paddle_status() -> ModuleStatus:
    return ModuleStatus(name="paddleocr", status=EpistemicState.UNSUPPORTED, reason="tool_not_installed")

