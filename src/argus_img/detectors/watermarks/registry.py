from argus_img.core.enums import EpistemicState
from argus_img.core.models import ModuleStatus


def watermark_registry_status() -> ModuleStatus:
    return ModuleStatus(
        name="registered_watermark_detectors",
        status=EpistemicState.UNSUPPORTED,
        reason="no invisible watermark plugins configured",
    )

