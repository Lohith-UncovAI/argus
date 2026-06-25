from argus_img.core.enums import EpistemicState
from argus_img.core.models import ModuleStatus


def learned_steganalysis_status() -> ModuleStatus:
    return ModuleStatus(
        name="learned_steganalysis",
        status=EpistemicState.NOT_TESTED,
        reason="local steganalysis model not configured",
    )

