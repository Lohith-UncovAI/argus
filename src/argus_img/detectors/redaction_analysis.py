from argus_img.core.enums import EpistemicState
from argus_img.core.models import ModuleStatus


def redaction_analysis_status() -> ModuleStatus:
    return ModuleStatus(
        name="redaction_analysis",
        status=EpistemicState.NOT_TESTED,
        reason="baseline does not recover blurred or pixelated redactions",
    )

