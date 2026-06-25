from argus_img.core.enums import EpistemicState
from argus_img.core.models import ModuleStatus


def baseline_stability_status() -> ModuleStatus:
    return ModuleStatus(
        name="adversarial_stability",
        status=EpistemicState.NOT_TESTED,
        reason="model-specific adversarial stability testing is not implemented in baseline",
    )

