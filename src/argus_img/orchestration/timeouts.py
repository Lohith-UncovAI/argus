from argus_img.core.limits import Limits


def detector_timeout(limits: Limits) -> int:
    return limits.detector_timeout_seconds

