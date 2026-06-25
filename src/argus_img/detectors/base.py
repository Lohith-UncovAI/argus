from datetime import datetime, timezone
from typing import List, Optional

from argus_img.core.enums import DetectorStatus, EpistemicState
from argus_img.core.models import (
    DetectorExecution,
    DetectorFinding,
    DetectorManifest,
    DetectorReport,
    Observation,
)


def detector_report(
    detector_id: str,
    family: str,
    status: DetectorStatus,
    state: EpistemicState,
    findings: Optional[List[DetectorFinding]] = None,
    observations: Optional[List[Observation]] = None,
    reason: Optional[str] = None,
    optional: bool = False,
) -> DetectorReport:
    manifest = DetectorManifest(detector_id=detector_id, name=detector_id, family=family, optional=optional)
    execution = DetectorExecution(
        detector_id=detector_id,
        status=status,
        state=state,
        completed_at=datetime.now(timezone.utc),
        reason=reason,
    )
    return DetectorReport(
        manifest=manifest,
        execution=execution,
        findings=findings or [],
        observations=observations or [],
        limitations=[reason] if reason else [],
    )

