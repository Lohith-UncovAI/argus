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
    category: Optional[str] = None,
    required: bool = False,
    started_at: Optional[datetime] = None,
) -> DetectorReport:
    now = datetime.now(timezone.utc)
    manifest = DetectorManifest(detector_id=detector_id, name=detector_id, family=family, optional=optional)
    execution = DetectorExecution(
        detector_id=detector_id,
        status=status,
        state=state,
        family=family,
        category=category,
        required=required,
        started_at=started_at or now,
        completed_at=now,
        reason=reason,
    )
    return DetectorReport(
        manifest=manifest,
        execution=execution,
        findings=findings or [],
        observations=observations or [],
        limitations=[reason] if reason else [],
    )
