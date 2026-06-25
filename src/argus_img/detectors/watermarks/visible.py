from typing import List

from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.models import DetectorFinding, TextObservation


def analyze_visible_watermarks(texts: List[TextObservation], scan_id: str) -> List[DetectorFinding]:
    findings: List[DetectorFinding] = []
    indicators = ["watermark", "stock", "shutterstock", "alamy", "getty images", "sample"]
    for obs in texts:
        lower = obs.normalized_text.lower()
        matched = [term for term in indicators if term in lower]
        if not matched:
            continue
        findings.append(
            DetectorFinding(
                finding_id="finding:%s:watermark:%03d" % (scan_id, len(findings)),
                category="watermarks",
                type="visible_watermark_indicator",
                state=EpistemicState.POSSIBLE,
                severity="low",
                evidence_quality=0.4,
                impact="low",
                source_artifact_ids=[obs.source_artifact_id],
                observation_ids=[obs.observation_id],
                detector_ids=["detector:visible-watermark"],
                reason_codes=["VISIBLE_WATERMARK_INDICATOR"],
                recommended_action=PolicyAction.REVIEW,
                evidence={"indicators": matched},
            )
        )
    return findings

