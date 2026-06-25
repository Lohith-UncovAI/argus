from typing import List

from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.models import DetectorFinding, TextObservation
from argus_img.reporting.excerpts import text_evidence


INDICATORS = {
    "password request": ["enter your password", "password required", "verify password"],
    "seed phrase request": ["seed phrase", "recovery phrase"],
    "payment request": ["payment required", "send payment", "wire transfer"],
    "urgent security warning": ["urgent", "account suspended", "security alert"],
    "fake software update": ["software update required", "install update now"],
    "remote support request": ["remote support", "anydesk", "teamviewer"],
}


def analyze_phishing(texts: List[TextObservation], scan_id: str, include_raw_text: bool = False) -> List[DetectorFinding]:
    findings: List[DetectorFinding] = []
    for obs in texts:
        lower = obs.normalized_text.lower()
        matched = [name for name, terms in INDICATORS.items() if any(term in lower for term in terms)]
        if not matched:
            continue
        findings.append(
            DetectorFinding(
                finding_id="finding:%s:phishing:%03d" % (scan_id, len(findings)),
                category="phishing",
                type="deceptive_interface_indicator",
                state=EpistemicState.POSSIBLE,
                severity="medium",
                evidence_quality=0.5,
                attack_likelihood=0.5,
                impact="high",
                source_artifact_ids=[obs.source_artifact_id],
                observation_ids=[obs.observation_id],
                detector_ids=["detector:phishing-rules"],
                reason_codes=["PHISHING_INDICATOR"],
                recommended_action=PolicyAction.REVIEW,
                evidence={**text_evidence(obs.normalized_text, include_raw_text), "indicators": matched},
            )
        )
    return findings

