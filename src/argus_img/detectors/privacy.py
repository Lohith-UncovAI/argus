import re
from typing import List

from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.models import DetectorFinding, TextObservation
from argus_img.reporting.excerpts import text_evidence

EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE = re.compile(r"\b(?:\+?\d[\d .()-]{7,}\d)\b")
API_KEY = re.compile(r"(?i)\b(?:api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_\-]{12,}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
CARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _luhn(candidate: str) -> bool:
    digits = [int(ch) for ch in candidate if ch.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def analyze_privacy(texts: List[TextObservation], scan_id: str, include_raw_text: bool = False) -> List[DetectorFinding]:
    findings: List[DetectorFinding] = []
    checks = [
        ("email_address", EMAIL, "EMAIL_ADDRESS"),
        ("telephone_number", PHONE, "TELEPHONE_NUMBER"),
        ("api_key_like_string", API_KEY, "API_KEY_LIKE_STRING"),
        ("private_key_header", PRIVATE_KEY, "PRIVATE_KEY_HEADER"),
    ]
    for obs in texts:
        text = obs.normalized_text
        for finding_type, pattern, code in checks:
            if not pattern.search(text):
                continue
            findings.append(
                DetectorFinding(
                    finding_id="finding:%s:privacy:%03d" % (scan_id, len(findings)),
                    category="privacy",
                    type=finding_type,
                    state=EpistemicState.CONFIRMED,
                    severity="high" if "key" in finding_type else "medium",
                    evidence_quality=0.8,
                    impact="high",
                    source_artifact_ids=[obs.source_artifact_id],
                    observation_ids=[obs.observation_id],
                    detector_ids=["detector:privacy-rules"],
                    reason_codes=[code],
                    recommended_action=PolicyAction.ALLOW_WITH_REDACTION,
                    evidence=text_evidence(text, include_raw_text=False),
                )
            )
        for match in CARD.findall(text):
            if _luhn(match):
                findings.append(
                    DetectorFinding(
                        finding_id="finding:%s:privacy:%03d" % (scan_id, len(findings)),
                        category="privacy",
                        type="payment_card_like_number",
                        state=EpistemicState.CONFIRMED,
                        severity="high",
                        evidence_quality=0.85,
                        impact="high",
                        source_artifact_ids=[obs.source_artifact_id],
                        observation_ids=[obs.observation_id],
                        detector_ids=["detector:privacy-rules"],
                        reason_codes=["PAYMENT_CARD_LIKE_NUMBER"],
                        recommended_action=PolicyAction.ALLOW_WITH_REDACTION,
                        evidence=text_evidence(match, include_raw_text=False),
                    )
                )
    return findings

