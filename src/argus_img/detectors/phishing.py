import re
from typing import List, Tuple

from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.models import DetectorFinding, TextObservation
from argus_img.reporting.excerpts import text_evidence


# Each entry: (indicator_name, phrases, co_occurrence_pairs)
# phrases: any single phrase match fires the indicator
# co_occurrence_pairs: list of (termA, termB) — BOTH must appear in the text
_INDICATOR_RULES: List[Tuple[str, List[str], List[Tuple[str, str]]]] = [
    ("password request", [
        "enter your password", "password required", "verify password",
        "verify your identity", "verify your account",
        "submit the token", "submit your token", "enter your token",
    ], []),
    ("credential harvesting", [
        "confirm your card", "card details", "card number", "cvv",
        "sign in to", "log in to", "open https://login", "open http://login",
        "submit the fake token",
    ], []),
    ("seed phrase request", [
        "seed phrase", "recovery phrase", "24-word", "12-word",
    ], []),
    ("payment request", [
        "payment required", "send payment", "wire transfer",
        "payment verification", "confirm payment", "complete the transaction",
        "scan qr to", "scan the code",
    ], []),
    ("urgent security warning", [
        "account suspended", "security alert", "suspicious activity detected",
        "click here to secure", "immediate action required",
    ], [
        ("urgent", "security"),
        ("urgent", "suspicious"),
    ]),
    ("fake software update", [
        "software update required", "install update now",
        "critical security update", "update now to protect",
    ], []),
    ("remote support request", [
        "remote support", "anydesk", "teamviewer",
        "remote assistance", "allow our support", "access your screen",
    ], []),
]


def _matches(lower: str, phrases: List[str], pairs: List[Tuple[str, str]]) -> bool:
    if any(p in lower for p in phrases):
        return True
    return any(a in lower and b in lower for a, b in pairs)


def analyze_phishing(
    texts: List[TextObservation], scan_id: str, include_raw_text: bool = False
) -> List[DetectorFinding]:
    findings: List[DetectorFinding] = []
    for obs in texts:
        lower = obs.normalized_text.lower()
        matched = [
            name for name, phrases, pairs in _INDICATOR_RULES
            if _matches(lower, phrases, pairs)
        ]
        if (
            ("login." in lower or "login/" in lower or "sign in" in lower or "log in" in lower)
            and any(term in lower for term in ("token", "password", "credential", "otp", "code"))
        ):
            matched.append("credential harvesting")
        matched = sorted(set(matched))
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
