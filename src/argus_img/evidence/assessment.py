from __future__ import annotations

from typing import Dict, List

from argus_img.core.enums import EpistemicState
from argus_img.core.models import CategoryAssessment, DetectorFinding
from argus_img.evidence.calibration import STATE_RANK

REQUIRED_CATEGORIES = [
    "file_security",
    "malware",
    "embedded_payload",
    "prompt_injection",
    "covert_channel",
    "steganography",
    "watermarks",
    "provenance",
    "phishing",
    "privacy",
    "redaction_failure",
    "adversarial_instability",
    "authenticity_indicators",
]


def _max_state(findings: List[DetectorFinding]) -> EpistemicState:
    if not findings:
        return EpistemicState.NO_EVIDENCE_FOUND
    return max((finding.state for finding in findings), key=lambda state: STATE_RANK[state])


def _max_impact(findings: List[DetectorFinding]) -> str:
    ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if not findings:
        return "low"
    return max((finding.impact for finding in findings), key=lambda impact: ranks.get(impact, 0))


def build_assessments(findings: List[DetectorFinding]) -> Dict[str, CategoryAssessment]:
    assessments: Dict[str, CategoryAssessment] = {}
    for category in REQUIRED_CATEGORIES:
        category_findings = [finding for finding in findings if finding.category == category]
        state = _max_state(category_findings)
        limitations = []
        coverage = "medium"
        if category in {"steganography", "covert_channel"}:
            limitations.append("Arbitrary encrypted steganography cannot be excluded.")
            coverage = "low" if not category_findings else "medium"
        if category == "watermarks":
            limitations.append("Unknown watermark schemes are unsupported.")
            coverage = "low"
        if category == "adversarial_instability":
            limitations.append("Model-specific adversarial perturbations were not fully tested.")
            coverage = "not_tested"
        assessments[category] = CategoryAssessment(
            state=state,
            likelihood=max((finding.attack_likelihood or 0.0 for finding in category_findings), default=None),
            impact=_max_impact(category_findings),
            coverage=coverage,
            finding_ids=[finding.finding_id for finding in category_findings],
            limitations=limitations,
            summary="%d finding(s)" % len(category_findings) if category_findings else "No evidence found in implemented checks.",
        )
    return assessments

