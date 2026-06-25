from __future__ import annotations

from typing import Dict, List, Optional

from argus_img.core.enums import DetectorStatus, EpistemicState
from argus_img.core.models import CategoryAssessment, DetectorExecution, DetectorFinding
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
        return EpistemicState.NOT_TESTED
    return max((finding.state for finding in findings), key=lambda state: STATE_RANK[state])


def _execution_state(executions: List[DetectorExecution]) -> EpistemicState:
    if not executions:
        return EpistemicState.NOT_TESTED
    states = [execution.state for execution in executions]
    statuses = [execution.status for execution in executions]
    if any(status == DetectorStatus.TIMEOUT for status in statuses):
        return EpistemicState.ERROR
    if any(state == EpistemicState.ERROR for state in states):
        return EpistemicState.ERROR
    if all(state == EpistemicState.UNSUPPORTED for state in states):
        return EpistemicState.UNSUPPORTED
    if all(state == EpistemicState.NOT_TESTED for state in states):
        return EpistemicState.NOT_TESTED
    if any(state == EpistemicState.INCONCLUSIVE for state in states):
        return EpistemicState.INCONCLUSIVE
    if any(state == EpistemicState.NO_EVIDENCE_FOUND for state in states):
        return EpistemicState.NO_EVIDENCE_FOUND
    return max(states, key=lambda state: STATE_RANK[state])


def _max_impact(findings: List[DetectorFinding]) -> str:
    ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if not findings:
        return "low"
    return max((finding.impact for finding in findings), key=lambda impact: ranks.get(impact, 0))


def build_assessments(
    findings: List[DetectorFinding],
    executions: Optional[List[DetectorExecution]] = None,
) -> Dict[str, CategoryAssessment]:
    executions = executions or []
    assessments: Dict[str, CategoryAssessment] = {}
    for category in REQUIRED_CATEGORIES:
        category_findings = [finding for finding in findings if finding.category == category]
        category_executions = [execution for execution in executions if execution.category == category]
        state = _max_state(category_findings) if category_findings else _execution_state(category_executions)
        limitations = []
        coverage = "medium"
        if not category_executions and not category_findings:
            coverage = "not_tested"
            limitations.append("No detector execution was recorded for this category.")
        elif any(execution.state in {EpistemicState.ERROR, EpistemicState.UNSUPPORTED, EpistemicState.NOT_TESTED} for execution in category_executions):
            coverage = "partial"
            limitations.extend(
                "%s: %s" % (execution.detector_id, execution.state.value)
                for execution in category_executions
                if execution.state in {EpistemicState.ERROR, EpistemicState.UNSUPPORTED, EpistemicState.NOT_TESTED}
            )
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
            summary="%d finding(s)" % len(category_findings)
            if category_findings
            else (
                "No evidence found in executed checks."
                if state == EpistemicState.NO_EVIDENCE_FOUND
                else "Assessment limited by detector coverage: %s." % state.value
            ),
        )
    return assessments
