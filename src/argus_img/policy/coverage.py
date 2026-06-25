from __future__ import annotations

from typing import List, Optional

from argus_img.core.detector_registry import DetectorRegistry
from argus_img.core.enums import DetectorStatus, EpistemicState, PolicyAction, UseProfile
from argus_img.core.models import DetectorExecution, PolicyDecision, RepresentationManifest


STRICT_PROFILES = {
    UseProfile.AGENT_WITH_TOOLS,
    UseProfile.OCR_EXTRACTION,
    UseProfile.PUBLIC_REPUBLISHING,
    UseProfile.SECURITY_FORENSICS,
}

# Only a completed real execution satisfies mandatory coverage.
MANDATORY_OK_STATUSES = {DetectorStatus.SUCCESS, DetectorStatus.NO_EVIDENCE, DetectorStatus.DETECTED}
MANDATORY_OK_STATES = {EpistemicState.CONFIRMED, EpistemicState.NO_EVIDENCE_FOUND}

# All other statuses indicate incomplete coverage and must block release.
INCOMPLETE_STATUSES = {
    DetectorStatus.UNSUPPORTED,
    DetectorStatus.TOOL_NOT_INSTALLED,
    DetectorStatus.NOT_TESTED,
    DetectorStatus.ERROR,
    DetectorStatus.TIMEOUT,
    DetectorStatus.RESOURCE_LIMIT,
    DetectorStatus.MISSING,
    DetectorStatus.CANCELLED,
}


def _execution_ok(execution: DetectorExecution) -> bool:
    """Return True only if the execution represents a real completed scan."""
    return (
        execution.status in MANDATORY_OK_STATUSES
        and execution.state in MANDATORY_OK_STATES
    )


def mandatory_coverage_decision(
    profile: UseProfile,
    registry: DetectorRegistry,
    executions: List[DetectorExecution],
    representation_manifest: Optional[RepresentationManifest] = None,
) -> Optional[PolicyDecision]:
    if profile not in STRICT_PROFILES:
        return None
    by_id = {execution.detector_id: execution for execution in executions}
    failures = []
    for entry in registry.required_for_profile(profile):
        execution = by_id.get(entry.id)
        if execution is None:
            failures.append("%s:missing" % entry.id)
            continue
        if not _execution_ok(execution):
            failures.append(
                "%s:%s/%s" % (entry.id, execution.status.value, execution.state.value)
            )
    if representation_manifest is not None and not representation_manifest.coverage_complete:
        failures.extend(
            "representation:%s:missing" % item
            for item in representation_manifest.missing_required
        )
    if not failures:
        return None
    return PolicyDecision(
        action=PolicyAction.UNSUPPORTED,
        safe_claim=False,
        reason_codes=["MANDATORY_ANALYSIS_NOT_RUN"],
        triggered_policy_rules=["mandatory-detector-coverage"],
        winning_rule_id="mandatory-detector-coverage",
        winning_rule_priority=20000,
        summary="Mandatory detector coverage did not complete for the selected profile.",
        explanation="; ".join(failures),
    )
