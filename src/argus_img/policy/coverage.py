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

MANDATORY_OK_STATUSES = {DetectorStatus.SUCCESS, DetectorStatus.NO_EVIDENCE}
MANDATORY_OK_STATES = {EpistemicState.CONFIRMED, EpistemicState.NO_EVIDENCE_FOUND}

# Detectors that must be executed but are permitted to return UNSUPPORTED
# (i.e., the tool is not yet fully implemented).  They still must appear in
# the execution list; "missing" is still a hard failure.
PERMITTED_UNSUPPORTED_STATUSES = {DetectorStatus.UNSUPPORTED, DetectorStatus.TOOL_NOT_INSTALLED}
PERMITTED_UNSUPPORTED_STATES = {EpistemicState.UNSUPPORTED, EpistemicState.NOT_TESTED}


def _execution_ok(execution: DetectorExecution, allow_unsupported: bool) -> bool:
    if execution.status in MANDATORY_OK_STATUSES and execution.state in MANDATORY_OK_STATES:
        return True
    if allow_unsupported:
        return (
            execution.status in PERMITTED_UNSUPPORTED_STATUSES
            and execution.state in PERMITTED_UNSUPPORTED_STATES
        )
    return False


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
        allow_unsupported = getattr(entry, "allow_unsupported", False)
        if not _execution_ok(execution, allow_unsupported):
            failures.append("%s:%s/%s" % (entry.id, execution.status.value, execution.state.value))
    if representation_manifest is not None and not representation_manifest.coverage_complete:
        failures.extend("representation:%s:missing" % item for item in representation_manifest.missing_required)
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
