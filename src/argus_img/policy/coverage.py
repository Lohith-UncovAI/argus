from __future__ import annotations

from typing import List, Optional

from argus_img.core.detector_registry import DetectorRegistry
from argus_img.core.enums import DetectorStatus, EpistemicState, PolicyAction, UseProfile
from argus_img.core.models import DetectorExecution, PolicyDecision


STRICT_PROFILES = {UseProfile.AGENT_WITH_TOOLS, UseProfile.SECURITY_FORENSICS}
MANDATORY_OK_STATUSES = {DetectorStatus.SUCCESS, DetectorStatus.NO_EVIDENCE}
MANDATORY_OK_STATES = {EpistemicState.CONFIRMED, EpistemicState.NO_EVIDENCE_FOUND}


def mandatory_coverage_decision(
    profile: UseProfile,
    registry: DetectorRegistry,
    executions: List[DetectorExecution],
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
        if execution.status not in MANDATORY_OK_STATUSES or execution.state not in MANDATORY_OK_STATES:
            failures.append("%s:%s/%s" % (entry.id, execution.status.value, execution.state.value))
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
