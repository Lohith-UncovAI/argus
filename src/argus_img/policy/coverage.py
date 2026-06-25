from __future__ import annotations

from typing import List, Optional

from argus_img.core.detector_registry import DetectorRegistry
from argus_img.core.enums import DetectorStatus, EpistemicState, PolicyAction, UseProfile
from argus_img.core.models import DetectorExecution, DetectorFinding, PolicyDecision, RepresentationManifest


STRICT_PROFILES = {
    UseProfile.AGENT_WITH_TOOLS,
    UseProfile.OCR_EXTRACTION,
    UseProfile.PUBLIC_REPUBLISHING,
    UseProfile.SECURITY_FORENSICS,
    UseProfile.RAG_INGESTION,
    UseProfile.VLM_READ_ONLY,
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


def detected_without_finding(
    executions: List[DetectorExecution],
    findings: List[DetectorFinding],
) -> List[str]:
    """Return detector IDs that have DETECTED status but no associated finding.

    Any such case must fail closed — a detection without evidence in the policy
    layer is an invariant violation.
    """
    finding_detector_ids: set[str] = set()
    for f in findings:
        finding_detector_ids.update(f.detector_ids)
    orphans = []
    for ex in executions:
        if ex.status == DetectorStatus.DETECTED and ex.detector_id not in finding_detector_ids:
            orphans.append(ex.detector_id)
    return orphans


def mandatory_coverage_decision(
    profile: UseProfile,
    registry: DetectorRegistry,
    executions: List[DetectorExecution],
    representation_manifest: Optional[RepresentationManifest] = None,
    findings: Optional[List[DetectorFinding]] = None,
) -> Optional[PolicyDecision]:
    # VLM_READ_ONLY always returns UNSUPPORTED — no real visual analyzer exists.
    if profile == UseProfile.VLM_READ_ONLY:
        return PolicyDecision(
            action=PolicyAction.UNSUPPORTED,
            safe_claim=False,
            reason_codes=["VLM_ANALYZER_NOT_AVAILABLE"],
            triggered_policy_rules=["vlm-read-only-unsupported"],
            winning_rule_id="vlm-read-only-unsupported",
            winning_rule_priority=25000,
            summary="VLM_READ_ONLY requires a real visual analyzer which is not installed.",
            explanation="VLM_READ_ONLY profile always returns UNSUPPORTED until a real visual analyzer exists.",
        )

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

    # Detection-to-policy invariant: every DETECTED execution must have a finding.
    orphan_detectors = detected_without_finding(executions, findings or [])
    for detector_id in orphan_detectors:
        failures.append("%s:DETECTED_WITHOUT_FINDING" % detector_id)

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


def detected_without_finding_decision(
    executions: List[DetectorExecution],
    findings: List[DetectorFinding],
) -> Optional[PolicyDecision]:
    """Fail-closed check for ALL profiles: any DETECTED without a finding blocks release."""
    orphans = detected_without_finding(executions, findings)
    if not orphans:
        return None
    return PolicyDecision(
        action=PolicyAction.BLOCK,
        safe_claim=False,
        reason_codes=["DETECTED_WITHOUT_FINDING"],
        triggered_policy_rules=["detected-without-finding"],
        winning_rule_id="detected-without-finding",
        winning_rule_priority=19000,
        summary="A detector reported DETECTED but produced no policy-visible finding.",
        explanation="; ".join("%s:DETECTED_WITHOUT_FINDING" % d for d in orphans),
    )
