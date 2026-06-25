from typing import Dict, List

from argus_img.core.models import Artifact, DetectorFinding, FileDescriptor, Observation, ScanReport, ScannerInfo
from argus_img.evidence.assessment import build_assessments
from argus_img.evidence.graph import build_evidence_graph
from argus_img.policy.engine import PolicyEngine


def build_report(
    scan_id: str,
    scanner: ScannerInfo,
    file_descriptor: FileDescriptor,
    artifacts: Dict[str, Artifact],
    observations: List[Observation],
    findings: List[DetectorFinding],
    module_status: dict,
    limitations: list,
    errors: list,
    timings_ms: dict,
) -> ScanReport:
    assessments = build_assessments(findings)
    decision = PolicyEngine.load_for_profile(scanner.use_profile).decide(findings)
    return ScanReport(
        scan_id=scan_id,
        scanner=scanner,
        input=file_descriptor,
        decision=decision,
        assessments=assessments,
        findings=findings,
        artifacts=artifacts,
        observations=observations,
        module_status=module_status,
        limitations=limitations,
        errors=errors,
        timings_ms=timings_ms,
        evidence_graph=build_evidence_graph(artifacts, observations, findings),
    )

