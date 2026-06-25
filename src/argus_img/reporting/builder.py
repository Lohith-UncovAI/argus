from typing import Dict, List, Optional

from argus_img.core.models import Artifact, DetectorExecution, DetectorFinding, FileDescriptor, Observation, ScanReport, ScannerInfo, TextObservation
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
    detector_executions: Optional[List[DetectorExecution]] = None,
    module_status: dict,
    limitations: list,
    errors: list,
    timings_ms: dict,
) -> ScanReport:
    detector_executions = detector_executions or []
    assessments = build_assessments(findings, detector_executions)
    decision = PolicyEngine.load_for_profile(scanner.use_profile).decide(findings)
    text_observations = [obs for obs in observations if isinstance(obs, TextObservation)]
    report = ScanReport(
        scan_id=scan_id,
        scanner=scanner,
        input=file_descriptor,
        decision=decision,
        assessments=assessments,
        findings=findings,
        artifacts=artifacts,
        observations=[observation.to_public() for observation in text_observations],
        detector_executions=detector_executions,
        module_status=module_status,
        limitations=limitations,
        errors=errors,
        timings_ms=timings_ms,
        evidence_graph=build_evidence_graph(artifacts, observations, findings),
    )
    report.internal_observations = observations
    return report
