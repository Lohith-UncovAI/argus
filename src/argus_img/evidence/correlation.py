from typing import Dict, List

from argus_img.core.models import DetectorFinding


def group_by_evidence_family(findings: List[DetectorFinding]) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    for finding in findings:
        family = finding.detector_ids[0].split(":")[-1].split("-")[0] if finding.detector_ids else "unknown"
        groups.setdefault(family, []).append(finding.finding_id)
    return groups

