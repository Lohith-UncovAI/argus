from typing import List

from argus_img.core.models import DetectorFinding


def deduplicate_findings(findings: List[DetectorFinding]) -> List[DetectorFinding]:
    seen = {}
    result = []
    for finding in findings:
        text_hash = finding.evidence.get("text_sha256")
        key = (
            finding.category,
            finding.type,
            tuple(sorted(finding.reason_codes)),
            text_hash or tuple(sorted(finding.observation_ids)),
        )
        if key in seen:
            existing = seen[key]
            existing.observation_ids = sorted(set(existing.observation_ids + finding.observation_ids))
            existing.source_artifact_ids = sorted(set(existing.source_artifact_ids + finding.source_artifact_ids))
            existing.detector_ids = sorted(set(existing.detector_ids + finding.detector_ids))
            continue
        seen[key] = finding
        result.append(finding)
    return result
