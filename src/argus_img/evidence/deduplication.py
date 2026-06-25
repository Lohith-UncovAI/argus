from typing import List

from argus_img.core.models import DetectorFinding
from argus_img.evidence.calibration import STATE_RANK


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _strength(finding: DetectorFinding) -> tuple:
    return (
        STATE_RANK[finding.state],
        SEVERITY_RANK.get(finding.severity, 0),
        finding.evidence_quality or 0.0,
        finding.attack_likelihood or 0.0,
    )


def _merge_support(target: DetectorFinding, source: DetectorFinding) -> None:
    target.observation_ids = sorted(set(target.observation_ids + source.observation_ids))
    target.source_artifact_ids = sorted(set(target.source_artifact_ids + source.source_artifact_ids))
    target.detector_ids = sorted(set(target.detector_ids + source.detector_ids))
    target.reason_codes = sorted(set(target.reason_codes + source.reason_codes))
    target.limitations = sorted(set(target.limitations + source.limitations))
    existing_transformations = set(target.evidence.get("transformations", []))
    existing_transformations.update(source.evidence.get("transformations", []))
    if existing_transformations:
        target.evidence["transformations"] = sorted(existing_transformations)


def deduplicate_findings(findings: List[DetectorFinding]) -> List[DetectorFinding]:
    seen = {}
    result = []
    for finding in findings:
        text_hash = finding.evidence.get("text_sha256")
        support_key = "prompt-class" if finding.category == "prompt_injection" else text_hash
        key = (
            finding.category,
            finding.type,
            tuple(sorted(finding.reason_codes)),
            support_key or tuple(sorted(finding.observation_ids)),
        )
        if key in seen:
            existing = seen[key]
            if _strength(finding) > _strength(existing):
                _merge_support(finding, existing)
                index = result.index(existing)
                result[index] = finding
                seen[key] = finding
            else:
                _merge_support(existing, finding)
            continue
        seen[key] = finding
        result.append(finding)
    return result
