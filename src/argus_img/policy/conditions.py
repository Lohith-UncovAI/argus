from __future__ import annotations

from argus_img.core.models import DetectorFinding
from argus_img.policy.decisions import PolicyCondition


def finding_matches(finding: DetectorFinding, condition: PolicyCondition) -> bool:
    if condition.category is not None and finding.category != condition.category:
        return False
    if condition.type is not None and finding.type != condition.type:
        return False
    if condition.state is not None and finding.state != condition.state:
        return False
    if condition.state_in is not None and finding.state not in condition.state_in:
        return False
    if condition.reason_code is not None and condition.reason_code not in finding.reason_codes:
        return False
    if condition.severity_in is not None and finding.severity not in condition.severity_in:
        return False
    if condition.greater_than_or_equal is not None:
        for key, value in condition.greater_than_or_equal.items():
            if getattr(finding, key, None) is None or getattr(finding, key) < value:
                return False
    return True
