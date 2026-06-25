from __future__ import annotations

from typing import Any, Dict

from argus_img.core.models import DetectorFinding


def finding_matches(finding: DetectorFinding, condition: Dict[str, Any]) -> bool:
    if "category" in condition and finding.category != condition["category"]:
        return False
    if "type" in condition and finding.type != condition["type"]:
        return False
    if "state" in condition and finding.state.value != condition["state"]:
        return False
    if "state_in" in condition and finding.state.value not in condition["state_in"]:
        return False
    if "reason_code" in condition and condition["reason_code"] not in finding.reason_codes:
        return False
    if "severity_in" in condition and finding.severity not in condition["severity_in"]:
        return False
    if "greater_than_or_equal" in condition:
        for key, value in condition["greater_than_or_equal"].items():
            if getattr(finding, key, None) is None or getattr(finding, key) < value:
                return False
    return True

