from __future__ import annotations

from pathlib import Path
from typing import Optional

from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.models import DetectorFinding


def detect_trailing_bytes(path: Path, format_name: str, artifact_id: str, finding_id: str) -> Optional[DetectorFinding]:
    data = path.read_bytes()
    end = None
    if format_name == "PNG":
        marker = b"IEND\xaeB`\x82"
        pos = data.rfind(marker)
        end = pos + len(marker) if pos != -1 else None
    elif format_name == "JPEG":
        pos = data.rfind(b"\xff\xd9")
        end = pos + 2 if pos != -1 else None
    elif format_name == "GIF":
        pos = data.rfind(b"\x3b")
        end = pos + 1 if pos != -1 else None
    if end is not None and end < len(data):
        trailing = len(data) - end
        return DetectorFinding(
            finding_id=finding_id,
            category="embedded_payload",
            type="trailing_bytes",
            state=EpistemicState.POSSIBLE,
            severity="medium",
            evidence_quality=0.6,
            impact="medium",
            source_artifact_ids=[artifact_id],
            detector_ids=["detector:file-structure"],
            reason_codes=["TRAILING_BYTES"],
            recommended_action=PolicyAction.REVIEW,
            evidence={"trailing_bytes": trailing},
        )
    return None

