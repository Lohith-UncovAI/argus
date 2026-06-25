from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.models import DetectorFinding, ModuleStatus

from . import opencv_decoder, pillow_decoder


def compare_decoders(path: Path, artifact_id: str, finding_id: str) -> Tuple[List[DetectorFinding], ModuleStatus]:
    pillow = pillow_decoder.decode_descriptor(path)
    opencv = opencv_decoder.decode_descriptor(path)
    if not opencv.get("success"):
        return [], ModuleStatus(
            name="opencv_decoder",
            status=EpistemicState.UNSUPPORTED
            if opencv.get("status") == "UNSUPPORTED"
            else EpistemicState.ERROR,
            reason=str(opencv.get("reason", "decode_failed")),
        )
    differences = []
    for field in ["width", "height", "channel_count", "alpha"]:
        if pillow.get(field) != opencv.get(field):
            differences.append(field)
    if differences:
        finding = DetectorFinding(
            finding_id=finding_id,
            category="file_security",
            type="decoder_differential",
            state=EpistemicState.POSSIBLE,
            severity="medium",
            evidence_quality=0.7,
            impact="medium",
            source_artifact_ids=[artifact_id],
            detector_ids=["detector:decoder-differential"],
            reason_codes=["DECODER_DISAGREEMENT"],
            recommended_action=PolicyAction.REVIEW,
            evidence={"differences": differences, "pillow": pillow, "opencv": opencv},
        )
        return [finding], ModuleStatus(name="opencv_decoder", status=EpistemicState.CONFIRMED)
    return [], ModuleStatus(name="opencv_decoder", status=EpistemicState.CONFIRMED)

