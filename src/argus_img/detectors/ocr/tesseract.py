from __future__ import annotations

import shutil
from datetime import datetime
from typing import Iterable, List, Optional

from argus_img.core.enums import DetectorStatus, EpistemicState
from argus_img.core.models import Artifact, DetectorReport, TextObservation
from argus_img.detectors.base import detector_report
from argus_img.detectors.prompt.normalizer import normalize_text
from argus_img.subprocesses.runner import executable_version, run_tool


def tesseract_available() -> bool:
    return shutil.which("tesseract") is not None


def tesseract_version() -> str:
    return executable_version("tesseract", "--version") or "unknown"


def analyze_with_tesseract(
    artifact_paths: Iterable[tuple],
    scan_id: str,
    timeout_seconds: int,
    max_output_bytes: int = 200_000,
    started_at: Optional[datetime] = None,
) -> DetectorReport:
    if not tesseract_available():
        return detector_report(
            "detector:tesseract",
            "OCR",
            DetectorStatus.TOOL_NOT_INSTALLED,
            EpistemicState.UNSUPPORTED,
            reason="tool_not_installed",
            optional=True,
            category="prompt_injection",
        )
    # Preprocessing transforms that benefit from sparse-text mode (PSM 11) in addition
    # to the default PSM 6 pass.  PSM 11 finds text anywhere without assuming a block
    # layout, which is critical for overlaid captions and partial OCR on photo backgrounds.
    _SPARSE_TEXT_LABELS = frozenset({
        "bg-normalised", "sharpen-contrast", "white-text-extract",
    })

    observations: List[TextObservation] = []
    errors: List[str] = []
    # Per-artifact dedup: skip a second PSM pass if it produces the same text as PSM 6
    # for the same artifact.  Cross-artifact dedup is handled downstream by merge_text_observations.
    version = tesseract_version()

    def _run_ocr(label: str, artifact: Artifact, path, psm: int, seen_this_artifact: set) -> None:
        result = run_tool(
            ["tesseract", str(path), "stdout", "--psm", str(psm)],
            timeout=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if result.timed_out:
            errors.append("%s: timeout" % artifact.artifact_id)
            return
        if result.returncode not in (0,):
            errors.append("%s: %s" % (artifact.artifact_id, result.stderr[:200]))
            return
        text = result.stdout.strip()
        if not text:
            return
        norm = normalize_text(text).normalized
        if norm in seen_this_artifact:
            return
        seen_this_artifact.add(norm)
        observations.append(
            TextObservation(
                observation_id="observation:%s:ocr:%03d" % (scan_id, len(observations)),
                source_artifact_id=artifact.artifact_id,
                detector_id="detector:tesseract",
                raw_text=text,
                normalized_text=norm,
                engine="tesseract",
                engine_version=version,
                confidence=None,
                transformation_id=artifact.transformation.transformation_id if artifact.transformation else None,
                value={"artifact_label": label, "psm": psm},
            )
        )

    for index, (label, artifact, path) in enumerate(artifact_paths):
        seen_this_artifact: set = set()
        _run_ocr(label, artifact, path, psm=6, seen_this_artifact=seen_this_artifact)
        if label in _SPARSE_TEXT_LABELS:
            _run_ocr(label, artifact, path, psm=11, seen_this_artifact=seen_this_artifact)
    if observations:
        status = DetectorStatus.SUCCESS
        state = EpistemicState.CONFIRMED
    elif errors:
        status = DetectorStatus.ERROR
        state = EpistemicState.ERROR
    else:
        status = DetectorStatus.NO_EVIDENCE
        state = EpistemicState.NO_EVIDENCE_FOUND
    report = detector_report(
        "detector:tesseract",
        "OCR",
        status,
        state,
        observations=observations,
        optional=True,
        category="prompt_injection",
        started_at=started_at,
    )
    report.errors = errors
    report.execution.tool_version = version
    return report
