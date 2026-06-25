from __future__ import annotations

import shutil
from typing import Iterable, List

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
    observations: List[TextObservation] = []
    errors: List[str] = []
    version = tesseract_version()
    for index, (label, artifact, path) in enumerate(artifact_paths):
        result = run_tool(
            ["tesseract", str(path), "stdout", "--psm", "6"],
            timeout=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if result.timed_out:
            errors.append("%s: timeout" % artifact.artifact_id)
            continue
        if result.returncode not in (0,):
            errors.append("%s: %s" % (artifact.artifact_id, result.stderr[:200]))
            continue
        text = result.stdout.strip()
        if not text:
            continue
        observations.append(
            TextObservation(
                observation_id="observation:%s:ocr:%03d" % (scan_id, len(observations)),
                source_artifact_id=artifact.artifact_id,
                detector_id="detector:tesseract",
                raw_text=text,
                normalized_text=normalize_text(text).normalized,
                engine="tesseract",
                engine_version=version,
                confidence=None,
                transformation_id=artifact.transformation.transformation_id if artifact.transformation else None,
                value={"artifact_label": label},
            )
        )
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
    )
    report.errors = errors
    report.execution.tool_version = version
    return report
