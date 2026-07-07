"""EasyOCR-based neural OCR detector.

Runs only on preprocessing-enhanced artifacts where Tesseract fails (photo-overlaid
text, small/stylized fonts).  CPU-only — no GPU required.

Offline mode: set ARGUS_EASYOCR_MODEL_DIR to an absolute local directory containing
pre-downloaded EasyOCR model weights.  Downloads are never attempted at runtime; a
missing or unconfigured path causes the detector to report UNSUPPORTED.

EasyOCR is used as a *supplement* to Tesseract, not a replacement.  It runs only on
the enhanced transforms (bg-normalised, sharpen-contrast, white-text-extract,
light-text-tophat variants) to avoid redundant processing on clean images where
Tesseract already succeeds.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Iterable, List, Optional

from argus_img.core.enums import DetectorStatus, EpistemicState
from argus_img.core.models import Artifact, DetectorReport, TextObservation
from argus_img.detectors.base import detector_report
from argus_img.detectors.prompt.normalizer import normalize_text

# Only run EasyOCR on these transform labels — they are the cases where Tesseract
# struggles and neural OCR adds value.
EASYOCR_TARGET_LABELS = frozenset({
    "bg-normalised",
    "sharpen-contrast",
    "white-text-extract",
    "light-text-tophat",
    "light-text-tophat-2x",
    "light-text-tophat-wide",
    "light-text-tophat-wide-2x",
})


def easyocr_available() -> bool:
    """Return True only when easyocr is installed AND a local model dir is configured."""
    try:
        import easyocr  # noqa: F401
    except ImportError:
        return False
    local = os.environ.get("ARGUS_EASYOCR_MODEL_DIR", "").strip()
    if not local:
        return False
    return Path(local).is_dir()


def _get_reader():
    """Return a cached EasyOCR reader (lazy singleton, MPS on Apple Silicon, else CPU)."""
    if not hasattr(_get_reader, "_instance"):
        import easyocr
        import torch
        model_dir = os.environ.get("ARGUS_EASYOCR_MODEL_DIR", "").strip() or None
        # EasyOCR treats gpu=True as "use CUDA or MPS" depending on platform.
        # On Apple Silicon this maps to MPS (~3.6x faster than CPU).
        use_gpu = torch.backends.mps.is_available()
        _get_reader._instance = easyocr.Reader(
            ["en"],
            gpu=use_gpu,
            verbose=False,
            model_storage_directory=model_dir,
            download_enabled=False,
        )
    return _get_reader._instance


def analyze_with_easyocr(
    artifact_paths: Iterable[tuple],
    scan_id: str,
    seen_normalized: Optional[set] = None,
    started_at=None,
) -> DetectorReport:
    """Run EasyOCR on target preprocessing artifacts only.

    artifact_paths: iterable of (label, artifact, path) triples.
    seen_normalized: optional set of already-seen normalized strings (for dedup).
    """
    if not easyocr_available():
        return detector_report(
            "detector:easyocr",
            "OCR",
            DetectorStatus.TOOL_NOT_INSTALLED,
            EpistemicState.UNSUPPORTED,
            reason="easyocr_not_installed",
            optional=True,
            category="prompt_injection",
        )

    if seen_normalized is None:
        seen_normalized = set()

    observations: List[TextObservation] = []
    errors: List[str] = []

    try:
        reader = _get_reader()
    except Exception as exc:
        return detector_report(
            "detector:easyocr",
            "OCR",
            DetectorStatus.ERROR,
            EpistemicState.ERROR,
            reason="easyocr_init_failed: %s" % exc,
            optional=True,
            category="prompt_injection",
        )

    for label, artifact, path in artifact_paths:
        if label not in EASYOCR_TARGET_LABELS:
            continue
        try:
            import numpy as np
            from PIL import Image
            with Image.open(path) as im:
                arr = np.array(im.convert("RGB"))
            results = reader.readtext(arr, detail=0)
            text = " ".join(r for r in results if r.strip())
            if not text:
                continue
            norm = normalize_text(text).normalized
            if norm in seen_normalized:
                continue
            seen_normalized.add(norm)
            observations.append(
                TextObservation(
                    observation_id="observation:%s:easyocr:%03d" % (scan_id, len(observations)),
                    source_artifact_id=artifact.artifact_id,
                    detector_id="detector:easyocr",
                    raw_text=text,
                    normalized_text=norm,
                    engine="easyocr",
                    engine_version="1.x",
                    confidence=None,
                    transformation_id=artifact.transformation.transformation_id if artifact.transformation else None,
                    value={"artifact_label": label},
                )
            )
        except Exception as exc:
            errors.append("%s: %s" % (artifact.artifact_id, str(exc)[:200]))

    status = DetectorStatus.SUCCESS if observations else (
        DetectorStatus.ERROR if errors else DetectorStatus.NO_EVIDENCE
    )
    state = EpistemicState.CONFIRMED if observations else (
        EpistemicState.ERROR if errors else EpistemicState.NO_EVIDENCE_FOUND
    )
    report = detector_report(
        "detector:easyocr",
        "OCR",
        status,
        state,
        observations=observations,
        optional=True,
        category="prompt_injection",
        started_at=started_at,
    )
    report.errors = errors
    return report
