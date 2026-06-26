"""Explicit execution plans for each ScanMode.

Each plan documents which detector sets and transformation sets run in that
mode.  The pipeline reads the active plan to decide what to run and what to
skip.  This makes the per-mode behaviour testable and auditable without
inspecting the pipeline implementation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet

from argus_img.core.enums import ScanMode


@dataclass(frozen=True)
class ModePlan:
    """Documented set of detectors and transformations active in a scan mode."""

    mode: ScanMode
    # Detector ids that are active.  A detector absent from this set is skipped.
    active_detectors: FrozenSet[str]
    # Named transformation stages that are active.
    active_transformations: FrozenSet[str]
    # Whether to extract animation frames.
    extract_frames: bool
    # Whether to extract embedded thumbnails.
    extract_thumbnails: bool
    # Whether to generate full fast-transformation bank.
    generate_transform_bank: bool
    description: str = ""


# ---------------------------------------------------------------------------
# fast: minimum viable analysis for real-time gating.
# Runs all mandatory detectors and core representations; skips expensive
# forensic-only transforms.
# ---------------------------------------------------------------------------
FAST_PLAN = ModePlan(
    mode=ScanMode.FAST,
    active_detectors=frozenset({
        "detector:metadata-builtin",
        "detector:exiftool",
        "detector:tesseract",
        "detector:qr-pyzbar",
        "detector:prompt-rules",
        "detector:semantic-scorer",
        "detector:malware-clamav",
        "detector:malware-yara",
        "detector:embedded-binwalk",
        "detector:privacy-rules",
        "detector:phishing-rules",
        "detector:visible-watermark-rules",
        "detector:steganalysis-statistics",
    }),
    active_transformations=frozenset({
        "canonical_lossless",
        "canonical_lossy",
        "flattened_white",
        "flattened_black",
        "grayscale",
        "red-channel",
        "green-channel",
        "blue-channel",
        "alpha-channel",
        "white-text-extract",
        "bg-normalised",
        "sharpen-contrast",
    }),
    extract_frames=True,
    extract_thumbnails=True,
    generate_transform_bank=True,
    description=(
        "Fast mode: all mandatory detectors, canonical representations, "
        "grayscale and RGBA channel transforms, frame and thumbnail extraction.  "
        "Skips Otsu threshold, inverted grayscale, bitplanes, and 2x enlargement."
    ),
)

# ---------------------------------------------------------------------------
# deep: full detector set and full transformation bank.
# Runs everything in fast plus channel views, bitplanes, enlargements, and
# decoder-differential analysis.
# ---------------------------------------------------------------------------
DEEP_PLAN = ModePlan(
    mode=ScanMode.DEEP,
    active_detectors=FAST_PLAN.active_detectors | frozenset({
        "detector:easyocr",
        "detector:vlm-caption",
        "detector:decoder-differential",
        "detector:trailing-bytes",
        "detector:release-candidate-validation",
    }),
    active_transformations=FAST_PLAN.active_transformations | frozenset({
        "otsu-threshold",
        "inverted-grayscale",
        "red-channel",
        "green-channel",
        "blue-channel",
        "alpha-channel",
        "2x-enlargement",
    }),
    extract_frames=True,
    extract_thumbnails=True,
    generate_transform_bank=True,
    description=(
        "Deep mode: everything in fast plus the full transformation bank "
        "(channel views, bitplanes, 2x enlargement, Otsu threshold) and "
        "extended decoder-differential and trailing-byte analysis."
    ),
)

# ---------------------------------------------------------------------------
# forensic: deep plus all optional forensic tools (zsteg, binwalk, C2PA, etc.)
# Intended for incident-response and chain-of-evidence workflows.
# ---------------------------------------------------------------------------
FORENSIC_PLAN = ModePlan(
    mode=ScanMode.FORENSIC,
    active_detectors=DEEP_PLAN.active_detectors | frozenset({
        "detector:zsteg",
        "detector:c2pa",
        "detector:adversarial-stability",
        "detector:redaction-analysis",
        "detector:watermark-registry",
        "detector:paddleocr",
    }),
    active_transformations=DEEP_PLAN.active_transformations,
    extract_frames=True,
    extract_thumbnails=True,
    generate_transform_bank=True,
    description=(
        "Forensic mode: everything in deep plus optional forensic detectors "
        "(zsteg, C2PA/provenance, adversarial stability, redaction analysis, "
        "watermark registry, PaddleOCR).  Intended for chain-of-evidence use."
    ),
)

_PLANS: dict[ScanMode, ModePlan] = {
    ScanMode.FAST: FAST_PLAN,
    ScanMode.DEEP: DEEP_PLAN,
    ScanMode.FORENSIC: FORENSIC_PLAN,
}


def plan_for_mode(mode: ScanMode) -> ModePlan:
    """Return the execution plan for the given scan mode."""
    return _PLANS[mode]


def detector_active(detector_id: str, mode: ScanMode) -> bool:
    """Return True if *detector_id* should run in *mode*."""
    return detector_id in _PLANS[mode].active_detectors
