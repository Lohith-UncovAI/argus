from __future__ import annotations

from pathlib import Path
from typing import Dict, FrozenSet, Optional

from PIL import Image, ImageOps

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.budget import ResourceBudget
from argus_img.core.models import Artifact, ArtifactTransformation
from argus_img.decoding.pillow_decoder import encode_png


def _otsu_threshold(gray: Image.Image) -> Image.Image:
    histogram = gray.histogram()
    total = sum(histogram)
    sum_total = sum(i * histogram[i] for i in range(256))
    sum_background = 0.0
    weight_background = 0
    max_variance = -1.0
    threshold = 127
    for i in range(256):
        weight_background += histogram[i]
        if weight_background == 0:
            continue
        weight_foreground = total - weight_background
        if weight_foreground == 0:
            break
        sum_background += i * histogram[i]
        mean_background = sum_background / weight_background
        mean_foreground = (sum_total - sum_background) / weight_foreground
        variance = weight_background * weight_foreground * (mean_background - mean_foreground) ** 2
        if variance > max_variance:
            max_variance = variance
            threshold = i
    return gray.point(lambda p: 255 if p > threshold else 0)


def generate_fast_transformations(
    store: ArtifactStore,
    source_artifact: Artifact,
    source_path: Path,
    scan_id: str,
    budget: Optional[ResourceBudget] = None,
    active_transformations: Optional[FrozenSet[str]] = None,
) -> Dict[str, Artifact]:
    """Generate transformation bank, filtered to active_transformations.

    When active_transformations is None, all transforms run (backward compatible).
    Pass mode_plan.active_transformations to enforce per-mode gating:
      - Fast: grayscale + RGBA channels only (no Otsu, no inversion, no enlargement)
      - Deep: all of the above plus Otsu, inverted-grayscale, 2x-enlargement
      - Forensic: same as deep (bit-plane analysis added separately)
    """
    with Image.open(source_path) as raw:
        image = raw.convert("RGBA")
    gray = ImageOps.grayscale(image)
    artifacts: Dict[str, Artifact] = {}

    def _active(label: str) -> bool:
        return active_transformations is None or label in active_transformations

    def store_transformed(label: str, transformed: Image.Image, parameters: Optional[dict] = None) -> None:
        if not _active(label):
            return
        if transformed.mode not in {"RGB", "RGBA"}:
            transformed = transformed.convert("RGB")
        data = encode_png(transformed)
        if budget:
            budget.consume_transformed_pixels(transformed.width * transformed.height)
            budget.consume_artifact(len(data))
        transformation = ArtifactTransformation(
            transformation_id="transform:%s" % label,
            type=label.replace("-", "_"),
            parameters=parameters or {},
            inverse_coordinate_mapping="identity",
            reliability_class="forensic",
            resource_cost_class="low",
        )
        artifacts[label] = store.store_bytes(
            data,
            artifact_id="artifact:%s:%s" % (scan_id, label),
            media_type="image/png",
            created_by="transformation-bank",
            role=label,
            release_eligible=False,
            derived_from=source_artifact.artifact_id,
            transformation=transformation,
            width=transformed.width,
            height=transformed.height,
            representation_id="repr:%s" % label,
        )

    # Always-mandatory transforms (run regardless of active_transformations filtering):
    store_transformed("grayscale", gray)

    # Deep/forensic-only transforms:
    store_transformed("otsu-threshold", _otsu_threshold(gray))
    store_transformed("inverted-grayscale", ImageOps.invert(gray))

    # RGBA channel views — mandatory for content analysis in fast+deep+forensic:
    channels = image.split()
    channel_names = ["red-channel", "green-channel", "blue-channel", "alpha-channel"]
    for name, channel in zip(channel_names, channels):
        store_transformed(name, channel, {"source_channel": name.removesuffix("-channel")})

    # Deep/forensic-only:
    if _active("2x-enlargement"):
        enlarged = image.resize((image.width * 2, image.height * 2), Image.Resampling.BICUBIC)
        store_transformed("2x-enlargement", enlarged)

    return artifacts


def generate_grayscale_only(
    store: ArtifactStore,
    source_artifact: Artifact,
    source_path: Path,
    scan_id: str,
    budget: Optional[ResourceBudget] = None,
) -> Dict[str, Artifact]:
    """Minimal transform set: only grayscale."""
    with Image.open(source_path) as raw:
        image = raw.convert("RGBA")
    gray = ImageOps.grayscale(image)
    artifacts: Dict[str, Artifact] = {}

    data = encode_png(gray.convert("RGB"))
    if budget:
        budget.consume_transformed_pixels(gray.width * gray.height)
        budget.consume_artifact(len(data))
    transformation = ArtifactTransformation(
        transformation_id="transform:grayscale",
        type="grayscale",
        parameters={},
        inverse_coordinate_mapping="identity",
        reliability_class="forensic",
        resource_cost_class="low",
    )
    artifacts["grayscale"] = store.store_bytes(
        data,
        artifact_id="artifact:%s:grayscale" % scan_id,
        media_type="image/png",
        created_by="transformation-bank",
        role="grayscale",
        release_eligible=False,
        derived_from=source_artifact.artifact_id,
        transformation=transformation,
        width=gray.width,
        height=gray.height,
        representation_id="repr:grayscale",
    )
    return artifacts
