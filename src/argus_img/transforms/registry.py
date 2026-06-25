from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

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
) -> Dict[str, Artifact]:
    with Image.open(source_path) as raw:
        image = raw.convert("RGBA")
    gray = ImageOps.grayscale(image)
    artifacts: Dict[str, Artifact] = {}

    def store_transformed(label: str, transformed: Image.Image) -> None:
        if transformed.mode not in {"RGB", "RGBA"}:
            transformed = transformed.convert("RGB")
        data = encode_png(transformed)
        if budget:
            budget.consume_transformed_pixels(transformed.width * transformed.height)
            budget.consume_artifact(len(data))
        transformation = ArtifactTransformation(
            transformation_id="transform:%s" % label,
            type=label.replace("-", "_"),
            parameters={},
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
        )

    store_transformed("grayscale", gray)
    store_transformed("otsu-threshold", _otsu_threshold(gray))
    store_transformed("inverted-grayscale", ImageOps.invert(gray))
    channels = image.split()
    channel_names = ["red-channel", "green-channel", "blue-channel", "alpha-channel"]
    for name, channel in zip(channel_names, channels):
        store_transformed(name, channel)
    enlarged = image.resize((image.width * 2, image.height * 2), Image.Resampling.BICUBIC)
    store_transformed("2x-enlargement", enlarged)
    return artifacts
