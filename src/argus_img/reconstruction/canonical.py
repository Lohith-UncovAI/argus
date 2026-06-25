from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

from PIL import Image

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.budget import ResourceBudget
from argus_img.core.models import Artifact, ArtifactTransformation
from argus_img.decoding.pillow_decoder import alpha_composite_rgb, encode_jpeg, encode_png, normalized_first_frame


def _flatten(image: Image.Image, color: tuple) -> Image.Image:
    if image.mode != "RGBA":
        return image.convert("RGB")
    background = Image.new("RGBA", image.size, color)
    return Image.alpha_composite(background, image).convert("RGB")


def create_canonical_artifacts(
    store: ArtifactStore,
    source_artifact: Artifact,
    source_path: Path,
    scan_id: str,
    budget: Optional[ResourceBudget] = None,
) -> Dict[str, Artifact]:
    image = normalized_first_frame(source_path)
    if image.mode not in {"RGB", "RGBA"}:
        image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
    artifacts: Dict[str, Artifact] = {}
    release_rgb = alpha_composite_rgb(image, (255, 255, 255))
    lossy_bytes = encode_jpeg(release_rgb, quality=90)
    if budget:
        budget.consume_transformed_pixels(release_rgb.width * release_rgb.height)
        budget.consume_artifact(len(lossy_bytes))
    artifacts["canonical_lossy"] = store.store_bytes(
        lossy_bytes,
        artifact_id="artifact:%s:canonical-lossy" % scan_id,
        media_type="image/jpeg",
        created_by="canonical-reconstruction",
        role="canonical_lossy",
        release_eligible=False,
        derived_from=source_artifact.artifact_id,
        transformation=ArtifactTransformation(
            transformation_id="transform:canonical-lossy",
            type="canonical_lossy_jpeg",
            parameters={
                "metadata_stripped": True,
                "lossy": True,
                "flattened": True,
                "alpha_composited": True,
                "background": "white",
                "quality": 90,
            },
        ),
        width=release_rgb.width,
        height=release_rgb.height,
        representation_id="repr:release-candidate",
    )
    lossless_bytes = encode_png(image)
    if budget:
        budget.consume_transformed_pixels(image.width * image.height)
        budget.consume_artifact(len(lossless_bytes))
    artifacts["canonical_lossless"] = store.store_bytes(
        lossless_bytes,
        artifact_id="artifact:%s:canonical-lossless" % scan_id,
        media_type="image/png",
        created_by="canonical-reconstruction",
        role="canonical_lossless",
        release_eligible=False,
        derived_from=source_artifact.artifact_id,
        transformation=ArtifactTransformation(
            transformation_id="transform:canonical-lossless",
            type="canonical_lossless_png",
            parameters={"metadata_stripped": True, "orientation_applied": True},
        ),
        width=image.width,
        height=image.height,
        representation_id="repr:canonical-lossless",
    )
    flattened_white = _flatten(image, (255, 255, 255, 255))
    flattened_white_bytes = encode_png(flattened_white)
    if budget:
        budget.consume_transformed_pixels(flattened_white.width * flattened_white.height)
        budget.consume_artifact(len(flattened_white_bytes))
    artifacts["flattened_white"] = store.store_bytes(
        flattened_white_bytes,
        artifact_id="artifact:%s:flattened-white" % scan_id,
        media_type="image/png",
        created_by="canonical-reconstruction",
        role="flattened_white",
        release_eligible=False,
        derived_from=source_artifact.artifact_id,
        transformation=ArtifactTransformation(
            transformation_id="transform:flattened-white",
            type="alpha_flatten",
            parameters={"background": "white", "metadata_stripped": True},
        ),
        width=flattened_white.width,
        height=flattened_white.height,
        representation_id="repr:alpha-white",
    )
    flattened_black = _flatten(image, (0, 0, 0, 255))
    flattened_black_bytes = encode_png(flattened_black)
    if budget:
        budget.consume_transformed_pixels(flattened_black.width * flattened_black.height)
        budget.consume_artifact(len(flattened_black_bytes))
    artifacts["flattened_black"] = store.store_bytes(
        flattened_black_bytes,
        artifact_id="artifact:%s:flattened-black" % scan_id,
        media_type="image/png",
        created_by="canonical-reconstruction",
        role="flattened_black",
        release_eligible=False,
        derived_from=source_artifact.artifact_id,
        transformation=ArtifactTransformation(
            transformation_id="transform:flattened-black",
            type="alpha_flatten",
            parameters={"background": "black", "metadata_stripped": True},
        ),
        width=flattened_black.width,
        height=flattened_black.height,
        representation_id="repr:alpha-black",
    )
    return artifacts
