from __future__ import annotations

from pathlib import Path
from typing import Dict

from PIL import Image

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.models import Artifact, ArtifactTransformation
from argus_img.decoding.pillow_decoder import encode_jpeg, encode_png, normalized_first_frame


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
) -> Dict[str, Artifact]:
    image = normalized_first_frame(source_path)
    if image.mode not in {"RGB", "RGBA"}:
        image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
    artifacts: Dict[str, Artifact] = {}
    artifacts["canonical_lossless"] = store.store_bytes(
        encode_png(image),
        artifact_id="artifact:%s:canonical-lossless" % scan_id,
        media_type="image/png",
        created_by="canonical-reconstruction",
        role="canonical_lossless",
        release_eligible=True,
        derived_from=source_artifact.artifact_id,
        transformation=ArtifactTransformation(
            transformation_id="transform:canonical-lossless",
            type="canonical_lossless_png",
            parameters={"metadata_stripped": True, "orientation_applied": True},
        ),
        width=image.width,
        height=image.height,
    )
    artifacts["canonical_lossy"] = store.store_bytes(
        encode_jpeg(image, quality=90),
        artifact_id="artifact:%s:canonical-lossy" % scan_id,
        media_type="image/jpeg",
        created_by="canonical-reconstruction",
        role="canonical_lossy",
        release_eligible=True,
        derived_from=source_artifact.artifact_id,
        transformation=ArtifactTransformation(
            transformation_id="transform:canonical-lossy",
            type="canonical_lossy_jpeg",
            parameters={"metadata_stripped": True, "quality": 90},
        ),
        width=image.width,
        height=image.height,
    )
    artifacts["flattened_white"] = store.store_bytes(
        encode_png(_flatten(image, (255, 255, 255, 255))),
        artifact_id="artifact:%s:flattened-white" % scan_id,
        media_type="image/png",
        created_by="canonical-reconstruction",
        role="flattened_white",
        release_eligible=True,
        derived_from=source_artifact.artifact_id,
        transformation=ArtifactTransformation(
            transformation_id="transform:flattened-white",
            type="alpha_flatten",
            parameters={"background": "white", "metadata_stripped": True},
        ),
        width=image.width,
        height=image.height,
    )
    artifacts["flattened_black"] = store.store_bytes(
        encode_png(_flatten(image, (0, 0, 0, 255))),
        artifact_id="artifact:%s:flattened-black" % scan_id,
        media_type="image/png",
        created_by="canonical-reconstruction",
        role="flattened_black",
        release_eligible=True,
        derived_from=source_artifact.artifact_id,
        transformation=ArtifactTransformation(
            transformation_id="transform:flattened-black",
            type="alpha_flatten",
            parameters={"background": "black", "metadata_stripped": True},
        ),
        width=image.width,
        height=image.height,
    )
    return artifacts

