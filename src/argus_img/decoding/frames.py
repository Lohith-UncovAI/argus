from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

from PIL import Image, ImageOps

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.budget import ResourceBudget
from argus_img.core.models import Artifact, ArtifactTransformation

from .pillow_decoder import encode_png


def extract_frames(
    store: ArtifactStore,
    source_artifact: Artifact,
    source_path: Path,
    scan_id: str,
    max_frames: int,
    budget: Optional[ResourceBudget] = None,
) -> Dict[str, Artifact]:
    artifacts: Dict[str, Artifact] = {}
    with Image.open(source_path) as image:
        count = min(getattr(image, "n_frames", 1), max_frames)
        for index in range(count):
            image.seek(index)
            frame = ImageOps.exif_transpose(image.copy()).convert("RGBA")
            label = "frame-%03d" % index
            data = encode_png(frame)
            if budget:
                budget.consume_decoded_pixels(frame.width * frame.height)
                budget.consume_artifact(len(data))
            artifacts[label] = store.store_bytes(
                data,
                artifact_id="artifact:%s:%s" % (scan_id, label),
                media_type="image/png",
                created_by="frame-extractor",
                role=label,
                release_eligible=False,
                derived_from=source_artifact.artifact_id,
                transformation=ArtifactTransformation(
                    transformation_id="transform:%s" % label,
                    type="frame_extract",
                    parameters={"frame_index": index},
                ),
                width=frame.width,
                height=frame.height,
                frame_index=index,
                representation_id="repr:frame:%03d" % index,
            )
    return artifacts
