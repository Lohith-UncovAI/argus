from __future__ import annotations

import io
from pathlib import Path
from typing import Dict, Optional

from PIL import ExifTags, Image, ImageOps

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.budget import ResourceBudget
from argus_img.core.models import Artifact, ArtifactTransformation, ModuleStatus
from argus_img.core.enums import EpistemicState

from .pillow_decoder import encode_png


JPEG_INTERCHANGE_FORMAT = 513
JPEG_INTERCHANGE_FORMAT_LENGTH = 514


def _exif_thumbnail_bytes(path: Path) -> Optional[bytes]:
    with Image.open(path) as image:
        exif = image.getexif()
        if not exif:
            return None
        try:
            ifd1 = exif.get_ifd(ExifTags.IFD.IFD1)
        except Exception:
            return None
    offset = ifd1.get(JPEG_INTERCHANGE_FORMAT)
    length = ifd1.get(JPEG_INTERCHANGE_FORMAT_LENGTH)
    if not isinstance(offset, int) or not isinstance(length, int) or length <= 0:
        return None
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(length)


def extract_embedded_thumbnails(
    store: ArtifactStore,
    source_artifact: Artifact,
    source_path: Path,
    scan_id: str,
    budget: Optional[ResourceBudget] = None,
) -> Dict[str, Artifact]:
    raw = _exif_thumbnail_bytes(source_path)
    if not raw:
        return {}
    with Image.open(io.BytesIO(raw)) as thumb:
        image = ImageOps.exif_transpose(thumb.copy()).convert("RGBA")
    data = encode_png(image)
    if budget:
        budget.consume_decoded_pixels(image.width * image.height)
        budget.consume_artifact(len(data))
    label = "thumbnail-000"
    return {
        label: store.store_bytes(
            data,
            artifact_id="artifact:%s:%s" % (scan_id, label),
            media_type="image/png",
            created_by="thumbnail-extractor",
            role=label,
            release_eligible=False,
            derived_from=source_artifact.artifact_id,
            transformation=ArtifactTransformation(
                transformation_id="transform:%s" % label,
                type="embedded_thumbnail_extract",
                parameters={"source": "exif_ifd1"},
                inverse_coordinate_mapping="not_applicable",
            ),
            width=image.width,
            height=image.height,
            representation_id="repr:thumbnail:000",
        )
    }


def thumbnail_status(artifacts: Dict[str, Artifact]) -> ModuleStatus:
    count = sum(1 for artifact in artifacts.values() if "thumbnail" in artifact.role)
    if count:
        return ModuleStatus(name="embedded_thumbnails", status=EpistemicState.CONFIRMED, reason="%d extracted" % count)
    return ModuleStatus(name="embedded_thumbnails", status=EpistemicState.NO_EVIDENCE_FOUND, reason="no embedded thumbnails found")
