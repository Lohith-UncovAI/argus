from __future__ import annotations

from pathlib import Path
from typing import Optional

from PIL import Image, ImageFile

from argus_img.core.exceptions import IntakeRejected
from argus_img.core.hashing import sha256_file
from argus_img.core.limits import Limits
from argus_img.core.models import FileDescriptor

from .format_policy import is_allowed_format
from .mime import detect_magic

Image.MAX_IMAGE_PIXELS = 150_000_000
ImageFile.LOAD_TRUNCATED_IMAGES = False


def validate_image_file(
    path: Path,
    declared_mime: Optional[str],
    limits: Limits,
    *,
    known_sha256: Optional[str] = None,
    known_size: Optional[int] = None,
    quarantined_artifact_id: Optional[str] = None,
) -> FileDescriptor:
    if path.is_symlink():
        raise IntakeRejected("symlink inputs are not accepted")
    if not path.is_file():
        raise IntakeRejected("input must be a regular file")
    size = known_size if known_size is not None else path.stat().st_size
    if size > limits.max_input_bytes:
        raise IntakeRejected("input exceeds maximum byte limit")
    detected_mime, format_name = detect_magic(path)
    if not is_allowed_format(format_name):
        raise IntakeRejected("unsupported or active input format: %s" % format_name)
    try:
        with Image.open(path) as image:
            width, height = image.size
            frames = getattr(image, "n_frames", 1)
            if width > limits.max_width or height > limits.max_height:
                raise IntakeRejected("image dimensions exceed configured limits")
            if width * height > limits.max_pixels_per_frame:
                raise IntakeRejected("image pixel count exceeds configured limits")
            if frames > limits.max_frames:
                raise IntakeRejected("image frame count exceeds configured limits")
            if width and height:
                ratio = max(width / height, height / width)
                if ratio > 200:
                    raise IntakeRejected("image aspect ratio exceeds configured limits")
            total_pixels = 0
            for index in range(frames):
                image.seek(index)
                frame_width, frame_height = image.size
                if frame_width > limits.max_width or frame_height > limits.max_height:
                    raise IntakeRejected("image frame dimensions exceed configured limits")
                pixels = frame_width * frame_height
                if pixels > limits.max_pixels_per_frame:
                    raise IntakeRejected("image frame pixel count exceeds configured limits")
                total_pixels += pixels
                if total_pixels > limits.max_total_decoded_pixels:
                    raise IntakeRejected("image decoded pixel count exceeds configured limits")
        with Image.open(path) as image:
            image.verify()
        # verify() checks container structure but does not force full pixel
        # decoding (e.g. a JPEG truncated mid-scan-data can pass verify()
        # cleanly). Re-open and force a real decode so files that fail later,
        # deeper in the pipeline (canonical reconstruction, decoder-differential)
        # are rejected here instead, where the failure is already handled.
        with Image.open(path) as image:
            image.seek(0)
            image.load()
    except IntakeRejected:
        raise
    except Exception as exc:
        raise IntakeRejected("decoder validation failed: %s" % exc)
    return FileDescriptor(
        original_filename=path.name,
        size_bytes=size,
        sha256=known_sha256 or sha256_file(path),
        declared_mime=declared_mime,
        detected_mime=detected_mime,
        format=format_name,
        width=width,
        height=height,
        frames=frames,
        quarantined_artifact_id=quarantined_artifact_id,
    )
