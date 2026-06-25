from __future__ import annotations

from pathlib import Path
from typing import Optional

from PIL import Image, ImageFile

from argus_img.core.exceptions import IntakeRejected
from argus_img.core.limits import Limits
from argus_img.core.models import FileDescriptor
from argus_img.core.hashing import sha256_file

from .format_policy import is_allowed_format
from .mime import detect_magic

Image.MAX_IMAGE_PIXELS = 150_000_000
ImageFile.LOAD_TRUNCATED_IMAGES = False


def validate_image_file(path: Path, declared_mime: Optional[str], limits: Limits) -> FileDescriptor:
    if path.is_symlink():
        raise IntakeRejected("symlink inputs are not accepted")
    size = path.stat().st_size
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
            image.verify()
    except IntakeRejected:
        raise
    except Exception as exc:
        raise IntakeRejected("decoder validation failed: %s" % exc)
    return FileDescriptor(
        original_filename=path.name,
        size_bytes=size,
        sha256=sha256_file(path),
        declared_mime=declared_mime,
        detected_mime=detected_mime,
        format=format_name,
        width=width,
        height=height,
        frames=frames,
    )

