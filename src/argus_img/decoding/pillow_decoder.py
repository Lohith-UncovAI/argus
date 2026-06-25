from __future__ import annotations

import io
from pathlib import Path
from typing import Dict

from PIL import Image, ImageOps

from argus_img.core.hashing import sha256_bytes


def normalized_first_frame(path: Path) -> Image.Image:
    with Image.open(path) as image:
        image.seek(0)
        frame = ImageOps.exif_transpose(image.copy())
    if frame.mode not in {"RGB", "RGBA"}:
        frame = frame.convert("RGBA" if "A" in frame.getbands() else "RGB")
    return frame


def decode_descriptor(path: Path) -> Dict[str, object]:
    with Image.open(path) as image:
        frames = getattr(image, "n_frames", 1)
        mode = image.mode
        width, height = image.size
        source_bands = image.getbands()
        alpha = "A" in source_bands or image.mode in {"LA", "PA"}
        frame = ImageOps.exif_transpose(image.copy()).convert("RGBA")
    return {
        "decoder": "pillow",
        "success": True,
        "width": width,
        "height": height,
        "frames": frames,
        "mode": mode,
        "alpha": alpha,
        "channel_count": len(source_bands),
        "normalized_pixel_digest": sha256_bytes(frame.tobytes()),
        "warnings": [],
    }


def encode_png(image: Image.Image) -> bytes:
    out = io.BytesIO()
    image.save(out, format="PNG", optimize=False)
    return out.getvalue()


def encode_jpeg(image: Image.Image, quality: int = 90) -> bytes:
    out = io.BytesIO()
    if image.mode != "RGB":
        image = image.convert("RGB")
    image.save(out, format="JPEG", quality=quality, optimize=False)
    return out.getvalue()
