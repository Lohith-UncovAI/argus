from __future__ import annotations

from pathlib import Path
from typing import Tuple


def detect_magic(path: Path) -> Tuple[str, str]:
    with path.open("rb") as handle:
        head = handle.read(64)
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "PNG"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "JPEG"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif", "GIF"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp", "WEBP"
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff", "TIFF"
    if head.startswith(b"BM"):
        return "image/bmp", "BMP"
    stripped = head.lstrip()
    if stripped.startswith(b"%PDF"):
        return "application/pdf", "PDF"
    if stripped.startswith((b"<svg", b"<?xml")) and b"<svg" in head.lower():
        return "image/svg+xml", "SVG"
    if stripped.startswith((b"%!PS", b"\x04%!PS")):
        return "application/postscript", "POSTSCRIPT"
    return "application/octet-stream", "UNKNOWN"


def extension_format(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    return {
        "jpg": "JPEG",
        "jpeg": "JPEG",
        "png": "PNG",
        "gif": "GIF",
        "webp": "WEBP",
        "tif": "TIFF",
        "tiff": "TIFF",
        "bmp": "BMP",
        "svg": "SVG",
        "pdf": "PDF",
        "ps": "POSTSCRIPT",
    }.get(suffix, "UNKNOWN")

