from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from argus_img.core.exceptions import IntakeRejected


def write_bounded_stream(handle: BinaryIO, dest: Path, max_bytes: int) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with dest.open("wb") as out:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if total > max_bytes:
                raise IntakeRejected("upload exceeds maximum byte limit")
            out.write(chunk)
    return total

