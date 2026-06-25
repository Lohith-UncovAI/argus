from __future__ import annotations

from pathlib import Path
from typing import Dict


def decode_descriptor(path: Path) -> Dict[str, object]:
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore
    except Exception:
        return {"decoder": "opencv", "success": False, "status": "UNSUPPORTED", "reason": "tool_not_installed"}
    data = path.read_bytes()
    array = np.frombuffer(data, dtype=np.uint8)
    decoded = cv2.imdecode(array, cv2.IMREAD_UNCHANGED)
    if decoded is None:
        return {"decoder": "opencv", "success": False, "status": "ERROR", "reason": "decode_failed"}
    height, width = decoded.shape[:2]
    channels = 1 if len(decoded.shape) == 2 else decoded.shape[2]
    alpha = channels == 4
    normalized = decoded.tobytes()
    from argus_img.core.hashing import sha256_bytes

    return {
        "decoder": "opencv",
        "success": True,
        "width": int(width),
        "height": int(height),
        "frames": 1,
        "mode": "unknown",
        "alpha": bool(alpha),
        "channel_count": int(channels),
        "normalized_pixel_digest": sha256_bytes(normalized),
        "warnings": [],
    }

