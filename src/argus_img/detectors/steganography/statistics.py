import math
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from PIL import Image

# Known canaries embedded by the ARGUS corpus generator and any controlled
# deployment that injects traceable payloads via LSB steganography.
_KNOWN_CANARIES: List[bytes] = [
    b"ARGUS-STEG-CANARY-7F91",
]

# Maximum bytes to extract from the LSB stream when scanning for canaries.
# Covers a 4-byte length header + up to 512 bytes of payload.
_MAX_EXTRACT_BYTES = 516


def image_entropy_summary(path: Path) -> Dict[str, float]:
    with Image.open(path) as image:
        gray = image.convert("L")
        hist = gray.histogram()
    total = float(sum(hist)) or 1.0
    entropy = -sum((count / total) * math.log(count / total, 2) for count in hist if count)
    return {"grayscale_entropy": entropy}


def lsb_canary_detect(
    path: Path,
    known_canaries: Optional[List[bytes]] = None,
) -> Tuple[bool, Optional[bytes]]:
    """Extract the LSB stream from an RGB image and search for known canary bytes.

    The corpus generator embeds payloads as:
        big-endian uint32 (length) || payload bytes
    encoded one bit per pixel across the flattened RGB channel array.

    Returns (found, matched_canary).  matched_canary is the first canary that
    was found in the extracted payload, or None if no match.
    """
    canaries = known_canaries if known_canaries is not None else _KNOWN_CANARIES
    if not canaries:
        return False, None

    with Image.open(path) as img:
        arr = np.array(img.convert("RGB")).flatten().astype(np.uint8)

    n_bits = min(len(arr), _MAX_EXTRACT_BYTES * 8)
    bits = (arr[:n_bits] & 1).astype(np.uint8)

    # Reconstruct bytes from the bit stream
    n_bytes = n_bits // 8
    byte_arr = np.packbits(bits[:n_bytes * 8])
    payload_raw = bytes(byte_arr)

    if len(payload_raw) < 4:
        return False, None

    # Check the length-prefixed framing first
    try:
        declared_len = struct.unpack(">I", payload_raw[:4])[0]
        if 0 < declared_len <= len(payload_raw) - 4:
            framed_payload = payload_raw[4:4 + declared_len]
            for canary in canaries:
                if canary in framed_payload:
                    return True, canary
    except struct.error:
        pass

    # Fallback: scan the raw byte stream for the canary without framing
    for canary in canaries:
        if canary in payload_raw:
            return True, canary

    return False, None

