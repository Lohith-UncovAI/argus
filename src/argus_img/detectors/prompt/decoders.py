from __future__ import annotations

import base64
import codecs
import re
import string
from typing import List

from argus_img.core.models import DerivedText, TextObservation
from argus_img.core.hashing import sha256_bytes

PRINTABLE = set(string.printable)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for ch in text if ch in PRINTABLE) / float(len(text))


def _candidate(source: TextObservation, transformation: str, text: str, depth: int, confidence: float) -> DerivedText:
    return DerivedText(
        source_text_id=source.observation_id,
        derived_text_id="derived:%s:%s" % (source.observation_id, sha256_bytes(text.encode("utf-8"))[-12:]),
        transformation=transformation,
        depth=depth,
        confidence=confidence,
        decoded_bytes=len(text.encode("utf-8", errors="replace")),
        printable_ratio=_printable_ratio(text),
        text=text,
    )


def derive_text_candidates(source: TextObservation, max_candidates: int = 20, max_bytes: int = 100_000) -> List[DerivedText]:
    text = source.normalized_text
    candidates: List[DerivedText] = []
    if len(text.encode("utf-8", errors="replace")) > max_bytes:
        return candidates
    b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{16,}={0,2})", text)
    for match in b64_matches[:5]:
        try:
            decoded = base64.b64decode(match, validate=True).decode("utf-8")
        except Exception:
            continue
        if _printable_ratio(decoded) >= 0.8:
            candidates.append(_candidate(source, "base64", decoded, 1, 0.8))
    hex_matches = re.findall(r"(?:[0-9a-fA-F]{24,})", text)
    for match in hex_matches[:5]:
        try:
            decoded = bytes.fromhex(match).decode("utf-8")
        except Exception:
            continue
        if _printable_ratio(decoded) >= 0.8:
            candidates.append(_candidate(source, "hex", decoded, 1, 0.75))
    rot13 = codecs.decode(text, "rot_13")
    if rot13 != text and any(word in rot13.lower() for word in ["ignore", "system", "password", "tool"]):
        candidates.append(_candidate(source, "rot13", rot13, 1, 0.5))
    reversed_text = text[::-1]
    if any(word in reversed_text.lower() for word in ["ignore", "system", "password", "tool"]):
        candidates.append(_candidate(source, "reversed", reversed_text, 1, 0.5))
    return candidates[:max_candidates]

