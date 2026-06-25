from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from html import unescape
from urllib.parse import unquote

ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\ufeff]")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
WHITESPACE = re.compile(r"\s+")


@dataclass
class NormalizedText:
    normalized: str
    zero_width_found: bool
    bidi_found: bool


def normalize_text(text: str) -> NormalizedText:
    nfkc = unicodedata.normalize("NFKC", text)
    zero_width_found = ZERO_WIDTH.search(nfkc) is not None
    bidi_found = BIDI.search(nfkc) is not None
    cleaned = ZERO_WIDTH.sub("", nfkc)
    cleaned = BIDI.sub("", cleaned)
    cleaned = unescape(cleaned)
    cleaned = unquote(cleaned)
    cleaned = WHITESPACE.sub(" ", cleaned).strip()
    return NormalizedText(normalized=cleaned, zero_width_found=zero_width_found, bidi_found=bidi_found)

