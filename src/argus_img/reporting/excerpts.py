import re

from argus_img.core.hashing import sha256_bytes

_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[A-Za-z0-9_\-./+=]{6,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


def safe_excerpt(text: str, max_chars: int = 80) -> str:
    normalized = text.replace("\n", " ").replace("\r", " ")
    for pattern in _SECRET_PATTERNS:
        normalized = pattern.sub("[redacted-sensitive-value]", normalized)
    if len(normalized) > max_chars:
        return normalized[:max_chars] + "..."
    return normalized


def text_evidence(text: str, include_raw_text: bool = False) -> dict:
    evidence = {
        "excerpt": safe_excerpt(text),
        "full_text_returned": include_raw_text,
        "text_sha256": sha256_bytes(text.encode("utf-8", errors="replace")),
    }
    if include_raw_text:
        evidence["raw_text"] = text
    return evidence

