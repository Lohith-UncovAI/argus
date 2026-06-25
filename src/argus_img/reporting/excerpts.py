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
    payload = text.encode("utf-8", errors="replace")
    return {
        "text_sha256": sha256_bytes(payload),
        "text_length": len(payload),
        "full_text_returned": False,
        "forensic_evidence_required": bool(text),
    }
