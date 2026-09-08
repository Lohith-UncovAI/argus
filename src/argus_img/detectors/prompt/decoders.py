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

    # Leetspeak fold: "1gn0r3 pr3v10u5 1n5truct10n5" -> "ignore previous
    # instructions". Only emitted when the fold surfaces an attack keyword the
    # original text did not contain, so ordinary text with digits (dates,
    # prices, version numbers) is never rewritten.
    deleet = _deleet(text)
    lower = text.lower()
    if deleet != lower and any(
        w in deleet and w not in lower
        for w in ("ignore", "instructions", "previous", "prior", "system", "prompt",
                  "password", "secret", "reveal", "override", "forget", "disregard")
    ):
        candidates.append(_candidate(source, "leetspeak", deleet, 1, 0.55))

    # Word re-segmentation: OCR routinely drops inter-word spaces
    # ("Nohidden instructions", "forwardalldata", "Forgetearlier rules"). Split
    # long unknown glued tokens back into words so every downstream signal sees
    # readable text. Conservative — only tokens that split cleanly into known
    # words are rewritten.
    resegmented = _resegment(text)
    if resegmented is not None and resegmented.lower() != lower:
        candidates.append(_candidate(source, "resegment", resegmented, 1, 0.6))

    # OCR spelling repair: per-token, try the common character confusions
    # (rn->m, vv->w, cl->d, I->l, 0->o, 1->l, 5->s) and keep a substitution only
    # when it turns an unknown token into a dictionary word ("systen" -> "system",
    # "prornpt" -> "prompt", "reveaI" -> "reveal"). Real words and true gibberish
    # are left alone.
    repaired = _ocr_spell_repair(text)
    if repaired is not None and repaired.lower() != lower:
        candidates.append(_candidate(source, "ocr_repair", repaired, 1, 0.6))

    return candidates[:max_candidates]


_LEET_MAP = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s",
                           "7": "t", "9": "g", "$": "s", "@": "a", "8": "b"})


def _deleet(text: str) -> str:
    """Fold common digit/symbol letter-substitutions, lowercased.

    "1" folds to "i" (not "l") — the dominant OCR/leet convention for injection
    strings ("1gn0r3", "1n5truct10n5"); the rule regexes tolerate the odd
    residual mismatch.
    """
    folded = text.lower().translate(_LEET_MAP)
    # collapse "1gn0r3" spacing artifacts is out of scope; just the char fold
    return folded


_KNOWN_COMPOUND = frozenset({
    "pythonpath", "textobservation", "screenshot", "username", "filename",
    "hostname", "namespace", "keyboard", "notebook", "dashboard", "framework",
    "database", "runtime", "codebase", "metadata", "whitespace", "lowercase",
})


def prefer_corrected_transcriptions(candidates: List[str]) -> List[str]:
    """Given [raw_text, *derived_candidates], drop any candidate that another
    candidate is a pure space-expansion of.

    "Nohidden instructions" and "No hidden instructions" describe the same image
    text; the spaced form is the faithful transcription, so the glued form is
    dropped. Decoded payloads (base64/hex/reversed) are NOT space-expansions of
    the source, so they survive and are still scored.
    """
    def _key(s: str) -> str:
        return re.sub(r"\s+", "", s).lower()

    by_key: dict = {}
    for c in candidates:
        k = _key(c)
        prev = by_key.get(k)
        # keep the variant with the most whitespace (the resegmented one)
        if prev is None or c.count(" ") > prev.count(" "):
            by_key[k] = c
    # preserve original order, using the chosen representative per key
    seen: set = set()
    out: List[str] = []
    for c in candidates:
        k = _key(c)
        if k in seen:
            continue
        seen.add(k)
        out.append(by_key[k])
    return out


_OCR_CONFUSIONS = [
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("ri", "n"), ("nn", "m"),
    ("ii", "n"), ("l", "i"), ("i", "l"), ("0", "o"), ("1", "l"), ("1", "i"),
    ("5", "s"), ("8", "b"), ("6", "b"), ("9", "g"), ("3", "e"),
]


def _ocr_spell_repair(text: str):
    """Repair single OCR-confusion errors that turn a word into gibberish.

    For each non-word token, try each confusion once; if exactly one produces a
    dictionary word, take it. Returns the repaired string, or None if nothing
    changed.
    """
    try:
        import wordninja
        vocab = wordninja.DEFAULT_LANGUAGE_MODEL._wordcost
    except Exception:  # noqa: BLE001
        return None
    changed = False
    out = []
    for tok in re.split(r"(\s+)", text):
        core = tok.lower()
        if not core or not core.isalnum() or core in vocab or len(core) < 3 or len(core) > 14:
            out.append(tok)
            continue
        fixes = set()
        for a, b in _OCR_CONFUSIONS:
            if a in core:
                cand = core.replace(a, b, 1)
                if cand in vocab and cand != core:
                    fixes.add(cand)
        if len(fixes) == 1:
            out.append(fixes.pop())
            changed = True
        else:
            out.append(tok)
    return "".join(out) if changed else None


def _resegment(text: str):
    """Split OCR-glued tokens back into words. Returns the rewritten string, or
    None if nothing changed / the splitter is unavailable.

    Only rewrites a token when: it is 8+ chars, all alphabetic, not a known
    compound, and wordninja splits it into >= 2 parts that are each >= 2 chars
    with at least one >= 4 chars. That keeps identifiers and real long words
    ("instructions", "configuration") intact while fixing "nohidden" ->
    "no hidden" and "forwardalldata" -> "forward all data".
    """
    try:
        import wordninja
    except ImportError:
        return None
    out = []
    changed = False
    for tok in re.split(r"(\s+)", text):
        if (len(tok) >= 8 and tok.isalpha() and tok.lower() not in _KNOWN_COMPOUND):
            parts = wordninja.split(tok)
            if (len(parts) >= 2 and all(len(p) >= 2 for p in parts)
                    and any(len(p) >= 4 for p in parts)
                    and "".join(parts).lower() == tok.lower()):
                out.append(" ".join(parts))
                changed = True
                continue
        out.append(tok)
    return "".join(out) if changed else None

