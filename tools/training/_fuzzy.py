#!/usr/bin/env python3
"""Small, dependency-free near-duplicate detection for leakage-safe corpus
assembly.

The training corpus is stitched together from several public datasets plus
synthetic augmentations. Exact-string de-duplication (``normalize`` equality) is
not enough: a paraphrase, an OCR-corrupted variant, or a whitespace/punctuation
edit of an evaluation item can still leak into training and inflate held-out
numbers.

``NearDupChecker`` seeds an inverted index of character-shingle fingerprints from
a bounded set of reference texts (every evaluation-corpus item, a sample of the
validation split, ...) and answers, for each streamed candidate, "is this within
Jaccard >= threshold of any reference?" — exact Jaccard, no MinHash
approximation, which is the right trade when one side is bounded (a few thousand
references) and the other is a stream of a few hundred thousand rows.

Pure Python, no numpy / datasketch.
"""
from __future__ import annotations

import re
import unicodedata
import zlib
from typing import Dict, Iterable, List, Optional, Set, Tuple

_DEFAULT_K = 5
_DEFAULT_THRESHOLD = 0.72


def normalize(text: str) -> str:
    """NFKC fold, lowercase, collapse whitespace."""
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text or "").lower()).strip()


def shingle_set(text: str, k: int = _DEFAULT_K) -> Set[int]:
    """Hashed character k-gram set over the whitespace-normalized string.

    Character shingles (rather than token k-grams) keep the Jaccard estimate high
    under the edits that actually occur here — a single changed/inserted/deleted
    word, OCR character corruption, added punctuation — which is what a leakage
    check must catch. Very short strings shingle as themselves.
    """
    s = normalize(text)
    if len(s) <= k:
        return {zlib.crc32(s.encode("utf-8"))} if s else set()
    return {zlib.crc32(s[i:i + k].encode("utf-8")) for i in range(len(s) - k + 1)}


class NearDupChecker:
    """Inverted-index near-duplicate membership test against a bounded reference
    set.

        checker = NearDupChecker(every_eval_text, threshold=0.72)
        leaked = [row for row in training_rows if checker.match(row.text)]

    ``match`` returns the reference key of the closest reference within
    ``threshold`` Jaccard, or ``None``. ``learn=True`` folds a non-matching query
    into the index, giving streaming intra-corpus de-duplication.
    """

    def __init__(self, references: Iterable[str] = (), threshold: float = _DEFAULT_THRESHOLD,
                 k: int = _DEFAULT_K, max_df: int = 80) -> None:
        self.k = k
        self.threshold = threshold
        self.max_df = max_df                 # shingles in more refs than this are not discriminative
        self._postings: Dict[int, List[int]] = {}
        self._sizes: List[int] = []          # full shingle-set size per ref
        self._keys: List[str] = []
        self._stop: Optional[frozenset] = None
        self._eff: List[int] = []            # discriminative (non-stop) shingle count per ref
        for i, text in enumerate(references):
            self.add(text, key="ref:%d" % i)
        self._finalize()

    def add(self, text: str, key: Optional[str] = None) -> None:
        sh = shingle_set(text, self.k)
        if not sh:
            return
        idx = len(self._sizes)
        self._sizes.append(len(sh))
        self._eff.append(0)
        self._keys.append(key if key is not None else "item:%d" % idx)
        for h in sh:
            self._postings.setdefault(h, []).append(idx)
        self._stop = None

    def _finalize(self) -> None:
        stop = {h for h, p in self._postings.items() if len(p) > self.max_df}
        self._stop = frozenset(stop)
        self._eff = [0] * len(self._sizes)
        for h, posting in self._postings.items():
            if h in stop:
                continue
            for idx in posting:
                self._eff[idx] += 1

    def match(self, text: str, learn: bool = False) -> Optional[str]:
        if self._stop is None:
            self._finalize()
        sh = shingle_set(text, self.k)
        if not sh:
            return None
        disc = [h for h in sh if h not in self._stop]
        q_eff = len(disc)
        if q_eff == 0:                       # nothing discriminative — fall back to full set
            disc, q_eff = list(sh), len(sh)
        overlap: Dict[int, int] = {}
        for h in disc:
            for idx in self._postings.get(h, ()):
                overlap[idx] = overlap.get(idx, 0) + 1
        best_key: Optional[str] = None
        best_j = 0.0
        for idx, inter in overlap.items():
            union = q_eff + (self._eff[idx] or self._sizes[idx]) - inter
            j = inter / union if union else 0.0
            if j >= self.threshold and j > best_j:
                best_key, best_j = self._keys[idx], j
        if best_key is None and learn:
            self.add(text)                   # add() clears _stop; recomputed lazily on next match
        return best_key

    def is_near(self, text: str, learn: bool = False) -> bool:
        return self.match(text, learn=learn) is not None

    def __len__(self) -> int:
        return len(self._sizes)


def audit_collisions(reference_texts: Iterable[str], candidate_texts: Iterable[str],
                     threshold: float = _DEFAULT_THRESHOLD, k: int = _DEFAULT_K,
                     limit: int = 20) -> Tuple[int, List[Tuple[str, str]]]:
    """Count candidates that near-duplicate a reference; return the count and up
    to ``limit`` (candidate, reference-key) example pairs."""
    checker = NearDupChecker(reference_texts, threshold=threshold, k=k)
    n = 0
    examples: List[Tuple[str, str]] = []
    for text in candidate_texts:
        hit = checker.match(text)
        if hit is not None:
            n += 1
            if len(examples) < limit:
                examples.append((text[:160], hit))
    return n, examples
