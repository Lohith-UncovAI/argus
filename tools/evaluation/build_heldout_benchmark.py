#!/usr/bin/env python3
"""Freeze an independent held-out benchmark for the prompt-injection classifier.

The hand-authored corpus (``prompt_text_corpus.jsonl``) measures ARGUS-specific
behaviour (OCR-garble, tiled-split, document-style benign, the corroboration
rule). It is small and it is written by us. A second, larger, externally-sourced
benchmark is needed to report *generalization* rather than fit-to-our-own-corpus.

With no network access, the stand-in is a frozen stratified slice of the
``jayavibhav/prompt-injection`` **test** split — a split the training assembler
draws its data from the **train** side of, and which this script additionally
fuzzy-excludes from every hand corpus. The result is checked in as
``corpus/heldout_benchmark.jsonl`` so the number is stable across runs and the
slice can never silently drift into training (``assemble_training_corpus.py``
reads this file into its hold-out set, exact + fuzzy).

    python tools/evaluation/build_heldout_benchmark.py --size 2000 --seed 20260910

Re-running with the same args reproduces the file byte-for-byte.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.training._fuzzy import NearDupChecker, normalize  # noqa: E402

OUT = REPO_ROOT / "tools" / "evaluation" / "corpus" / "heldout_benchmark.jsonl"
HAND_CORPORA = [
    REPO_ROOT / "tools" / "evaluation" / "corpus" / "prompt_text_corpus.jsonl",
    REPO_ROOT / "tools" / "evaluation" / "corpus" / "domain_holdout.jsonl",
]
MAX_CHARS = 2000


def _hand_texts():
    for path in HAND_CORPORA:
        if path.is_file():
            for line in path.read_text().splitlines():
                line = line.strip()
                if line:
                    yield json.loads(line)["text"]


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--size", type=int, default=2000, help="target rows (balanced across the two classes)")
    ap.add_argument("--seed", type=int, default=20260910)
    ap.add_argument("--min-chars", type=int, default=8)
    ap.add_argument("--out", type=pathlib.Path, default=OUT)
    args = ap.parse_args(argv)

    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
    from datasets import load_dataset

    test = load_dataset("jayavibhav/prompt-injection")["test"]

    fuzzy = NearDupChecker(_hand_texts(), threshold=0.72)

    # Deterministic order: sort candidate rows by a seeded hash of their text.
    def rank(text: str) -> str:
        return hashlib.sha256(("%d:%s" % (args.seed, normalize(text))).encode()).hexdigest()

    rows = []
    for rec in test:
        text = (rec["text"] or "").strip()
        if not (args.min_chars <= len(text) <= MAX_CHARS):
            continue
        rows.append((rank(text), text, int(rec["label"])))
    rows.sort()

    per_class = args.size // 2
    picked = {0: [], 1: []}
    seen_norm = set()
    for _, text, label in rows:
        if len(picked[label]) >= per_class:
            continue
        key = normalize(text)
        if key in seen_norm or fuzzy.is_near(text):
            continue
        seen_norm.add(key)
        picked[label].append(text)
        if len(picked[0]) >= per_class and len(picked[1]) >= per_class:
            break

    out_rows = []
    for label in (1, 0):
        for i, text in enumerate(picked[label]):
            out_rows.append({
                "id": "hob-%s-%04d" % ("a" if label else "b", i),
                "text": text,
                "label": "attack" if label else "benign",
                "source": "jayavibhav/prompt-injection:test",
            })

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for row in out_rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    print("wrote %d rows (attack=%d benign=%d) -> %s"
          % (len(out_rows), len(picked[1]), len(picked[0]), args.out.relative_to(REPO_ROOT)))
    print("sha256:%s" % digest)
    if len(picked[1]) < per_class or len(picked[0]) < per_class:
        print("WARNING: could not fill both classes to %d after fuzzy exclusion" % per_class)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
