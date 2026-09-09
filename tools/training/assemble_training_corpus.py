#!/usr/bin/env python3
"""Assemble a *binary* (benign / injection) training corpus for the local
prompt-injection classifier from public datasets + the synthetic image-domain
augmentations in build_prompt_corpus.py.

Sources
  - deepset/prompt-injections            (~660, chatbot-style)
  - xTRam1/safe-guard-prompt-injection   (~10k, chatbot-style)
  - build_prompt_corpus.build()          synthetic: OCR-corruption / leetspeak /
                                         spacing / misleading-caption attacks,
                                         template paraphrases, and the large
                                         hard-negative bank (vocabulary traps,
                                         security-education text, plain captions)

Held out entirely (never enters train/val) so the calibration harness and the
generalization test remain a fair evaluation:
  - every text in tools/evaluation/corpus/prompt_text_corpus.jsonl (the 107
    hand-labelled ARGUS items)
  - the adversarial benign probes from
    tests/unit/test_prompt_paraphrase_generalization.py

Public chatbot injections carry the *semantics* of an attack; the synthetic
augmentations carry ARGUS's actual *distribution* (short, OCR-mangled, embedded
in captions). Both are needed — a model trained only on the public data learns
"act as DAN" phrasing and does not transfer to image OCR text.

Usage:
    python tools/training/assemble_training_corpus.py --out tools/training/corpus
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import random
import re
import sys
import unicodedata
from typing import Dict, List, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "evaluation"))

ARGUS_CORPUS = REPO_ROOT / "tools" / "evaluation" / "corpus" / "prompt_text_corpus.jsonl"
GENERALIZATION_TEST = REPO_ROOT / "tests" / "unit" / "test_prompt_paraphrase_generalization.py"

MAX_CHARS = 2000  # image OCR text is not 12k chars long


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text).lower()).strip()


def _holdout_keys() -> set:
    keys = set()
    for corpus_path in (ARGUS_CORPUS, ARGUS_CORPUS.with_name("domain_holdout.jsonl")):
        for line in corpus_path.read_text().splitlines():
            line = line.strip()
            if line:
                keys.add(_norm(json.loads(line)["text"]))
    # ADVERSARIAL_BENIGN list from the generalization test
    src = GENERALIZATION_TEST.read_text()
    block = re.search(r"ADVERSARIAL_BENIGN\s*=\s*\[(.*?)\]", src, re.S)
    if block:
        for m in re.finditer(r'"([^"]+)"', block.group(1)):
            keys.add(_norm(m.group(1)))
    return keys


def _from_public(holdout: set) -> List[Tuple[str, int, str]]:
    from datasets import concatenate_datasets, load_dataset

    rows: List[Tuple[str, int, str]] = []
    for name in ("deepset/prompt-injections", "xTRam1/safe-guard-prompt-injection"):
        ds = load_dataset(name)
        merged = concatenate_datasets([ds[s] for s in ds])
        for rec in merged:
            text = (rec["text"] or "").strip()[:MAX_CHARS]
            if len(text) < 4:
                continue
            if _norm(text) in holdout:
                continue
            source_name = name.split("/")[-1]
            group = hashlib.sha256(_norm(text).encode()).hexdigest()[:16]
            rows.append((text, int(rec["label"]), "public:%s:%s" % (source_name, group)))
    return rows


def _from_synthetic(holdout: set, multiplier: int, seed: int) -> List[Tuple[str, int, str]]:
    import build_prompt_corpus as bpc

    rows: List[Tuple[str, int, str]] = []
    for it in bpc.build(multiplier=multiplier, seed=seed):
        if _norm(it.text) in holdout:
            continue
        # keep synthetic ATTACK augmentations + template paraphrases + hard
        # negatives; drop the raw 107 seed texts (they are the held-out set)
        if it.seed_id:
            continue
        variants = [it.text]
        if not it.source.startswith("aug:"):
            for augmentation in ("ocr_confuse", "leet", "punct_noise"):
                generator = random.Random("%s:%s:%s" % (seed, it.text, augmentation))
                variants.append(bpc.ATTACK_AUGS[augmentation](it.text, generator))
        for text in variants:
            if _norm(text[:MAX_CHARS]) not in holdout:
                rows.append((text[:MAX_CHARS], 0 if not it.is_attack else 1, "synthetic:%s" % it.group))
    return rows


def _from_ocr_captures(holdout: set, path: pathlib.Path) -> List[Tuple[str, int, str]]:
    """Real OCR output over a labelled image corpus (extract_ocr_captures.py).
    This is the highest-value negative/positive source — the exact text
    distribution the classifier sees at scan time."""
    if not path.is_file():
        return []
    rows: List[Tuple[str, int, str]] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        text = (rec["text"] or "").strip()[:MAX_CHARS]
        if len(text) < 4 or _norm(text) in holdout:
            continue
        image_id = rec.get("image_id")
        if not image_id:
            raise ValueError("OCR captures require image_id for leakage-safe splitting")
        rows.append((text, int(rec["binary_label"]), "ocr_capture:%s" % image_id))
    print("ocr captures: %d rows" % len(rows))
    return rows


def _split_rows(rows, val_frac, seed):
    if not 0 < val_frac < 1:
        raise ValueError("val_frac must be between zero and one")
    splits = {"train": [], "val": []}
    for row in rows:
        text, label, source = row
        group = source if source.startswith(("synthetic:", "ocr_capture:")) else _norm(text)
        digest = hashlib.sha256((str(seed) + ":" + group).encode()).digest()
        fraction = int.from_bytes(digest[:8], "big") / 2**64
        splits["val" if fraction < val_frac else "train"].append(row)
    return splits


def _augment_training_rows(rows, excluded, seed):
    import build_prompt_corpus as builder

    augmented = list(rows)
    seen = {_norm(text) for text, _, _ in rows} | excluded
    for text, label, source in rows:
        if not source.startswith("public:") or len(text) > 600:
            continue
        generator = random.Random("ocr-domain:%s:%s" % (seed, _norm(text)))
        words = text.split()
        transposed = []
        for word in words:
            if len(word) >= 5 and generator.random() < 0.5:
                position = generator.randrange(1, len(word) - 2)
                word = (word[:position] + word[position + 1] + word[position]
                        + word[position + 2:])
            transposed.append(word)
        for variant in (builder.aug_ocr_confuse(text, generator), " ".join(transposed)):
            key = _norm(variant)
            if key not in seen and len(key) >= 4:
                augmented.append((variant, label, source))
                seen.add(key)
    return augmented


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=pathlib.Path, default=REPO_ROOT / "tools" / "training" / "corpus")
    ap.add_argument("--ocr-captures", type=pathlib.Path,
                    default=REPO_ROOT / "tools" / "training" / "corpus" / "ocr_captures.jsonl",
                    help="output of extract_ocr_captures.py; used if present")
    ap.add_argument("--val-frac", type=float, default=0.1)
    ap.add_argument("--synthetic-multiplier", type=int, default=10)
    ap.add_argument("--max-benign-ratio", type=float, default=1.6,
                    help="cap benign:injection so the model is not trained to say 'safe'")
    ap.add_argument("--seed", type=int, default=20260908)
    args = ap.parse_args(argv)

    random.seed(args.seed)
    holdout = _holdout_keys()
    print("held out %d normalized texts (ARGUS corpus + adversarial probes)" % len(holdout))

    rows = (_from_public(holdout)
            + _from_synthetic(holdout, args.synthetic_multiplier, args.seed)
            + _from_ocr_captures(holdout, args.ocr_captures))

    # dedup by normalized text, injection wins ties
    by_key: Dict[str, Tuple[str, int, str]] = {}
    for text, label, source in rows:
        k = _norm(text)
        if k in holdout:
            continue
        if k not in by_key or label > by_key[k][1]:
            by_key[k] = (text, label, source)
    rows = list(by_key.values())

    inj = [r for r in rows if r[1] == 1]
    ben = [r for r in rows if r[1] == 0]
    # cap benign, but keep every synthetic hard negative — those are the ones
    # that fix the model's false-positive modes; only public benign is trimmed.
    cap = int(len(inj) * args.max_benign_ratio)
    ben_synth = [r for r in ben if r[2].startswith("synthetic")]
    ben_public = [r for r in ben if not r[2].startswith("synthetic")]
    random.shuffle(ben_public)
    ben = ben_synth + ben_public[: max(0, cap - len(ben_synth))]
    rows = inj + ben
    random.shuffle(rows)

    splits = _split_rows(rows, args.val_frac, args.seed)
    excluded = holdout | {_norm(text) for text, _, _ in splits["val"]}
    splits["train"] = _augment_training_rows(splits["train"], excluded, args.seed)

    args.out.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, object] = {"held_out": len(holdout), "max_chars": MAX_CHARS, "splits": {}}
    for name, split_rows in splits.items():
        path = args.out / ("prompt_corpus.%s.jsonl" % name)
        with path.open("w") as fh:
            for i, (text, label, source) in enumerate(split_rows):
                fh.write(json.dumps({
                    "id": "tr-%s-%06d" % (name, i),
                    "text": text,
                    "labels": ["instruction_override"] if label else ["benign"],
                    "label": "attack" if label else "benign",
                    "binary_label": label,
                    "source": source,
                }) + "\n")
        n_inj = sum(1 for r in split_rows if r[1] == 1)
        by_src: Dict[str, int] = {}
        for _, _, s in split_rows:
            key = s.split(":")[0]
            by_src[key] = by_src.get(key, 0) + 1
        manifest["splits"][name] = {"n": len(split_rows), "injection": n_inj,
                                    "benign": len(split_rows) - n_inj, "by_source": by_src}
        try:
            rel = path.relative_to(REPO_ROOT)
        except ValueError:
            rel = path
        print("wrote %-5s %6d  (injection=%d benign=%d)  -> %s"
              % (name, len(split_rows), n_inj, len(split_rows) - n_inj, rel))

    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
