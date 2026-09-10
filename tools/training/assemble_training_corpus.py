#!/usr/bin/env python3
"""Assemble a *binary* (benign / injection) training corpus for the local
prompt-injection classifier from HF-cached public datasets + the synthetic
image-domain augmentations in build_prompt_corpus.py + real-OCR captures.

Sources
  - deepset/prompt-injections            (~660, chatbot-style)
  - xTRam1/safe-guard-prompt-injection   (~10k, chatbot-style)
  - jayavibhav/prompt-injection          (~262k train rows, ~47% injection,
                                         some non-Latin script) — the backbone;
                                         capped per class (--max-public-per-class)
  - build_prompt_corpus.build()          synthetic: OCR-corruption / leetspeak /
                                         spacing / misleading-caption attacks,
                                         template paraphrases, contrastive
                                         negation pairs, the hard-negative bank,
                                         and multilingual attack/benign banks
  - tools/training/corpus/ocr_captures.jsonl  real OCR over the rendered corpus

Held out entirely (never enters train/val), by exact normalized text AND by
near-duplicate (tools/training/_fuzzy.py, char-shingle Jaccard >= FUZZY_THRESHOLD):
  - tools/evaluation/corpus/prompt_text_corpus.jsonl   (the hand corpus)
  - tools/evaluation/corpus/domain_holdout.jsonl
  - tools/evaluation/corpus/heldout_benchmark.jsonl    (the independent benchmark)
  - the ADVERSARIAL_BENIGN probes in test_prompt_paraphrase_generalization.py

A split audit (leakage + balance) is written to manifest.json; --fail-on-leak
exits non-zero on any train/eval or train/val hard leak, and build_model.py
refuses to build a model on a leaky corpus.

Usage:
    python tools/training/assemble_training_corpus.py --out tools/training/corpus --fail-on-leak
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
from typing import Dict, List, Optional, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "evaluation"))
sys.path.insert(0, str(REPO_ROOT))

from tools.training._fuzzy import NearDupChecker  # noqa: E402

ARGUS_CORPUS = REPO_ROOT / "tools" / "evaluation" / "corpus" / "prompt_text_corpus.jsonl"
HELDOUT_BENCHMARK = REPO_ROOT / "tools" / "evaluation" / "corpus" / "heldout_benchmark.jsonl"
GENERALIZATION_TEST = REPO_ROOT / "tests" / "unit" / "test_prompt_paraphrase_generalization.py"

# Every text an evaluation harness scores. Nothing here — nor a near-duplicate of
# it — may enter train/val.
_EVAL_CORPORA = (ARGUS_CORPUS, ARGUS_CORPUS.with_name("domain_holdout.jsonl"), HELDOUT_BENCHMARK)

MAX_CHARS = 2000  # image OCR text is not 12k chars long
FUZZY_THRESHOLD = 0.72  # char-shingle Jaccard; a paraphrase/OCR-variant of an eval item lands above this


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text).lower()).strip()


def _eval_texts() -> list:
    texts = []
    for corpus_path in _EVAL_CORPORA:
        if not corpus_path.is_file():
            continue
        for line in corpus_path.read_text().splitlines():
            line = line.strip()
            if line:
                texts.append(json.loads(line)["text"])
    src = GENERALIZATION_TEST.read_text()
    block = re.search(r"ADVERSARIAL_BENIGN\s*=\s*\[(.*?)\]", src, re.S)
    if block:
        texts.extend(m.group(1) for m in re.finditer(r'"([^"]+)"', block.group(1)))
    return texts


def _holdout_keys() -> set:
    return {_norm(t) for t in _eval_texts()}


def _fuzzy_holdout() -> NearDupChecker:
    """Near-duplicate index over every evaluation text; ``.is_near(t)`` gates
    each candidate row on top of the exact ``_holdout_keys`` check."""
    return NearDupChecker(_eval_texts(), threshold=FUZZY_THRESHOLD)


# Public binary prompt-injection sets, all read from the local HF cache. The
# jayavibhav set (~262k train rows, ~47% injection, includes non-Latin-script
# rows) is the backbone; deepset + safe-guard are kept for their distinct
# chatbot-style phrasing. Only the *train* split of each is pulled — the
# jayavibhav *test* split is frozen separately as the held-out benchmark.
_PUBLIC_SETS = (
    ("deepset/prompt-injections", ("train",)),
    ("xTRam1/safe-guard-prompt-injection", ("train",)),
    ("jayavibhav/prompt-injection", ("train",)),
)


def _from_public(holdout: set, fuzzy: Optional[NearDupChecker] = None) -> List[Tuple[str, int, str]]:
    from datasets import load_dataset

    rows: List[Tuple[str, int, str]] = []
    dropped_fuzzy = 0
    for name, splits in _PUBLIC_SETS:
        ds = load_dataset(name)
        source_name = name.split("/")[-1]
        for split in splits:
            if split not in ds:
                continue
            texts = ds[split]["text"]          # column access — far faster than per-row dicts
            labels = ds[split]["label"]
            for raw, label in zip(texts, labels):
                text = (raw or "").strip()[:MAX_CHARS]
                if len(text) < 4 or _norm(text) in holdout:
                    continue
                if fuzzy is not None and fuzzy.is_near(text):
                    dropped_fuzzy += 1
                    continue
                group = hashlib.sha256(_norm(text).encode()).hexdigest()[:16]
                rows.append((text, int(label), "public:%s:%s" % (source_name, group)))
    if dropped_fuzzy:
        print("public: dropped %d rows as near-duplicates of an eval text" % dropped_fuzzy)
    return rows


def _from_synthetic(holdout: set, multiplier: int, seed: int,
                    fuzzy: Optional[NearDupChecker] = None) -> List[Tuple[str, int, str]]:
    import build_prompt_corpus as bpc

    rows: List[Tuple[str, int, str]] = []
    dropped_fuzzy = 0
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
            if _norm(text[:MAX_CHARS]) in holdout:
                continue
            if fuzzy is not None and fuzzy.is_near(text[:MAX_CHARS]):
                dropped_fuzzy += 1
                continue
            rows.append((text[:MAX_CHARS], 0 if not it.is_attack else 1, "synthetic:%s" % it.group))
    if dropped_fuzzy:
        print("synthetic: dropped %d rows as near-duplicates of an eval text" % dropped_fuzzy)
    return rows


def _from_ocr_captures(holdout: set, path: pathlib.Path,
                       fuzzy: Optional[NearDupChecker] = None) -> List[Tuple[str, int, str]]:
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
        if fuzzy is not None and fuzzy.is_near(text):
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


def _augment_training_rows(rows, excluded, seed, max_added=120000):
    """Add OCR-confusion / letter-transposition variants of short public rows so
    chatbot-style phrasing also appears in the image-OCR distribution. Capped
    (``max_added``) and applied to a deterministic shuffled subset so it does not
    balloon a large public pool."""
    import build_prompt_corpus as builder

    augmented = list(rows)
    seen = {_norm(text) for text, _, _ in rows} | excluded
    candidates = [r for r in rows if r[2].startswith("public:") and len(r[0]) <= 600]
    random.Random("aug-order:%s" % seed).shuffle(candidates)
    added = 0
    for text, label, source in candidates:
        if max_added and added >= max_added:
            break
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
                added += 1
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
    ap.add_argument("--max-public-per-class", type=int, default=50000,
                    help="cap rows drawn from public datasets per class (deterministic sample); "
                         "synthetic image-domain and real-OCR rows are never capped so they are "
                         "not drowned out. 0 = no cap.")
    ap.add_argument("--seed", type=int, default=20260908)
    ap.add_argument("--fail-on-leak", action="store_true",
                    help="exit non-zero if the split audit finds any train/eval or train/val leak")
    args = ap.parse_args(argv)

    random.seed(args.seed)
    holdout = _holdout_keys()
    fuzzy = _fuzzy_holdout()
    print("held out %d normalized texts + fuzzy index over %d eval texts"
          % (len(holdout), len(fuzzy)))

    rows = (_from_public(holdout, fuzzy)
            + _from_synthetic(holdout, args.synthetic_multiplier, args.seed, fuzzy)
            + _from_ocr_captures(holdout, args.ocr_captures, fuzzy))

    # dedup by normalized text, injection wins ties
    by_key: Dict[str, Tuple[str, int, str]] = {}
    for text, label, source in rows:
        k = _norm(text)
        if k in holdout:
            continue
        if k not in by_key or label > by_key[k][1]:
            by_key[k] = (text, label, source)
    rows = list(by_key.values())

    # Cap the public contribution per class (jayavibhav alone is ~260k rows and
    # would otherwise dilute the ARGUS-domain synthetic + real-OCR signal to a
    # fraction of a percent). Deterministic sample; synthetic / ocr_capture kept.
    if args.max_public_per_class:
        kept: List[Tuple[str, int, str]] = []
        for label in (0, 1):
            pub = [r for r in rows if r[1] == label and r[2].startswith("public:")]
            other = [r for r in rows if r[1] == label and not r[2].startswith("public:")]
            random.shuffle(pub)
            kept.extend(other + pub[: args.max_public_per_class])
        dropped = len(rows) - len(kept)
        if dropped:
            print("capped public rows: dropped %d (keeping <=%d public per class)"
                  % (dropped, args.max_public_per_class))
        rows = kept

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
    audit = _audit_splits(splits, seed=args.seed)
    manifest: Dict[str, object] = {"held_out": len(holdout), "max_chars": MAX_CHARS,
                                   "fuzzy_threshold": FUZZY_THRESHOLD, "audit": audit,
                                   "splits": {}}
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

    print("\n=== split audit ===")
    for key, value in audit.items():
        print("  %-28s %s" % (key, value))
    hard = (audit["shared_source_groups_train_val"]
            + audit["fuzzy_eval_in_train"]
            + audit["exact_eval_in_train"])
    if hard:
        print("\nLEAK: %d hard leak(s) — train shares content with an eval corpus or across splits" % hard)
        if args.fail_on_leak:
            return 1
    return 0


def _nonlatin_ratio(texts) -> float:
    n = sum(1 for t in texts if t and sum(ord(c) > 592 for c in t) >= 3)
    return round(n / max(len(texts), 1), 4)


def _audit_splits(splits, seed: int) -> Dict[str, object]:
    """Leakage + balance audit written into manifest.json. ``build_model.py``
    reads the hard-leak counters and refuses to build when any is non-zero."""
    train, val = splits["train"], splits["val"]
    train_groups = {s for _, _, s in train}
    val_groups = {s for _, _, s in val}
    shared = train_groups & val_groups

    train_texts = [t for t, _, _ in train]
    rng = random.Random(seed)
    val_sample = [t for t, _, _ in rng.sample(val, min(len(val), 4000))]
    train_sample = rng.sample(train_texts, min(len(train_texts), 25000))
    fuzzy_val = NearDupChecker(val_sample, threshold=FUZZY_THRESHOLD)
    fuzzy_val_hits = sum(1 for t in train_sample if fuzzy_val.is_near(t))

    eval_texts = _eval_texts()
    fuzzy_eval = NearDupChecker(eval_texts, threshold=FUZZY_THRESHOLD)
    eval_norm = {_norm(t) for t in eval_texts}
    # eval-in-train is a hard gate: scan every train row, not a sample.
    fuzzy_eval_hits = sum(1 for t in train_texts if fuzzy_eval.is_near(t))
    exact_eval_hits = sum(1 for t in train_texts if _norm(t) in eval_norm)

    by_src_train: Dict[str, int] = {}
    for _, _, s in train:
        by_src_train[s.split(":")[0]] = by_src_train.get(s.split(":")[0], 0) + 1

    return {
        "train_rows": len(train),
        "val_rows": len(val),
        "train_injection_frac": round(sum(l for _, l, _ in train) / max(len(train), 1), 4),
        "val_injection_frac": round(sum(l for _, l, _ in val) / max(len(val), 1), 4),
        "shared_source_groups_train_val": len(shared),
        "fuzzy_train_in_val_sample": fuzzy_val_hits,
        "fuzzy_train_in_val_sample_scanned": len(train_sample),
        "exact_eval_in_train": exact_eval_hits,
        "fuzzy_eval_in_train": fuzzy_eval_hits,
        "train_nonlatin_ratio": _nonlatin_ratio(train_texts),
        "val_nonlatin_ratio": _nonlatin_ratio([t for t, _, _ in val]),
        "train_by_source": by_src_train,
    }


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
