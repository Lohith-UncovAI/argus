#!/usr/bin/env python3
"""Run OCR over a labelled image corpus and emit (ocr_text, label) pairs for
classifier training.

This closes the gap the synthetic-augmentation corpus can only approximate: the
text the classifier actually sees at scan time is *real* OCR output — dropped
spaces, merged lines, confused glyphs, missing punctuation — not clean strings
with a simulated-corruption pass. Rendering an injection into an image and
reading it back with the same OCR stack the pipeline uses produces exactly that
distribution.

Input: a corpus directory + a JSONL manifest, one record per image with
`path` (relative), `labels` (list; "prompt_injection" => attack, otherwise
benign). The ARGUS eval corpus from tools/evaluation/generate_mac_corpus.py is
the reference format.

Output: `ocr_captures.jsonl` — {text, label, binary_label, source, image_id}.

Fold it into training by pointing assemble_training_corpus.py at it, or just
concatenate.

    python tools/training/extract_ocr_captures.py \
        --corpus ~/argus-eval-data/corpus \
        --manifest ~/argus-eval-data/manifests/argus-eval.jsonl \
        --out tools/training/corpus/ocr_captures.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import unicodedata

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

ATTACK_LABELS = {"prompt_injection", "jailbreak", "instruction_override",
                 "tool_invocation", "data_exfiltration", "policy_bypass",
                 "multilingual_injection", "compound_attack"}


def _norm(t: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", t).lower()).strip()


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=pathlib.Path, required=True)
    ap.add_argument("--manifest", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, default=REPO_ROOT / "tools" / "training" / "corpus" / "ocr_captures.jsonl")
    ap.add_argument("--easyocr-model-dir", default=os.environ.get("ARGUS_EASYOCR_MODEL_DIR", "").strip() or None)
    ap.add_argument("--merge-lines", action="store_true",
                    help="also emit the whole-image text (lines joined), not just per-line")
    args = ap.parse_args(argv)

    from argus_img.detectors.prompt.normalizer import normalize_text

    import easyocr
    reader = easyocr.Reader(["en"], model_storage_directory=args.easyocr_model_dir,
                            gpu=True, verbose=False,
                            download_enabled=args.easyocr_model_dir is None)

    records = [json.loads(l) for l in args.manifest.read_text().splitlines() if l.strip()]
    print("manifest: %d images" % len(records))

    seen: set = set()
    out_rows = []
    for i, rec in enumerate(records):
        img = args.corpus / rec["path"]
        if not img.is_file():
            continue
        labels = set(rec.get("labels", []))
        binary = 1 if labels & ATTACK_LABELS else 0
        try:
            lines = reader.readtext(str(img), detail=0)
        except Exception as exc:  # noqa: BLE001
            print("  ! %s: %s" % (rec.get("id"), exc))
            continue
        chunks = list(lines)
        if args.merge_lines and len(lines) > 1:
            chunks.append(" ".join(lines))
        for chunk in chunks:
            text = normalize_text(chunk).normalized
            k = _norm(text)
            if len(k) < 4 or k in seen:
                continue
            seen.add(k)
            out_rows.append({
                "id": "ocr-%05d" % len(out_rows),
                "text": text,
                "labels": ["instruction_override"] if binary else ["benign"],
                "label": "attack" if binary else "benign",
                "binary_label": binary,
                "source": "ocr_capture:%s" % rec.get("id", "?"),
                "image_id": rec.get("id"),
            })
        if (i + 1) % 50 == 0:
            print("  %d/%d images -> %d text rows" % (i + 1, len(records), len(out_rows)))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for r in out_rows:
            fh.write(json.dumps(r) + "\n")
    n_att = sum(r["binary_label"] for r in out_rows)
    print("\nwrote %d rows (attack=%d benign=%d) -> %s"
          % (len(out_rows), n_att, len(out_rows) - n_att, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
