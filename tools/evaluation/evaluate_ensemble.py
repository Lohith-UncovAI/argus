#!/usr/bin/env python3
"""Evaluate an ensemble of local prompt-injection classifiers.

Motivation: 9+ single-model training configurations (see
docs/prompt-classifier-releases.md) all plateaued in the same 0.80-0.94
classifier-solo recall / 3-8 FP band. Several of the observed false positives
were borderline / inconsistent across configs — exactly the failure mode
ensembling addresses: combine N independently-trained models (different seeds)
and require agreement before trusting a solo hit, which should cut
variance-driven FPs without giving up much recall.

Combination rules:
  * mean       — average the per-model scores
  * max        — most alarming model wins (recall-favoring)
  * min        — least alarming model wins (precision-favoring)
  * vote:K     — score = fraction of models scoring >= the sweep threshold;
                 K members must agree (informational; reported at fixed 0.5)

Usage:
    python tools/evaluation/evaluate_ensemble.py \
        --model models/pi-argus-v11 --model models/pi-argus-ens-b \
        --model models/pi-argus-ens-c --backend onnx
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Dict, List

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from argus_img.detectors.prompt.classifier import LocalTransformerClassifier  # noqa: E402

CORPUS_PATH = REPO_ROOT / "tools" / "evaluation" / "corpus" / "prompt_text_corpus.jsonl"
BENCHMARK_PATH = REPO_ROOT / "tools" / "evaluation" / "corpus" / "heldout_benchmark.jsonl"


def _load_corpus(path: pathlib.Path) -> List[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _score_all(models: List[LocalTransformerClassifier], items: List[dict]) -> List[List[float]]:
    """Return per-item list of per-model scores."""
    out = []
    for item in items:
        row = []
        for clf in models:
            r = clf.classify_sync(item["text"])
            row.append(r.score if r.status == "SUCCESS" else float("nan"))
        out.append(row)
    return out


def _combine(scores: List[float], rule: str) -> float:
    valid = [s for s in scores if s == s]  # drop NaN
    if not valid:
        return 0.0
    if rule == "mean":
        return sum(valid) / len(valid)
    if rule == "max":
        return max(valid)
    if rule == "min":
        return min(valid)
    raise ValueError("unknown combination rule: %s" % rule)


def _sweep(pos: List[float], neg: List[float]) -> List[dict]:
    thresholds = [round(t * 0.05, 2) for t in range(1, 20)]
    rows = []
    for t in thresholds:
        tp = sum(1 for s in pos if s >= t)
        fn = len(pos) - tp
        fp = sum(1 for s in neg if s >= t)
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        rows.append({"threshold": t, "tp": tp, "fp": fp, "fn": fn,
                     "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)})
    return rows


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", action="append", required=True, dest="models",
                    help="model directory; pass 2+ times for an ensemble")
    ap.add_argument("--backend", default="onnx", choices=["onnx", "transformers"])
    ap.add_argument("--corpus", type=pathlib.Path, default=CORPUS_PATH)
    ap.add_argument("--benchmark", type=pathlib.Path, default=BENCHMARK_PATH)
    ap.add_argument("--rules", nargs="+", default=["mean", "max", "min"])
    ap.add_argument("--output", type=pathlib.Path, default=None)
    args = ap.parse_args(argv)

    print("Loading %d model(s): %s" % (len(args.models), ", ".join(args.models)))
    from argus_img.detectors.prompt.classifier import load_label_map
    models = []
    for m in args.models:
        model_dir = pathlib.Path(m).resolve()
        lm = load_label_map(model_dir, None)
        models.append(LocalTransformerClassifier(model_dir, lm, backend=args.backend))

    corpus = _load_corpus(args.corpus)
    pos_items = [c for c in corpus if c["label"] == "attack"]
    neg_items = [c for c in corpus if c["label"] == "benign" and c["category"] != "quoted_discussed"]

    print("Scoring %d corpus items x %d models..." % (len(corpus), len(models)))
    pos_scores_per_model = _score_all(models, pos_items)
    neg_scores_per_model = _score_all(models, neg_items)

    report: Dict[str, object] = {"models": args.models, "n_attack": len(pos_items), "n_benign": len(neg_items)}
    print("\n=== ARGUS hand corpus (n_attack=%d, n_benign excl. quoted/discussed=%d) ===" % (len(pos_items), len(neg_items)))
    for rule in args.rules:
        pos = [_combine(row, rule) for row in pos_scores_per_model]
        neg = [_combine(row, rule) for row in neg_scores_per_model]
        sweep = _sweep(pos, neg)
        best_f1 = max(sweep, key=lambda r: r["f1"])
        # operating point: smallest threshold with fp <= 2 (the actual floor)
        clean = [r for r in sweep if r["fp"] <= 2]
        best_clean = max(clean, key=lambda r: r["recall"]) if clean else None
        print("\n--- combine=%s ---" % rule)
        print("%8s %5s %5s %5s %10s %8s %6s" % ("thresh", "tp", "fp", "fn", "precision", "recall", "f1"))
        for r in sweep:
            marker = " <- best F1" if r == best_f1 else (" <- best recall @ fp<=2" if best_clean and r == best_clean else "")
            print("%8.2f %5d %5d %5d %10.3f %8.3f %6.3f%s" % (
                r["threshold"], r["tp"], r["fp"], r["fn"], r["precision"], r["recall"], r["f1"], marker))
        report[rule] = {"sweep": sweep, "best_f1": best_f1, "best_recall_at_fp_le_2": best_clean}

    if args.benchmark.is_file():
        bench = _load_corpus(args.benchmark)
        bpos = [c for c in bench if c["label"] == "attack"]
        bneg = [c for c in bench if c["label"] == "benign"]
        print("\n=== held-out benchmark (n_attack=%d, n_benign=%d) ===" % (len(bpos), len(bneg)))
        bpos_scores = _score_all(models, bpos)
        bneg_scores = _score_all(models, bneg)
        report["benchmark"] = {}
        for rule in args.rules:
            pos = [_combine(row, rule) for row in bpos_scores]
            neg = [_combine(row, rule) for row in bneg_scores]
            sn = sorted(neg)
            thr_1pct = sn[min(len(sn) - 1, int(0.99 * len(sn)))]
            recall_1pct = sum(1 for s in pos if s >= thr_1pct) / len(pos)
            print("combine=%-5s recall@1%%FP=%.3f (thr=%.3f)" % (rule, recall_1pct, thr_1pct))
            report["benchmark"][rule] = {"recall_at_1pct_fp": round(recall_1pct, 4), "threshold": round(thr_1pct, 4)}

    if args.output:
        args.output.write_text(json.dumps(report, indent=2))
        print("\nwrote %s" % args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
