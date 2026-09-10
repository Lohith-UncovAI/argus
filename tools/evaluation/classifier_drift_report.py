#!/usr/bin/env python3
"""Compare a production classifier score log against the model's evaluation-time
baseline and flag distribution drift.

Input:
  * ``--score-log``  a JSONL written by the scan-time hook
    (``ARGUS_PROMPT_CLASSIFIER_SCORE_LOG``); one row per scored observation,
    fields ``score`` / ``action`` / ``model_fingerprint`` / ``ts``.
  * ``--baseline``   ``EVAL_SUMMARY.json`` written next to the model at build
    time (``score_baseline`` block: benign score deciles + flag rate on the
    held-out benchmark). Defaults to ``$ARGUS_PROMPT_CLASSIFIER_PATH/EVAL_SUMMARY.json``.

Output: mean / median / p95 score, flag (REVIEW+BLOCK) rate, a two-sample
Kolmogorov-Smirnov statistic between the production score CDF and the baseline
benign score CDF, and a verdict. Exit 1 when drift crosses a threshold — wire it
into a periodic job.

    python tools/evaluation/classifier_drift_report.py --score-log /var/log/argus/pi_scores.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import statistics
import sys

# Production traffic is mostly benign with a thin tail of real attacks, so the
# stable quantity to watch is the *benign bulk*: the median prod score should sit
# well below the eval benign p95. If the middle of the distribution climbs, the
# model is miscalibrated on this traffic or the input distribution shifted.
DEF_FLAG_RATE_ALERT = 0.30   # prod flag rate this far above the eval benign FP rate => investigate
DEF_MEDIAN_ALERT_MULT = 1.0  # prod p50 above (eval benign p95 * this) => drift


def _load_scores(path: pathlib.Path):
    scores, actions, fps = [], [], set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if "score" not in row:
            continue
        scores.append(float(row["score"]))
        actions.append(row.get("action", "none"))
        if row.get("model_fingerprint"):
            fps.add(row["model_fingerprint"])
    return scores, actions, fps


def _ks_vs_deciles(scores, baseline_deciles) -> float:
    """KS-style statistic between the empirical CDF of ``scores`` and the baseline
    benign CDF described by 11 quantile points. Informational only — production
    traffic is not the eval benign mix, so a nonzero value is expected."""
    if not scores or not baseline_deciles or len(baseline_deciles) < 2:
        return 0.0
    qs = [i / (len(baseline_deciles) - 1) for i in range(len(baseline_deciles))]
    s = sorted(scores)
    n = len(s)
    return round(max(abs(sum(1 for x in s if x <= v) / n - q)
                     for v, q in zip(baseline_deciles, qs)), 4)


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--score-log", type=pathlib.Path, required=True)
    ap.add_argument("--baseline", type=pathlib.Path, default=None)
    ap.add_argument("--flag-rate-alert", type=float, default=DEF_FLAG_RATE_ALERT)
    ap.add_argument("--median-alert-mult", type=float, default=DEF_MEDIAN_ALERT_MULT)
    ap.add_argument("--min-samples", type=int, default=200)
    args = ap.parse_args(argv)

    if not args.score_log.is_file():
        raise SystemExit("no score log at %s" % args.score_log)
    scores, actions, fps = _load_scores(args.score_log)
    if len(scores) < args.min_samples:
        print("only %d scored observations (< --min-samples %d); not enough to judge drift"
              % (len(scores), args.min_samples))
        return 0

    baseline_path = args.baseline
    if baseline_path is None:
        env = os.environ.get("ARGUS_PROMPT_CLASSIFIER_PATH", "").strip()
        baseline_path = pathlib.Path(env) / "EVAL_SUMMARY.json" if env else None
    baseline = {}
    if baseline_path and baseline_path.is_file():
        baseline = json.loads(baseline_path.read_text()).get("score_baseline", {})

    flag_rate = sum(1 for a in actions if a in ("REVIEW", "BLOCK")) / len(actions)
    block_rate = sum(1 for a in actions if a == "BLOCK") / len(actions)
    ss = sorted(scores)
    p50 = ss[min(len(ss) - 1, int(0.50 * len(ss)))]
    p95 = ss[min(len(ss) - 1, int(0.95 * len(ss)))]

    print("=== prompt-classifier drift report ===")
    print("score log:            %s" % args.score_log)
    print("scored observations:  %d" % len(scores))
    print("model fingerprints:   %s" % (", ".join(sorted(fps)) or "(none recorded)"))
    print("score mean/median/p95: %.3f / %.3f / %.3f"
          % (statistics.fmean(scores), statistics.median(scores), p95))
    print("flag rate (REVIEW+BLOCK): %.1f%%   BLOCK rate: %.1f%%" % (100 * flag_rate, 100 * block_rate))

    problems = []
    if not baseline:
        print("\nno baseline (EVAL_SUMMARY.json) — reporting distribution only, no drift verdict")
        return 0

    base_fp = float(baseline.get("benign_fp_at_review", 0.0))
    base_p95 = float(baseline.get("benign_score_p95", 0.0))
    ks = _ks_vs_deciles(scores, baseline.get("benign_score_quantiles") or [])
    median_limit = base_p95 * args.median_alert_mult + 0.02
    print("\nbaseline (eval benign): FP@review %.1f%%   p95 score %.3f   fingerprint %s"
          % (100 * base_fp, base_p95, baseline.get("model_fingerprint", "?")))
    print("prod median score %.3f  (drift if > %.3f = eval benign p95 x %.1f)"
          % (p50, median_limit, args.median_alert_mult))
    print("prod flag rate %.1f%% vs eval benign FP %.1f%%  (investigate if +%.0f pp)  |  KS %.3f (informational)"
          % (100 * flag_rate, 100 * base_fp, 100 * args.flag_rate_alert, ks))

    if baseline.get("model_fingerprint") and fps and baseline["model_fingerprint"] not in fps:
        problems.append("score log fingerprint(s) do not match the baseline model — comparing different models")
    if base_p95 > 0 and p50 > median_limit:
        problems.append("prod median score %.3f above eval benign p95 %.3f — distribution shifted up"
                        % (p50, base_p95))
    if flag_rate - base_fp >= args.flag_rate_alert:
        problems.append("prod flag rate %.1f%% is %.1f pp above the eval benign FP rate"
                        % (100 * flag_rate, 100 * (flag_rate - base_fp)))

    if problems:
        print("\nDRIFT DETECTED:")
        for p in problems:
            print("  - " + p)
        return 1
    print("\nno significant drift.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
