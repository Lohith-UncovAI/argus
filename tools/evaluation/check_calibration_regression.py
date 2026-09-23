#!/usr/bin/env python3
"""CI regression gate for the deterministic prompt-injection layers.

``calibrate_prompt_detectors.py`` measures the rule engine + heuristic scorer
(and, when configured, the ML classifier) against the hand-labeled corpus. This
wrapper runs *only the deterministic layers* — no model weights, so it runs on a
stock CI runner — and compares the per-category behaviour against a checked-in
baseline (``tools/evaluation/corpus/expected_calibration.json``).

It fails (exit 1) when, versus the baseline:
  * overall attack recall drops, or overall benign false-positive rate rises;
  * any attack category flags fewer items;
  * any benign category flags or blocks more items.

Regenerate the baseline deliberately (after an intended behaviour change or a
corpus edit) with ``--update``.

    PYTHONPATH=src python tools/evaluation/check_calibration_regression.py
    PYTHONPATH=src python tools/evaluation/check_calibration_regression.py --update
"""
from __future__ import annotations

import argparse
import io
import json
import pathlib
import sys
from contextlib import redirect_stdout

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
for _p in (str(REPO_ROOT), str(REPO_ROOT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

BASELINE = REPO_ROOT / "tools" / "evaluation" / "corpus" / "expected_calibration.json"
ATTACK_CATEGORIES = {
    "direct_attack", "paraphrased_attack", "obfuscated_attack", "garbled_ocr_attack",
    "compound_attack", "tiled_split_attack", "multilingual_attack",
}


def _measure() -> dict:
    from tools.evaluation import calibrate_prompt_detectors as cal

    if cal._CLASSIFIER is not None:
        raise SystemExit("ARGUS_PROMPT_CLASSIFIER_PATH must be unset for the deterministic gate")
    items = cal.load_corpus(cal.CORPUS_PATH)
    with redirect_stdout(io.StringIO()):
        report = cal.report_pipeline_behaviour(items)
    return {
        "corpus_size": len(items),
        "overall_recall_pct": report["overall_recall_pct"],
        "overall_false_positive_rate_pct": report["overall_false_positive_rate_pct"],
        "by_category": {c: {"total": v["total"], "flagged": v["flagged"], "blocked": v["blocked"]}
                        for c, v in sorted(report["by_category"].items())},
    }


def _diff(current: dict, baseline: dict) -> list:
    problems = []
    if current["overall_recall_pct"] < baseline["overall_recall_pct"] - 1e-6:
        problems.append("overall attack recall %.1f%% < baseline %.1f%%"
                        % (current["overall_recall_pct"], baseline["overall_recall_pct"]))
    if current["overall_false_positive_rate_pct"] > baseline["overall_false_positive_rate_pct"] + 1e-6:
        problems.append("overall benign FP rate %.1f%% > baseline %.1f%%"
                        % (current["overall_false_positive_rate_pct"], baseline["overall_false_positive_rate_pct"]))
    for cat, base in baseline["by_category"].items():
        cur = current["by_category"].get(cat)
        if cur is None:
            problems.append("category %s disappeared from the corpus" % cat)
            continue
        if cur["total"] != base["total"]:
            problems.append("category %s size changed %d -> %d (regenerate baseline with --update)"
                            % (cat, base["total"], cur["total"]))
        if cat in ATTACK_CATEGORIES:
            if cur["flagged"] < base["flagged"]:
                problems.append("attack category %s flags %d < baseline %d"
                                % (cat, cur["flagged"], base["flagged"]))
        else:
            if cur["flagged"] > base["flagged"]:
                problems.append("benign category %s flags %d > baseline %d"
                                % (cat, cur["flagged"], base["flagged"]))
            if cur["blocked"] > base["blocked"]:
                problems.append("benign category %s BLOCKs %d > baseline %d"
                                % (cat, cur["blocked"], base["blocked"]))
    return problems


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--update", action="store_true", help="overwrite the baseline with current measurements")
    ap.add_argument("--baseline", type=pathlib.Path, default=BASELINE)
    args = ap.parse_args(argv)

    current = _measure()
    if args.update:
        args.baseline.write_text(json.dumps(current, indent=2) + "\n")
        print("wrote baseline -> %s" % args.baseline.relative_to(REPO_ROOT))
        print(json.dumps(current, indent=2))
        return 0

    if not args.baseline.is_file():
        raise SystemExit("no baseline at %s — create it with --update" % args.baseline)
    baseline = json.loads(args.baseline.read_text())
    problems = _diff(current, baseline)
    print("deterministic prompt-layer calibration: overall recall %.1f%% (baseline %.1f%%), "
          "FP %.1f%% (baseline %.1f%%)"
          % (current["overall_recall_pct"], baseline["overall_recall_pct"],
             current["overall_false_positive_rate_pct"], baseline["overall_false_positive_rate_pct"]))
    if problems:
        print("\nREGRESSION:")
        for p in problems:
            print("  - " + p)
        return 1
    print("no regression vs baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
