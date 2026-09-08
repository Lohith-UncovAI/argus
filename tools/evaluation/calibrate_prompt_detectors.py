#!/usr/bin/env python3
"""Calibration harness for the prompt-injection text detectors.

ARGUS-IMG's prompt_injection detectors (rule engine + "semantic" scorer) are
hand-tuned: regex/token/bigram weights and the block/review thresholds
(THRESHOLD_BLOCK / THRESHOLD_REVIEW in detectors/prompt/semantic.py) were set
by inspecting individual failing cases, not by measuring precision/recall
against a labeled corpus. This script closes that gap for the text layer:

  1. Runs the real detector code (PromptRuleBundle + analyze_semantic, wired
     together the same way orchestration/pipeline.py wires them) against a
     labeled corpus (tools/evaluation/corpus/prompt_text_corpus.jsonl).
  2. Reports recall/false-positive-rate by corpus category, so the
     direct-match vs. paraphrase vs. OCR-garbled vs. obfuscated generalization
     gap is a number instead of a feeling.
  3. Independently sweeps score_text() thresholds to show where the current
     hardcoded THRESHOLD_BLOCK/THRESHOLD_REVIEW sit relative to the
     precision/recall-optimal operating point on this corpus.

This is a text-level corpus only. It does not require local OCR/VLM/malware
tools, so it can run anywhere the package imports. It does not replace the
existing image-level corpus in tools/evaluation/generate_mac_corpus.py, which
tests the full pipeline (OCR, transforms, policy, release grants) end to end.

Usage:
    PYTHONPATH=src python3 tools/evaluation/calibrate_prompt_detectors.py
"""
from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from argus_img.core.enums import PolicyAction
from argus_img.core.models import TextObservation
from argus_img.detectors.prompt.classify import analyze_classifier
from argus_img.detectors.prompt.classifier import (
    LocalTransformerClassifier,
    classifier_fingerprint,
    prompt_classifier_available,
)
from argus_img.detectors.prompt.decoders import derive_text_candidates
from argus_img.detectors.prompt.rules import PromptRuleBundle
from argus_img.detectors.prompt.semantic import (
    THRESHOLD_BLOCK,
    THRESHOLD_REVIEW,
    analyze_semantic,
    score_text,
)

_CLASSIFIER = LocalTransformerClassifier.from_env() if prompt_classifier_available() else None

CORPUS_PATH = REPO_ROOT / "tools" / "evaluation" / "corpus" / "prompt_text_corpus.jsonl"
RESULTS_DIR = REPO_ROOT / "tools" / "evaluation" / "results"


@dataclass
class CorpusItem:
    id: str
    text: str
    category: str
    label: str  # "attack" | "benign"
    context: str
    notes: str = ""


def load_corpus(path: pathlib.Path) -> List[CorpusItem]:
    items: List[CorpusItem] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            items.append(CorpusItem(**rec))
    return items


def _obs(item: CorpusItem) -> TextObservation:
    return TextObservation(
        observation_id="observation:calibration:%s" % item.id,
        source_artifact_id="artifact:calibration:%s" % item.id,
        detector_id="detector:calibration",
        raw_text=item.text,
        normalized_text=item.text,
        engine="calibration",
    )


@dataclass
class PipelineOutcome:
    rule_action: Optional[str]
    semantic_action: Optional[str]
    classifier_action: Optional[str]
    combined_action: Optional[str]  # None means "not flagged at all"
    raw_score: float
    classifier_score: Optional[float] = None


def run_pipeline(item: CorpusItem) -> PipelineOutcome:
    """Reproduce the rule -> semantic -> classifier wiring of orchestration/pipeline.py."""
    obs = _obs(item)
    derived = derive_text_candidates(obs)
    derived_map = {obs.observation_id: [d.text for d in derived]} if derived else {}
    rule_findings = PromptRuleBundle.load_default().analyze_texts(
        [obs], "calibration", derived_texts=derived_map)
    rule_action = _strongest_action(f.recommended_action for f in rule_findings) if rule_findings else None
    rule_covered_obs = {f.observation_ids[0] for f in rule_findings if f.observation_ids}

    semantic_findings = analyze_semantic([obs], "calibration", skip_observation_ids=rule_covered_obs)
    semantic_action = _strongest_action(f.recommended_action for f in semantic_findings) if semantic_findings else None

    classifier_action = None
    classifier_score = None
    if _CLASSIFIER is not None:
        corroborated = rule_covered_obs | {
            oid for f in rule_findings for oid in f.observation_ids
        } | {oid for f in semantic_findings for oid in f.observation_ids}
        clf_findings = analyze_classifier([obs], "calibration", classifier=_CLASSIFIER,
                                          skip_observation_ids=rule_covered_obs,
                                          corroborated_observation_ids=corroborated)
        classifier_action = _strongest_action(f.recommended_action for f in clf_findings) if clf_findings else None
        result = _CLASSIFIER.classify_sync(item.text)
        classifier_score = result.score if result.status == "SUCCESS" else None

    # The real pipeline collects findings from all three signals and the policy
    # engine takes the strongest — a classifier REVIEW never masks a semantic
    # BLOCK on the same text.
    _rank = {None: 0, "REVIEW": 1, "BLOCK": 2}
    combined = max((rule_action, classifier_action, semantic_action), key=lambda a: _rank.get(a, 0))
    return PipelineOutcome(
        rule_action=rule_action,
        semantic_action=semantic_action,
        classifier_action=classifier_action,
        combined_action=combined,
        raw_score=score_text(item.text)["score"],  # type: ignore[index]
        classifier_score=classifier_score,
    )


_ACTION_RANK = {PolicyAction.REVIEW: 1, PolicyAction.BLOCK: 2}


def _strongest_action(actions) -> Optional[str]:
    best = None
    best_rank = -1
    for action in actions:
        rank = _ACTION_RANK.get(action, 0)
        if rank > best_rank:
            best, best_rank = action.value, rank
    return best


def flagged(action: Optional[str]) -> bool:
    return action in ("BLOCK", "REVIEW")


def blocked(action: Optional[str]) -> bool:
    return action == "BLOCK"


# ---------------------------------------------------------------------------
# Section 1: end-to-end pipeline behaviour by corpus category
# ---------------------------------------------------------------------------

def report_pipeline_behaviour(items: List[CorpusItem]) -> Dict[str, object]:
    per_item = []
    for item in items:
        outcome = run_pipeline(item)
        per_item.append((item, outcome))

    by_category: Dict[str, Dict[str, int]] = {}
    misses: List[dict] = []
    false_positives: List[dict] = []

    classifier_on = _CLASSIFIER is not None

    for item, outcome in per_item:
        cat = by_category.setdefault(item.category, {"total": 0, "flagged": 0, "blocked": 0, "clf_flagged": 0})
        cat["total"] += 1
        if flagged(outcome.combined_action):
            cat["flagged"] += 1
        if blocked(outcome.combined_action):
            cat["blocked"] += 1
        if flagged(outcome.classifier_action):
            cat["clf_flagged"] += 1

        if item.label == "attack" and not flagged(outcome.combined_action):
            misses.append({
                "id": item.id, "category": item.category, "text": item.text,
                "rule_action": outcome.rule_action, "semantic_action": outcome.semantic_action,
                "classifier_action": outcome.classifier_action,
                "raw_score": round(outcome.raw_score, 3),
                "classifier_score": round(outcome.classifier_score, 3) if outcome.classifier_score is not None else None,
            })
        if item.label == "benign" and flagged(outcome.combined_action):
            false_positives.append({
                "id": item.id, "category": item.category, "text": item.text,
                "rule_action": outcome.rule_action, "semantic_action": outcome.semantic_action,
                "classifier_action": outcome.classifier_action,
                "combined_action": outcome.combined_action,
                "raw_score": round(outcome.raw_score, 3),
            })

    summary_lines = []
    wiring = "rule engine -> classifier -> semantic scorer" if classifier_on else "rule engine -> semantic scorer"
    summary_lines.append("=== Pipeline behaviour by corpus category (%s, as wired in orchestration/pipeline.py) ===" % wiring)
    if not classifier_on:
        summary_lines.append("(prompt classifier: not configured — set ARGUS_PROMPT_CLASSIFIER_PATH to include it)")
    header = "%-22s %6s %10s %10s" % ("category", "n", "flagged%", "blocked%")
    if classifier_on:
        header += " %12s" % "classifier%"
    summary_lines.append(header)
    for cat, counts in sorted(by_category.items()):
        n = counts["total"]
        row = "%-22s %6d %9.0f%% %9.0f%%" % (
            cat, n, 100.0 * counts["flagged"] / n, 100.0 * counts["blocked"] / n)
        if classifier_on:
            row += " %11.0f%%" % (100.0 * counts["clf_flagged"] / n)
        summary_lines.append(row)

    attack_items = [i for i in items if i.label == "attack"]
    benign_items = [i for i in items if i.label == "benign"]
    overall_recall = 100.0 * sum(1 for i, o in per_item if i.label == "attack" and flagged(o.combined_action)) / max(len(attack_items), 1)
    overall_fpr = 100.0 * sum(1 for i, o in per_item if i.label == "benign" and flagged(o.combined_action)) / max(len(benign_items), 1)

    summary_lines.append("")
    summary_lines.append("Overall recall on attack items (any flag):  %.1f%% (%d/%d)" % (overall_recall, sum(1 for i, o in per_item if i.label == 'attack' and flagged(o.combined_action)), len(attack_items)))
    summary_lines.append("Overall false-positive rate on benign items: %.1f%% (%d/%d)" % (overall_fpr, sum(1 for i, o in per_item if i.label == 'benign' and flagged(o.combined_action)), len(benign_items)))

    print("\n".join(summary_lines))

    print("\n--- Missed attacks (label=attack, not flagged at all) ---")
    if not misses:
        print("  (none)")
    for m in misses:
        print("  [%s/%s] score=%.2f rule=%s semantic=%s :: %s" % (
            m["category"], m["id"], m["raw_score"], m["rule_action"], m["semantic_action"], m["text"][:90]))

    print("\n--- False positives (label=benign, flagged) ---")
    if not false_positives:
        print("  (none)")
    for fp in false_positives:
        print("  [%s/%s] action=%s score=%.2f rule=%s semantic=%s :: %s" % (
            fp["category"], fp["id"], fp["combined_action"], fp["raw_score"],
            fp["rule_action"], fp["semantic_action"], fp["text"][:90]))

    return {
        "by_category": by_category,
        "overall_recall_pct": round(overall_recall, 1),
        "overall_false_positive_rate_pct": round(overall_fpr, 1),
        "missed_attacks": misses,
        "false_positives": false_positives,
    }


# ---------------------------------------------------------------------------
# Section 2: raw score_text() threshold sweep (signal quality, context-free)
# ---------------------------------------------------------------------------

def report_threshold_sweep(items: List[CorpusItem]) -> Dict[str, object]:
    # Positive class: all "attack" labeled items regardless of subtype.
    # Negative class: "benign" items that are NOT quoted/discussed attack text
    # (quoted/discussed text legitimately contains attack vocabulary; scoring
    # it high is a context-layer problem, not a raw-signal problem, so it is
    # excluded from this particular sweep and reported separately below).
    positives = [i for i in items if i.label == "attack"]
    negatives = [i for i in items if i.label == "benign" and i.category != "quoted_discussed"]
    scores = {i.id: score_text(i.text)["score"] for i in items}

    thresholds = [round(t * 0.05, 2) for t in range(1, 20)]
    rows = []
    best = None
    for t in thresholds:
        tp = sum(1 for i in positives if scores[i.id] >= t)
        fn = len(positives) - tp
        fp = sum(1 for i in negatives if scores[i.id] >= t)
        tn = len(negatives) - fp
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        rows.append({"threshold": t, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                      "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)})
        if best is None or f1 > best["f1"]:
            best = rows[-1]

    def metrics_at(t: float) -> dict:
        tp = sum(1 for i in positives if scores[i.id] >= t)
        fn = len(positives) - tp
        fp = sum(1 for i in negatives if scores[i.id] >= t)
        tn = len(negatives) - fp
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        return {"threshold": t, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}

    current_review = metrics_at(THRESHOLD_REVIEW)
    current_block = metrics_at(THRESHOLD_BLOCK)

    print("\n=== score_text() threshold sweep (positive=attack, n=%d; negative=benign excl. quoted/discussed, n=%d) ===" % (len(positives), len(negatives)))
    print("%8s %5s %5s %5s %5s %10s %8s %6s" % ("thresh", "tp", "fp", "fn", "tn", "precision", "recall", "f1"))
    for r in rows:
        marker = ""
        if abs(r["threshold"] - THRESHOLD_REVIEW) < 1e-9:
            marker += " <- current THRESHOLD_REVIEW"
        if abs(r["threshold"] - THRESHOLD_BLOCK) < 1e-9:
            marker += " <- current THRESHOLD_BLOCK"
        print("%8.2f %5d %5d %5d %5d %10.3f %8.3f %6.3f%s" % (
            r["threshold"], r["tp"], r["fp"], r["fn"], r["tn"], r["precision"], r["recall"], r["f1"], marker))

    print("\nCurrent THRESHOLD_REVIEW=%.2f -> precision=%.3f recall=%.3f f1=%.3f" % (
        THRESHOLD_REVIEW, current_review["precision"], current_review["recall"], current_review["f1"]))
    print("Current THRESHOLD_BLOCK=%.2f  -> precision=%.3f recall=%.3f f1=%.3f" % (
        THRESHOLD_BLOCK, current_block["precision"], current_block["recall"], current_block["f1"]))
    print("Best-F1 threshold on this corpus: %.2f (precision=%.3f recall=%.3f f1=%.3f)" % (
        best["threshold"], best["precision"], best["recall"], best["f1"]))

    # Context-layer check: quoted/discussed items should not end up BLOCKed by
    # the full pipeline even though their raw score_text() may be high.
    quoted_items = [i for i in items if i.category == "quoted_discussed"]
    quoted_outcomes = [(i, run_pipeline(i)) for i in quoted_items]
    quoted_blocked = [i for i, o in quoted_outcomes if blocked(o.combined_action)]
    print("\n=== Context layer: quoted/discussed attack-vocabulary text (n=%d) ===" % len(quoted_items))
    print("Incorrectly BLOCKed despite quoted/discussed context: %d/%d" % (len(quoted_blocked), len(quoted_items)))
    for i in quoted_blocked:
        print("  [%s] :: %s" % (i.id, i.text[:90]))

    return {
        "sweep": rows,
        "current_review_threshold_metrics": current_review,
        "current_block_threshold_metrics": current_block,
        "best_f1_threshold_metrics": best,
        "quoted_discussed_incorrectly_blocked": [i.id for i in quoted_blocked],
    }


# ---------------------------------------------------------------------------
# Section 3: local ML classifier threshold sweep (only when a model is configured)
# ---------------------------------------------------------------------------

def report_classifier_sweep(items: List[CorpusItem]) -> Optional[Dict[str, object]]:
    if _CLASSIFIER is None:
        print("\n=== Local ML classifier ===\nNot configured (ARGUS_PROMPT_CLASSIFIER_PATH unset) — skipping classifier sweep.")
        return None

    positives = [i for i in items if i.label == "attack"]
    negatives = [i for i in items if i.label == "benign" and i.category != "quoted_discussed"]
    quoted = [i for i in items if i.category == "quoted_discussed"]

    def clf_score(text: str) -> float:
        r = _CLASSIFIER.classify_sync(text)
        return r.score if r.status == "SUCCESS" else 0.0

    scores = {i.id: clf_score(i.text) for i in items}
    thresholds = [round(t * 0.05, 2) for t in range(1, 20)]
    rows = []
    best = None
    for t in thresholds:
        tp = sum(1 for i in positives if scores[i.id] >= t)
        fp = sum(1 for i in negatives if scores[i.id] >= t)
        fn = len(positives) - tp
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        rows.append({"threshold": t, "tp": tp, "fp": fp, "fn": fn,
                     "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)})
        if best is None or f1 > best["f1"]:
            best = rows[-1]

    src = getattr(_CLASSIFIER, "model_dir", "?")
    lm = getattr(_CLASSIFIER, "label_map", None)
    print("\n=== Local ML classifier threshold sweep (model=%s; positive=attack n=%d, negative=benign excl. quoted n=%d) ===" % (src, len(positives), len(negatives)))
    print("fingerprint=%s  problem_type=%s  calibration=%s  thresholds(block/review)=%.2f/%.2f" % (
        classifier_fingerprint(getattr(_CLASSIFIER, "model_dir", None)),
        getattr(lm, "problem_type", "?"),
        getattr(getattr(lm, "calibration", None), "method", "none"),
        getattr(lm, "threshold_block", 0.0), getattr(lm, "threshold_review", 0.0)))
    print("%8s %5s %5s %5s %10s %8s %6s" % ("thresh", "tp", "fp", "fn", "precision", "recall", "f1"))
    for r in rows:
        print("%8.2f %5d %5d %5d %10.3f %8.3f %6.3f" % (
            r["threshold"], r["tp"], r["fp"], r["fn"], r["precision"], r["recall"], r["f1"]))
    print("Best-F1 classifier threshold on this corpus: %.2f (precision=%.3f recall=%.3f f1=%.3f)" % (
        best["threshold"], best["precision"], best["recall"], best["f1"]))
    quoted_hi = [i.id for i in quoted if scores[i.id] >= 0.5]
    print("Quoted/discussed items scored >=0.50 by the raw model: %d/%d %s" % (
        len(quoted_hi), len(quoted), quoted_hi or ""))
    return {"sweep": rows, "best_f1_threshold_metrics": best,
            "quoted_discussed_high_raw_score": quoted_hi}


def main() -> None:
    items = load_corpus(CORPUS_PATH)
    print("Loaded %d labeled corpus items from %s\n" % (len(items), CORPUS_PATH.relative_to(REPO_ROOT)))

    pipeline_report = report_pipeline_behaviour(items)
    sweep_report = report_threshold_sweep(items)
    classifier_report = report_classifier_sweep(items)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "prompt_calibration_report.json"
    out_path.write_text(json.dumps({
        "classifier_configured": _CLASSIFIER is not None,
        "classifier_sweep": classifier_report,
        "corpus_path": str(CORPUS_PATH.relative_to(REPO_ROOT)),
        "corpus_size": len(items),
        "pipeline_behaviour": pipeline_report,
        "threshold_sweep": sweep_report,
    }, indent=2))
    print("\nFull report written to %s" % out_path.relative_to(REPO_ROOT))


if __name__ == "__main__":
    main()
