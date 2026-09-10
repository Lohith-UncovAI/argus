"""Pipeline adapter: run the optional local prompt-injection classifier over
text observations and emit ``DetectorFinding``s.

Wired into ``orchestration/pipeline.py`` as the "configured prompt-classifier
adapter" step (plan.md §19.2 / pipeline step 18), between the deterministic rule
bundle and the privacy detector, after the heuristic semantic scorer.

Design invariants:
  * The classifier is *evidence only*. Findings cap at ``HIGHLY_LIKELY`` —
    ``CONFIRMED`` is reserved for the deterministic rule engine. The policy
    engine makes the actual BLOCK/REVIEW/allow decision.
  * Same context gate as the other two prompt signals: text classified as
    quoted / discussed / warning (security-education framing) is skipped.
  * Observations already conclusively handled by the rule engine are skipped to
    avoid duplicate findings.
  * If no local model is configured the adapter is never called (the pipeline
    checks ``prompt_classifier_available()`` first); when called with a Null or
    erroring classifier it simply returns ``[]``.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Dict, List, Optional

from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.models import DetectorFinding, TextObservation
from argus_img.detectors.prompt.classifier import (
    THRESHOLD_BLOCK,
    THRESHOLD_REVIEW,
    LocalTransformerClassifier,
    PromptClassification,
    classifier_fingerprint,
)
from argus_img.detectors.prompt.decoders import prefer_corrected_transcriptions
from argus_img.detectors.prompt.intent import classify_text_context

_DETECTOR_ID = "detector:prompt-classifier"

# Aggressive channel/contrast transforms turn a clean image into OCR gibberish
# ("Quareni} cashone Voldde) jsluDti@jur"); the model's score on non-words is
# not evidence. Candidates below the prose bar are dropped. Genuinely garbled
# attacks are recovered by the leetspeak fold / word re-segmentation / OCR
# spell repair, whose readable output clears the bar and feeds the rules.
_MIN_PROSE_RATIO = 0.40
_MIN_PROSE_TOKENS = 3

_logger = logging.getLogger(__name__)
# Opt-in production drift signal. When ``ARGUS_PROMPT_CLASSIFIER_SCORE_LOG`` names
# a writable path, every scored observation appends one JSON line (no raw text) —
# score distribution + flag rate over time, compared against the eval baseline by
# tools/evaluation/classifier_drift_report.py. Best-effort: a logging failure
# must never disturb a scan.
_SCORE_LOG_ENV = "ARGUS_PROMPT_CLASSIFIER_SCORE_LOG"


def _log_score(fingerprint, result, corroborated, thr_block, thr_review, text_len) -> None:
    path = os.environ.get(_SCORE_LOG_ENV, "").strip()
    if not path:
        return
    try:
        blocked = result.score >= thr_block and corroborated
        review = result.score >= thr_review and not blocked
        row = {
            "ts": round(time.time(), 3),
            "model_fingerprint": fingerprint,
            "score": round(float(result.score), 4),
            "label": result.label,
            "corroborated": bool(corroborated),
            "action": "BLOCK" if blocked else ("REVIEW" if review else "none"),
            "text_length": int(text_len),
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    except Exception as exc:  # noqa: BLE001 — drift logging must not break a scan
        _logger.debug("prompt classifier score-log write failed: %s", exc)


def _prose_ratio(text: str) -> float:
    """Fraction of ASCII-Latin word tokens that are real English words.

    Only meaningful for predominantly-ASCII-Latin text — the failure mode it
    guards against is aggressive-transform gibberish ("Quareni} cashone Voldde)
    jsluDti@jur"), which is ASCII. Non-Latin scripts and heavily-accented text
    (French/German/… injections, Arabic/CJK/Cyrillic) are not gibberish just
    because they are not in an English dictionary, so they are not gated here —
    the negation-trained model plus the corroboration rule handle their FPs.
    """
    try:
        import wordninja
        vocab = wordninja.DEFAULT_LANGUAGE_MODEL._wordcost
    except Exception:  # noqa: BLE001
        return 1.0
    import re
    letters = [c for c in text if c.isalpha()]
    if letters and sum(c.isascii() for c in letters) / len(letters) < 0.75:
        return 1.0  # substantial non-ASCII script — English dictionary does not apply
    toks = re.findall(r"[A-Za-z]{2,}", text)
    if len(toks) < _MIN_PROSE_TOKENS:
        return 1.0
    english = sum(1 for t in toks if t.lower() in vocab) / len(toks)
    if english >= _MIN_PROSE_RATIO:
        return english
    # Below the English bar: gate only when the text also *looks* mangled —
    # symbols wedged into words, digit/letter mixing, mid-word case flips.
    # Ordinary non-English prose (German, Dutch, Italian, …) is not mangled and
    # should reach the model. Real transform gibberish ("Voldde) jsluDti@jur")
    # trips at least one of these.
    body = re.sub(r"\s+", "", text)
    if not body:
        return english
    noise = sum(1 for c in body if not c.isalnum()) / len(body)
    digit_words = sum(1 for t in re.findall(r"\S+", text)
                      if re.search(r"[A-Za-z]", t) and re.search(r"\d", t)) / max(len(toks), 1)
    # "clean shape" = all-lower, Title-case, or ALL-CAPS. Real words in any Latin
    # script take one of these; transform gibberish ("jOuIIAIVAIoue", "IMZImttz")
    # does not. Also flag vowel-less / hyper-consonantal tokens.
    def _clean(t: str) -> bool:
        return (t.islower() or t.istitle() or t.isupper()) and not re.search(r"[bcdfghjklmnpqrstvwxz]{5,}", t.lower())
    clean_ratio = sum(1 for t in toks if _clean(t)) / len(toks)
    mangled = noise > 0.12 or digit_words > 0.25 or clean_ratio < 0.6
    # Not mangled → ordinary (possibly non-English) prose: let it reach the model.
    # Mangled → transform gibberish: keep it gated out.
    return min(english, _MIN_PROSE_RATIO - 0.01) if mangled else max(english, _MIN_PROSE_RATIO)


def analyze_classifier(
    observations: List[TextObservation],
    scan_id: str,
    classifier: Optional[object] = None,
    include_raw_text: bool = False,
    skip_observation_ids: Optional[set] = None,
    corroborated_observation_ids: Optional[set] = None,
    derived_texts: Optional[dict] = None,
    errors: Optional[List[str]] = None,
) -> List[DetectorFinding]:
    """Score text observations with the local ML classifier.

    corroborated_observation_ids: observations that the deterministic rules or
    the heuristic scorer already flagged. A classifier BLOCK on an observation
    NOT in this set is emitted as REVIEW instead — a lone, uncorroborated model
    prediction (often on OCR-garbled text) is the least trustworthy case and
    must not single-handedly BLOCK an image.
    derived_texts: decoder candidates (leetspeak fold, word re-segmentation,
    base64, ...) keyed by observation id — scored alongside the observation's
    own text; the highest-scoring candidate wins (a de-obfuscated attack scores
    higher; a benign FP is left to the negation-trained model + corroboration).
    """
    clf = classifier or LocalTransformerClassifier.from_env()
    if clf is None:
        return []
    corroborated = corroborated_observation_ids or set()
    derived_texts = derived_texts or {}

    label_map = getattr(clf, "label_map", None)
    thr_block = getattr(label_map, "threshold_block", THRESHOLD_BLOCK)
    thr_review = getattr(label_map, "threshold_review", THRESHOLD_REVIEW)
    calibration = getattr(label_map, "calibration", None)
    fingerprint = classifier_fingerprint(getattr(clf, "model_dir", None))

    findings: List[DetectorFinding] = []
    seen_texts: set = set()

    for obs in observations:
        if skip_observation_ids and obs.observation_id in skip_observation_ids:
            continue
        text = obs.normalized_text
        if not text or text in seen_texts:
            continue
        seen_texts.add(text)

        candidates = prefer_corrected_transcriptions(
            [text] + [d for d in derived_texts.get(obs.observation_id, []) if d and d != text])
        if any(classify_text_context(c) in ("quoted", "discussed", "warning") for c in candidates):
            continue

        scored = []
        for c in candidates:
            r = clf.classify_sync(c)
            if r.status != "SUCCESS":
                if errors is not None:
                    errors.append(r.reason or r.status)
                continue
            if _prose_ratio(c) < _MIN_PROSE_RATIO:
                continue
            scored.append(r)
        if not scored:
            continue
        result: PromptClassification = max(scored, key=lambda r: r.score)

        corroborated_here = obs.observation_id in corroborated
        _log_score(fingerprint, result, corroborated_here, thr_block, thr_review, len(text))
        if result.score < thr_review:
            continue

        active = result.score >= thr_block and corroborated_here
        downgraded = result.score >= thr_block and not corroborated_here
        spec_reason_codes = _reason_codes_for(clf, result.label)

        state = EpistemicState.HIGHLY_LIKELY if active else EpistemicState.POSSIBLE
        action = PolicyAction.BLOCK if active else PolicyAction.REVIEW
        severity = _severity_for(clf, result.label, active)
        likelihood = round(min(result.score, 0.95), 3)

        evidence: Dict[str, object] = {
            "classifier_score": round(result.score, 4),
            "classifier_label": result.label,
            "per_label": {k: round(v, 4) for k, v in result.per_label.items()},
            "model_source": result.model_source,
            "model_fingerprint": fingerprint,
            "calibration": getattr(calibration, "method", "none"),
            "windows_scored": result.windows,
            "threshold_block": thr_block,
            "threshold_review": thr_review,
            "corroborated_by_rules_or_semantic": corroborated_here,
            "downgraded_to_review_uncorroborated": downgraded,
            "text_length": len(text),
            "full_text_returned": False,
            "forensic_evidence_required": True,
        }
        if include_raw_text:
            evidence["raw_text"] = text

        findings.append(DetectorFinding(
            finding_id="finding:%s:classifier:%03d" % (scan_id, len(findings)),
            category="prompt_injection",
            type="model_injection",
            state=state,
            severity=severity,
            detector_confidence=result.score,
            evidence_quality=0.75 if active else 0.5,
            attack_likelihood=likelihood,
            impact="critical" if active else "medium",
            source_artifact_ids=[obs.source_artifact_id],
            observation_ids=[obs.observation_id],
            detector_ids=[_DETECTOR_ID],
            reason_codes=sorted(set(spec_reason_codes) | {"PROMPT_INJECTION"}),
            recommended_action=action,
            limitations=[
                "ML classifier output is a probability, not proof; findings cap at "
                "HIGHLY_LIKELY. A BLOCK-level score is emitted as REVIEW unless the "
                "rules or the heuristic scorer independently flagged the same text.",
                "Model runs offline on CPU against a local checkpoint; it reflects its "
                "training distribution and may miss novel phrasings or misfire on "
                "security-education content or OCR-garbled benign text.",
            ],
            evidence=evidence,
        ))

    return findings


def _reason_codes_for(clf: object, label_name: str) -> tuple:
    label_map = getattr(clf, "label_map", None)
    if label_map is not None:
        for spec in label_map.labels.values():
            if spec.name == label_name and not spec.benign:
                return spec.reason_codes
    return ("PROMPT_INJECTION",)


def _severity_for(clf: object, label_name: str, active: bool) -> str:
    label_map = getattr(clf, "label_map", None)
    if label_map is not None:
        for spec in label_map.labels.values():
            if spec.name == label_name and not spec.benign:
                return spec.severity
    return "critical" if active else "medium"
