"""Pipeline adapter: run the optional local prompt-injection classifier over
text observations and emit ``DetectorFinding``s.

Wired into ``orchestration/pipeline.py`` as the "configured prompt-classifier
adapter" step (plan.md §19.2 / pipeline step 18), between the deterministic rule
bundle and the heuristic semantic scorer.

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
from argus_img.detectors.prompt.intent import classify_text_context

_DETECTOR_ID = "detector:prompt-classifier"


def analyze_classifier(
    observations: List[TextObservation],
    scan_id: str,
    classifier: Optional[object] = None,
    include_raw_text: bool = False,
    skip_observation_ids: Optional[set] = None,
) -> List[DetectorFinding]:
    clf = classifier or LocalTransformerClassifier.from_env()
    if clf is None:
        return []

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

        if classify_text_context(text) in ("quoted", "discussed", "warning"):
            continue

        result: PromptClassification = clf.classify_sync(text)
        if result.status != "SUCCESS":
            continue
        if result.score < thr_review:
            continue

        active = result.score >= thr_block
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
                "HIGHLY_LIKELY and never drive a decision on their own.",
                "Model runs offline on CPU against a local checkpoint; it reflects its "
                "training distribution and may miss novel phrasings or misfire on "
                "security-education content.",
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
