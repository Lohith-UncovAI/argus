from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.exceptions import ConfigurationError
from argus_img.core.models import DetectorFinding, TextObservation
from argus_img.detectors.prompt.intent import extract_intent
from argus_img.reporting.excerpts import text_evidence


class PromptRule:
    def __init__(self, raw: dict) -> None:
        self.id = raw["id"]
        self.category = raw["category"]
        self.severity = raw.get("severity", "medium")
        self.languages = raw.get("languages", ["generic"])
        self.patterns = []
        for pattern in raw.get("patterns", []):
            try:
                self.patterns.append(re.compile(pattern, re.IGNORECASE | re.UNICODE))
            except re.error as exc:
                raise ConfigurationError("invalid regex in %s: %s" % (self.id, exc))

    def match(self, text: str) -> bool:
        return any(pattern.search(text) for pattern in self.patterns)


class PromptRuleBundle:
    def __init__(self, rules: List[PromptRule]) -> None:
        self.rules = rules

    @classmethod
    def load(cls, *paths: Path) -> "PromptRuleBundle":
        rules: List[PromptRule] = []
        for path in paths:
            if not path.exists():
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            if isinstance(data, dict):
                data = data.get("rules", [])
            for raw in data:
                rules.append(PromptRule(raw))
        return cls(rules)

    def analyze_texts(
        self,
        texts: Iterable[TextObservation],
        scan_id: str,
        include_raw_text: bool = False,
        derived_texts: Optional[Dict[str, List[str]]] = None,
    ) -> List[DetectorFinding]:
        findings: List[DetectorFinding] = []
        derived_texts = derived_texts or {}
        for obs in texts:
            candidates = [obs.normalized_text] + derived_texts.get(obs.observation_id, [])
            for candidate in candidates:
                matching = [rule for rule in self.rules if rule.match(candidate)]
                if not matching:
                    continue
                intent = extract_intent(candidate)
                context = intent["quoted_or_active"]
                active = context == "active"
                state = EpistemicState.CONFIRMED if active else EpistemicState.POSSIBLE
                likelihood = 0.95 if active else 0.35
                severity = "critical" if active and any(rule.severity == "critical" for rule in matching) else matching[0].severity
                reason_codes = sorted({"PROMPT_INJECTION", *(rule.category.upper() for rule in matching)})
                if intent.get("requested_action") == "tool_call":
                    reason_codes.append("TOOL_INVOCATION_REQUEST")
                if intent.get("credential_request"):
                    reason_codes.append("CREDENTIAL_REQUEST")
                findings.append(
                    DetectorFinding(
                        finding_id="finding:%s:prompt:%03d" % (scan_id, len(findings)),
                        category="prompt_injection",
                        type=matching[0].category,
                        state=state,
                        severity=severity,
                        detector_confidence=None,
                        evidence_quality=0.85 if active else 0.45,
                        attack_likelihood=likelihood,
                        impact="critical" if active else "medium",
                        source_artifact_ids=[obs.source_artifact_id],
                        observation_ids=[obs.observation_id],
                        detector_ids=["detector:prompt-rules"],
                        reason_codes=reason_codes,
                        recommended_action=PolicyAction.BLOCK if active else PolicyAction.REVIEW,
                        limitations=["Context classification is deterministic and may misclassify quoted text."],
                        evidence={
                            **text_evidence(candidate, include_raw_text=include_raw_text),
                            "matched_rule_ids": [rule.id for rule in matching],
                            "intent": intent,
                        },
                    )
                )
                break
        return findings

