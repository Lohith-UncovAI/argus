from __future__ import annotations

from typing import List

from pydantic import ValidationError

from argus_img.core.config import load_yaml_config
from argus_img.core.enums import PolicyAction, UseProfile
from argus_img.core.exceptions import ConfigurationError
from argus_img.core.models import DetectorFinding, PolicyDecision
from argus_img.policy.conditions import finding_matches
from argus_img.policy.decisions import PolicyDocument, PolicyRule
from argus_img.policy.profiles import policy_relative_path


class PolicyEngine:
    def __init__(self, rules: List[PolicyRule]) -> None:
        self.rules = sorted(rules, key=lambda rule: (-rule.priority, rule.id))

    @classmethod
    def load_for_profile(cls, profile: UseProfile) -> "PolicyEngine":
        data = load_yaml_config(policy_relative_path(profile))
        try:
            document = PolicyDocument.model_validate(data)
        except ValidationError as exc:
            raise ConfigurationError("invalid policy for %s: %s" % (profile.value, exc)) from exc
        if document.profile != profile:
            raise ConfigurationError("policy profile mismatch: expected %s got %s" % (profile.value, document.profile.value))
        return cls(document.rules)

    def decide(self, findings: List[DetectorFinding]) -> PolicyDecision:
        matches = []
        for rule in self.rules:
            for finding in findings:
                if finding_matches(finding, rule.when):
                    matches.append((rule, finding))
                    break
        if not matches:
            return PolicyDecision(
                action=PolicyAction.ALLOW_RECONSTRUCTED_ONLY,
                safe_claim=False,
                reason_codes=[],
                triggered_policy_rules=[],
                summary="No policy rule matched; only reconstructed derivatives are releasable.",
                explanation="The original upload remains quarantined.",
            )
        winning, winning_finding = matches[0]
        reason_codes = sorted({code for _, finding in matches for code in finding.reason_codes})
        return PolicyDecision(
            action=winning.action,
            safe_claim=False,
            reason_codes=reason_codes,
            triggered_policy_rules=[rule.id for rule, _ in matches],
            winning_rule_id=winning.id,
            winning_rule_priority=winning.priority,
            summary=winning.summary,
            explanation="Rule %s matched finding %s." % (winning.id, winning_finding.finding_id),
        )
