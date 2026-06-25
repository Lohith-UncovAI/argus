from __future__ import annotations

from pathlib import Path
from typing import List

import yaml

from argus_img.core.enums import PolicyAction, UseProfile
from argus_img.core.models import DetectorFinding, PolicyDecision
from argus_img.policy.conditions import finding_matches
from argus_img.policy.decisions import PolicyRule
from argus_img.policy.profiles import policy_path


class PolicyEngine:
    def __init__(self, rules: List[PolicyRule]) -> None:
        self.rules = sorted(rules, key=lambda rule: (-rule.priority, rule.id))

    @classmethod
    def load_for_profile(cls, profile: UseProfile) -> "PolicyEngine":
        path = policy_path(profile)
        if not path.exists():
            path = policy_path(UseProfile.AGENT_WITH_TOOLS)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rules = [
            PolicyRule(
                id=raw["id"],
                priority=int(raw.get("priority", 0)),
                when=raw.get("when", {}),
                action=raw["action"],
                summary=raw.get("summary", raw["id"]),
            )
            for raw in data.get("rules", [])
        ]
        return cls(rules)

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
        action = PolicyAction(winning.action)
        reason_codes = sorted({code for _, finding in matches for code in finding.reason_codes})
        return PolicyDecision(
            action=action,
            safe_claim=False,
            reason_codes=reason_codes,
            triggered_policy_rules=[rule.id for rule, _ in matches],
            winning_rule_id=winning.id,
            winning_rule_priority=winning.priority,
            summary=winning.summary,
            explanation="Rule %s matched finding %s." % (winning.id, winning_finding.finding_id),
        )

