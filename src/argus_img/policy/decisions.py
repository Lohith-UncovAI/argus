from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from argus_img.core.enums import EpistemicState, PolicyAction, UseProfile


ALLOWED_CATEGORIES = {
    "file_security",
    "malware",
    "embedded_payload",
    "prompt_injection",
    "covert_channel",
    "steganography",
    "watermarks",
    "provenance",
    "phishing",
    "privacy",
    "redaction_failure",
    "adversarial_instability",
    "authenticity_indicators",
}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
PROBABILITY_FIELDS = {"detector_confidence", "evidence_quality", "attack_likelihood"}


class PolicyCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: Optional[str] = None
    type: Optional[str] = None
    state: Optional[EpistemicState] = None
    state_in: Optional[List[EpistemicState]] = None
    reason_code: Optional[str] = None
    severity_in: Optional[List[str]] = None
    greater_than_or_equal: Optional[Dict[str, float]] = None

    @field_validator("category")
    @classmethod
    def valid_category(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in ALLOWED_CATEGORIES:
            raise ValueError("unknown category: %s" % value)
        return value

    @field_validator("severity_in")
    @classmethod
    def valid_severities(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is not None:
            if not value:
                raise ValueError("severity_in cannot be empty")
            unknown = sorted(set(value) - ALLOWED_SEVERITIES)
            if unknown:
                raise ValueError("unknown severities: %s" % ", ".join(unknown))
        return value

    @field_validator("state_in")
    @classmethod
    def non_empty_states(cls, value: Optional[List[EpistemicState]]) -> Optional[List[EpistemicState]]:
        if value is not None and not value:
            raise ValueError("state_in cannot be empty")
        return value

    @field_validator("greater_than_or_equal")
    @classmethod
    def valid_thresholds(cls, value: Optional[Dict[str, float]]) -> Optional[Dict[str, float]]:
        if value is None:
            return value
        if not value:
            raise ValueError("greater_than_or_equal cannot be empty")
        for field, threshold in value.items():
            if field in PROBABILITY_FIELDS and not 0.0 <= threshold <= 1.0:
                raise ValueError("invalid probability threshold for %s" % field)
        return value

    @model_validator(mode="after")
    def non_empty_condition(self) -> "PolicyCondition":
        if not any(
            value is not None
            for value in [
                self.category,
                self.type,
                self.state,
                self.state_in,
                self.reason_code,
                self.severity_in,
                self.greater_than_or_equal,
            ]
        ):
            raise ValueError("policy condition cannot be empty")
        return self


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    priority: int = 0
    when: PolicyCondition
    action: PolicyAction
    summary: str = ""


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: UseProfile
    rules: List[PolicyRule] = Field(min_length=1)

    @field_validator("rules")
    @classmethod
    def unique_rule_ids(cls, value: List[PolicyRule]) -> List[PolicyRule]:
        ids = [rule.id for rule in value]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError("duplicate policy rule ids: %s" % ", ".join(duplicates))
        return value
