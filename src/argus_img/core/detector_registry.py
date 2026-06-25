from __future__ import annotations

from typing import List

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from argus_img.core.config import load_yaml_config
from argus_img.core.enums import UseProfile
from argus_img.core.exceptions import ConfigurationError
from argus_img.policy.decisions import ALLOWED_CATEGORIES


class DetectorRegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    family: str = Field(min_length=1)
    category: str = Field(min_length=1)
    required: bool = False
    required_profiles: List[UseProfile] = Field(default_factory=list)
    # When True the detector is mandatory but may legitimately return UNSUPPORTED
    # (e.g., a stub awaiting full implementation).  Missing from execution list
    # is still a hard failure.
    allow_unsupported: bool = False

    @field_validator("category")
    @classmethod
    def known_category(cls, value: str) -> str:
        if value not in ALLOWED_CATEGORIES:
            raise ValueError("unknown category: %s" % value)
        return value


class DetectorRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detectors: List[DetectorRegistryEntry] = Field(min_length=1)

    @field_validator("detectors")
    @classmethod
    def unique_detector_ids(cls, value: List[DetectorRegistryEntry]) -> List[DetectorRegistryEntry]:
        ids = [entry.id for entry in value]
        duplicates = sorted({detector_id for detector_id in ids if ids.count(detector_id) > 1})
        if duplicates:
            raise ValueError("duplicate detector ids: %s" % ", ".join(duplicates))
        return value

    def required_for_profile(self, profile: UseProfile) -> List[DetectorRegistryEntry]:
        return [
            entry
            for entry in self.detectors
            if entry.required or profile in entry.required_profiles
        ]


def load_detector_registry() -> DetectorRegistry:
    data = load_yaml_config(("detector_registry.yaml",))
    try:
        return DetectorRegistry.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError("invalid detector registry: %s" % exc) from exc
