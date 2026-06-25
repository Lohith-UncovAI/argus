from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field

from .hashing import sha256_bytes
from .limits import Limits


class OfflineConfig(BaseModel):
    strict: bool = False
    allow_dns_configured: bool = True


class AppConfig(BaseModel):
    data_dir: str = "data"
    default_policy: str = "agent-with-tools"
    limits: Limits = Field(default_factory=Limits)
    offline: OfflineConfig = Field(default_factory=OfflineConfig)
    optional_tools: Dict[str, str] = Field(default_factory=dict)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Optional[Path] = None) -> AppConfig:
    default_path = Path("config/default.yaml")
    data: Dict[str, Any] = {}
    if default_path.exists():
        with default_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    if path is not None:
        with path.open("r", encoding="utf-8") as handle:
            data = _deep_merge(data, yaml.safe_load(handle) or {})
    return AppConfig.model_validate(data)


def config_hash(config: AppConfig) -> str:
    payload = json.dumps(config.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    return sha256_bytes(payload)

