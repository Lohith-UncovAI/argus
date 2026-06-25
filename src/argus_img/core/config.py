from __future__ import annotations

import os
import json
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .exceptions import ConfigurationError
from .hashing import sha256_bytes
from .limits import Limits


class OfflineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    strict: bool = False
    allow_dns_configured: bool = True


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    maximum_total_store_bytes: int = Field(default=10 * 1024 * 1024 * 1024, gt=0)  # 10 GiB
    maximum_bytes_per_scan: int = Field(default=500 * 1024 * 1024, gt=0)  # 500 MiB
    report_retention_seconds: float = Field(default=7 * 24 * 3600, gt=0)
    quarantine_retention_seconds: float = Field(default=30 * 24 * 3600, gt=0)
    forensic_evidence_retention_seconds: float = Field(default=90 * 24 * 3600, gt=0)
    released_artifact_retention_seconds: float = Field(default=7 * 24 * 3600, gt=0)
    job_directory_retention_seconds: float = Field(default=3600, gt=0)
    orphan_grace_period_seconds: float = Field(default=300, ge=0)


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_dir: str = "data"
    default_policy: str = "agent-with-tools"
    limits: Limits = Field(default_factory=Limits)
    offline: OfflineConfig = Field(default_factory=OfflineConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    optional_tools: Dict[str, str] = Field(default_factory=dict)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


ConfigRoot = Union[Path, Traversable]


def _read_text(root: ConfigRoot, relative: Sequence[str]) -> str:
    if isinstance(root, Path):
        path = root.joinpath(*relative)
        if not path.exists():
            raise ConfigurationError("missing required config file: %s" % path)
        return path.read_text(encoding="utf-8")
    resource = root
    for part in relative:
        resource = resource.joinpath(part)
    if not resource.is_file():
        raise ConfigurationError("missing required packaged config file: %s" % "/".join(relative))
    return resource.read_text(encoding="utf-8")


def read_config_text(relative: Sequence[str], config_root: Optional[Path] = None) -> str:
    return _read_text(resolve_config_root(config_root), relative)


def _validate_config_root(root: ConfigRoot) -> ConfigRoot:
    for relative in [("default.yaml",), ("policies", "agent-with-tools.yaml"), ("prompt_rules", "generic.yaml")]:
        _read_text(root, relative)
    return root


def _repo_config_root() -> Optional[Path]:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "config"
        if (candidate / "default.yaml").exists():
            return candidate
    return None


def _packaged_config_root() -> ConfigRoot:
    return resources.files("argus_img").joinpath("config")


def resolve_config_root(explicit_root: Optional[Path] = None) -> ConfigRoot:
    if explicit_root is not None:
        return _validate_config_root(explicit_root.resolve())
    env_root = os.environ.get("ARGUS_CONFIG_ROOT")
    if env_root:
        return _validate_config_root(Path(env_root).resolve())
    repo_root = _repo_config_root()
    if repo_root is not None:
        return _validate_config_root(repo_root)
    return _validate_config_root(_packaged_config_root())


def load_yaml_config(relative: Sequence[str], config_root: Optional[Path] = None) -> Dict[str, Any]:
    raw = yaml.safe_load(read_config_text(relative, config_root)) or {}
    if not isinstance(raw, dict):
        raise ConfigurationError("config file must contain a mapping: %s" % "/".join(relative))
    return raw


def load_config(path: Optional[Path] = None, config_root: Optional[Path] = None) -> AppConfig:
    data: Dict[str, Any] = load_yaml_config(("default.yaml",), config_root)
    if path is not None:
        with path.open("r", encoding="utf-8") as handle:
            override = yaml.safe_load(handle) or {}
            if not isinstance(override, dict):
                raise ConfigurationError("config override must contain a mapping: %s" % path)
            data = _deep_merge(data, override)
    if os.environ.get("ARGUS_DATA_DIR"):
        data["data_dir"] = os.environ["ARGUS_DATA_DIR"]
    if os.environ.get("ARGUS_OFFLINE_STRICT"):
        data.setdefault("offline", {})["strict"] = os.environ["ARGUS_OFFLINE_STRICT"].lower() in {"1", "true", "yes"}
    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError("invalid configuration: %s" % exc) from exc


def config_hash(config: AppConfig) -> str:
    payload = json.dumps(config.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    return sha256_bytes(payload)
