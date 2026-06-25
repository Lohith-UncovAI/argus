from pathlib import Path

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.config import load_config


def get_config():
    return load_config()


def get_store():
    config = get_config()
    return ArtifactStore(Path(config.data_dir))

