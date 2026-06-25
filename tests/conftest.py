from pathlib import Path
import sys

import pytest

from argus_img.core.config import load_config

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.generate_test_images import main as generate_fixtures


@pytest.fixture(scope="session", autouse=True)
def fixtures():
    generate_fixtures()


@pytest.fixture()
def app_config(tmp_path):
    config = load_config()
    config.data_dir = str(tmp_path / "data")
    return config


@pytest.fixture()
def fixture_path():
    return Path("tests/fixtures")
