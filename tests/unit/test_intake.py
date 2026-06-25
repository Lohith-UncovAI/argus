from pathlib import Path

import pytest

from argus_img.core.exceptions import IntakeRejected
from argus_img.core.limits import Limits
from argus_img.intake.mime import detect_magic
from argus_img.intake.validation import validate_image_file


def test_magic_detects_png(fixture_path):
    mime, fmt = detect_magic(fixture_path / "clean.png")
    assert mime == "image/png"
    assert fmt == "PNG"


def test_malformed_png_is_rejected(fixture_path):
    with pytest.raises(IntakeRejected):
        validate_image_file(fixture_path / "malformed.png", None, Limits())

