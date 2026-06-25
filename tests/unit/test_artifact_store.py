from pathlib import Path

import pytest

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.exceptions import ArtifactAccessDenied


def test_original_artifact_is_not_release_eligible(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"not an image")
    store = ArtifactStore(tmp_path / "data")
    artifact = store.store_file(
        sample,
        artifact_id="artifact:test:original",
        media_type="application/octet-stream",
        created_by="test",
        role="original",
        quarantine=True,
        release_eligible=False,
    )
    with pytest.raises(ArtifactAccessDenied):
        store.get_artifact(artifact.artifact_id, release_only=True)
    assert store.get_artifact(artifact.artifact_id, release_only=False).role == "original"


def test_release_eligible_artifact_resolves_inside_store(tmp_path):
    store = ArtifactStore(tmp_path / "data")
    artifact = store.store_bytes(
        b"derived",
        artifact_id="artifact:test:derived",
        media_type="text/plain",
        created_by="test",
        role="derived",
        release_eligible=True,
    )
    assert store.resolve_path(artifact).read_bytes() == b"derived"

