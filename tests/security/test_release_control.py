from pathlib import Path

from fastapi.testclient import TestClient

from argus_img.api.app import create_app
from argus_img.api.routes import artifacts as artifact_routes
from argus_img.artifacts.store import ArtifactStore
from argus_img.core.enums import PolicyAction
from argus_img.core.models import ScanRequest
from argus_img.orchestration.pipeline import scan_file


def test_blocked_prompt_image_cannot_download_any_derivative(fixture_path, app_config, monkeypatch):
    report = scan_file(fixture_path / "visible_prompt.png", ScanRequest(original_filename="visible_prompt.png"), app_config)
    assert report.decision.action == PolicyAction.BLOCK
    assert report.release_grants == []
    monkeypatch.setattr(artifact_routes, "load_config", lambda: app_config)
    client = TestClient(create_app())
    derivatives = [artifact for artifact in report.artifacts.values() if artifact.role != "original"]
    assert derivatives
    for artifact in derivatives:
        response = client.get("/v1/artifacts/%s" % artifact.artifact_id)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "artifact_not_released"


def test_normal_endpoint_serves_only_release_granted_reconstruction(fixture_path, app_config):
    report = scan_file(fixture_path / "clean.png", ScanRequest(original_filename="clean.png"), app_config)
    store = ArtifactStore(Path(app_config.data_dir))
    released = store.get_artifact(report.artifacts["canonical_lossy"].artifact_id, release_only=True)
    assert released.role == "canonical_lossy"
    assert report.artifacts["canonical_lossless"].release_eligible is False
