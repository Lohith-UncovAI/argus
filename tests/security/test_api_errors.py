from fastapi.testclient import TestClient

from argus_img.api.app import create_app
from argus_img.api.routes import artifacts as artifact_routes
from argus_img.api.routes import scans as scan_routes


def _client(app_config, monkeypatch):
    monkeypatch.setattr(scan_routes, "load_config", lambda: app_config)
    monkeypatch.setattr(artifact_routes, "load_config", lambda: app_config)
    return TestClient(create_app())


def test_invalid_mode_returns_422_json(fixture_path, app_config, monkeypatch):
    client = _client(app_config, monkeypatch)
    with (fixture_path / "clean.png").open("rb") as handle:
        response = client.post(
            "/v1/scans",
            data={"mode": "turbo", "use_profile": "AGENT_WITH_TOOLS"},
            files={"file": ("clean.png", handle, "image/png")},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_invalid_profile_returns_422_json(fixture_path, app_config, monkeypatch):
    client = _client(app_config, monkeypatch)
    with (fixture_path / "clean.png").open("rb") as handle:
        response = client.post(
            "/v1/scans",
            data={"mode": "fast", "use_profile": "UNKNOWN_PROFILE"},
            files={"file": ("clean.png", handle, "image/png")},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_oversized_upload_returns_413_json(fixture_path, app_config, monkeypatch):
    app_config.limits.max_input_bytes = 4
    client = _client(app_config, monkeypatch)
    with (fixture_path / "clean.png").open("rb") as handle:
        response = client.post(
            "/v1/scans",
            data={"mode": "fast", "use_profile": "AGENT_WITH_TOOLS"},
            files={"file": ("clean.png", handle, "image/png")},
        )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_unknown_scan_and_artifact_return_404_json(app_config, monkeypatch):
    client = _client(app_config, monkeypatch)
    scan_response = client.get("/v1/scans/not-a-scan")
    artifact_response = client.get("/v1/artifacts/artifact:not-found")
    assert scan_response.status_code == 404
    assert scan_response.json()["error"]["code"] == "not_found"
    assert artifact_response.status_code == 404
    assert artifact_response.json()["error"]["code"] == "not_found"
