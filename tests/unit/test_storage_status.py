import json
import os
import time
from pathlib import Path

from PIL import Image

from argus_img.artifacts.store import ArtifactStore
from argus_img.cli.main import _argparse_main
from argus_img.core.config import load_config
from argus_img.core.enums import PolicyAction
from argus_img.core.models import ScanRequest
from argus_img.orchestration.pipeline import scan_file


def test_storage_status_reports_quota_scope(tmp_path):
    store = ArtifactStore(tmp_path / "data")
    store.store_bytes(
        b"x" * 128,
        artifact_id="artifact:scan-storage:original",
        media_type="application/octet-stream",
        created_by="test",
        role="original",
        quarantine=True,
    )

    status = store.storage_status(quota_bytes=1)

    assert status["data_dir"] == str((tmp_path / "data").resolve())
    assert status["total_bytes"] >= 128
    assert status["quota_bytes"] == 1
    assert status["remaining_bytes"] < 0
    assert status["over_quota"] is True
    assert set(status["areas"]) == {
        "quarantine_bytes",
        "artifacts_bytes",
        "forensic_bytes",
        "db_bytes",
    }


def test_health_and_capabilities_include_storage(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    store = ArtifactStore(data_dir)
    store.store_bytes(
        b"x" * 64,
        artifact_id="artifact:scan-health:original",
        media_type="application/octet-stream",
        created_by="test",
        role="original",
        quarantine=True,
    )
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_dir))
    monkeypatch.setenv("ARGUS_STORAGE_MAX_BYTES", "1")

    from argus_img.api.routes.capabilities import capabilities
    from argus_img.api.routes.health import health

    health_payload = health()
    capabilities_payload = capabilities()

    assert health_payload["status"] == "degraded"
    assert health_payload["storage"]["over_quota"] is True
    assert capabilities_payload["storage"]["data_dir"] == str(data_dir.resolve())
    assert capabilities_payload["storage"]["over_quota"] is True


def test_cli_storage_status_outputs_json(monkeypatch, tmp_path, capsys):
    data_dir = tmp_path / "data"
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_dir))
    monkeypatch.setenv("ARGUS_STORAGE_MAX_BYTES", "1000000")

    _argparse_main(["storage", "status"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["data_dir"] == str(data_dir.resolve())
    assert payload["quota_bytes"] == 1000000
    assert payload["over_quota"] is False


def test_cli_storage_cleanup_is_retention_based(monkeypatch, tmp_path, capsys):
    data_dir = tmp_path / "data"
    store = ArtifactStore(data_dir)
    old_job = store.jobs_dir / "old-job"
    old_job.mkdir(parents=True)
    old = time.time() - 7200
    os.utime(old_job, (old, old))
    monkeypatch.setenv("ARGUS_DATA_DIR", str(data_dir))

    _argparse_main(["storage", "cleanup"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert "old-job" in payload["cleanup"]["expired_jobs"]
    assert not old_job.exists()
    assert "before" in payload and "after" in payload


def test_scan_fails_closed_before_quarantining_when_store_lacks_headroom(tmp_path):
    image_path = tmp_path / "input.png"
    Image.new("RGB", (64, 64), "white").save(image_path)
    config = load_config()
    config.data_dir = str(tmp_path / "data")
    config.storage.maximum_total_store_bytes = 1

    report = scan_file(image_path, ScanRequest(original_filename=image_path.name), config)
    store = ArtifactStore(Path(config.data_dir))

    assert report.decision.action == PolicyAction.UNSUPPORTED
    assert "before quarantine" in (report.decision.explanation or "")
    assert not any(path.is_file() for path in store.quarantine_dir.rglob("*"))
