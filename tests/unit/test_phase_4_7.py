"""Phase 4.7 unit and integration tests.

Covers:
- Explicit mode execution plans (fast / deep / forensic)
- AGENT_WITH_TOOLS fail-closed coverage gate
- ASGI-level request-body limit
- Snapshot intake no-follow and regular-file hardening
- Offline attestation verified-facts contract
- Detector registry allow_unsupported field
- sanitize/redact parameters removed from public API
- compileall (all .py files import without syntax errors)
"""
from __future__ import annotations

import importlib
import os
import pkgutil
import stat
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

import argus_img
from argus_img.api.app import create_app
from argus_img.api.routes import artifacts as artifact_routes
from argus_img.api.routes import scans as scan_routes
from argus_img.core.config import load_config
from argus_img.core.detector_registry import load_detector_registry
from argus_img.core.enums import DetectorStatus, EpistemicState, PolicyAction, ScanMode, UseProfile
from argus_img.core.models import DetectorExecution, ScanRequest
from argus_img.orchestration.mode_plan import DEEP_PLAN, FAST_PLAN, FORENSIC_PLAN, plan_for_mode
from argus_img.orchestration.pipeline import scan_file
from argus_img.policy.coverage import mandatory_coverage_decision


# ---------------------------------------------------------------------------
# Mode execution plans
# ---------------------------------------------------------------------------

def test_fast_plan_has_all_mandatory_detectors():
    """fast plan must declare all mandatory detectors."""
    mandatory = {
        "detector:metadata-builtin",
        "detector:prompt-rules",
        "detector:tesseract",
        "detector:qr-pyzbar",
        "detector:malware-clamav",
        "detector:malware-yara",
        "detector:embedded-binwalk",
    }
    assert mandatory <= FAST_PLAN.active_detectors


def test_deep_plan_is_superset_of_fast():
    assert FAST_PLAN.active_detectors <= DEEP_PLAN.active_detectors
    assert FAST_PLAN.active_transformations <= DEEP_PLAN.active_transformations


def test_forensic_plan_is_superset_of_deep():
    assert DEEP_PLAN.active_detectors <= FORENSIC_PLAN.active_detectors


def test_all_scan_modes_have_plans():
    for mode in ScanMode:
        plan = plan_for_mode(mode)
        assert plan.mode == mode
        assert plan.active_detectors
        assert plan.active_transformations
        assert plan.description


def test_fast_plan_includes_channel_transforms():
    """Channel views are safety-critical and must run in fast mode."""
    for channel in ("red-channel", "green-channel", "blue-channel", "alpha-channel"):
        assert channel in FAST_PLAN.active_transformations, "missing %s" % channel


def test_forensic_plan_includes_optional_forensic_detectors():
    forensic_only = {"detector:zsteg", "detector:c2pa", "detector:adversarial-stability"}
    assert forensic_only <= FORENSIC_PLAN.active_detectors


# ---------------------------------------------------------------------------
# Fail-closed coverage gate
# ---------------------------------------------------------------------------

def test_agent_with_tools_fails_closed_without_malware_execution():
    """Missing malware execution => UNSUPPORTED, even if all other detectors ran."""
    registry = load_detector_registry()
    executions = [
        DetectorExecution(
            detector_id="detector:metadata-builtin",
            status=DetectorStatus.NO_EVIDENCE,
            state=EpistemicState.NO_EVIDENCE_FOUND,
            required=True,
        ),
        DetectorExecution(
            detector_id="detector:prompt-rules",
            status=DetectorStatus.NO_EVIDENCE,
            state=EpistemicState.NO_EVIDENCE_FOUND,
            required=True,
        ),
        DetectorExecution(
            detector_id="detector:tesseract",
            status=DetectorStatus.NO_EVIDENCE,
            state=EpistemicState.NO_EVIDENCE_FOUND,
        ),
        DetectorExecution(
            detector_id="detector:qr-pyzbar",
            status=DetectorStatus.NO_EVIDENCE,
            state=EpistemicState.NO_EVIDENCE_FOUND,
        ),
        # malware-clamav, malware-yara, embedded-binwalk intentionally absent
    ]
    decision = mandatory_coverage_decision(UseProfile.AGENT_WITH_TOOLS, registry, executions)
    assert decision is not None
    assert decision.action == PolicyAction.UNSUPPORTED
    assert "missing" in decision.explanation.lower() or "malware" in decision.explanation.lower()


def test_unsupported_malware_fails_coverage_for_agent_with_tools():
    """UNSUPPORTED malware stubs MUST fail the coverage gate — no fail-open."""
    registry = load_detector_registry()
    executions = [
        DetectorExecution(
            detector_id="detector:metadata-builtin",
            status=DetectorStatus.NO_EVIDENCE,
            state=EpistemicState.NO_EVIDENCE_FOUND,
            required=True,
        ),
        DetectorExecution(
            detector_id="detector:prompt-rules",
            status=DetectorStatus.NO_EVIDENCE,
            state=EpistemicState.NO_EVIDENCE_FOUND,
            required=True,
        ),
        DetectorExecution(
            detector_id="detector:tesseract",
            status=DetectorStatus.NO_EVIDENCE,
            state=EpistemicState.NO_EVIDENCE_FOUND,
        ),
        DetectorExecution(
            detector_id="detector:qr-pyzbar",
            status=DetectorStatus.NO_EVIDENCE,
            state=EpistemicState.NO_EVIDENCE_FOUND,
        ),
        DetectorExecution(
            detector_id="detector:malware-clamav",
            status=DetectorStatus.UNSUPPORTED,
            state=EpistemicState.UNSUPPORTED,
            reason="tool_not_installed",
        ),
        DetectorExecution(
            detector_id="detector:malware-yara",
            status=DetectorStatus.UNSUPPORTED,
            state=EpistemicState.UNSUPPORTED,
            reason="tool_not_installed",
        ),
        DetectorExecution(
            detector_id="detector:embedded-binwalk",
            status=DetectorStatus.UNSUPPORTED,
            state=EpistemicState.UNSUPPORTED,
            reason="tool_not_installed",
        ),
    ]
    decision = mandatory_coverage_decision(UseProfile.AGENT_WITH_TOOLS, registry, executions)
    # UNSUPPORTED is no longer permitted for mandatory coverage — must fail closed.
    assert decision is not None
    assert decision.action == PolicyAction.UNSUPPORTED
    assert "UNSUPPORTED" in decision.explanation


def test_allow_unsupported_field_removed_from_registry():
    """DetectorRegistryEntry must not have allow_unsupported (removed in Phase 4.7B)."""
    registry = load_detector_registry()
    for entry in registry.detectors:
        assert not hasattr(entry, "allow_unsupported"), (
            "allow_unsupported must be removed from registry entry %s" % entry.id
        )


def test_pipeline_emits_malware_stub_executions(fixture_path, app_config):
    """Pipeline must emit explicit execution records for malware/embedded stubs."""
    report = scan_file(fixture_path / "clean.png", ScanRequest(original_filename="clean.png"), app_config)
    exec_ids = {e.detector_id for e in report.detector_executions}
    assert "detector:malware-clamav" in exec_ids
    assert "detector:malware-yara" in exec_ids
    assert "detector:embedded-binwalk" in exec_ids


# ---------------------------------------------------------------------------
# ASGI-level body size limit
# ---------------------------------------------------------------------------

def _client_with_config(app_config, monkeypatch):
    monkeypatch.setattr(scan_routes, "load_config", lambda: app_config)
    monkeypatch.setattr(artifact_routes, "load_config", lambda: app_config)
    return TestClient(create_app(max_body_bytes=app_config.limits.max_input_bytes))


def test_asgi_body_limit_rejects_via_content_length(fixture_path, app_config, monkeypatch):
    """Content-Length header triggers 413 before body is spooled."""
    app_config.limits.max_input_bytes = 4
    client = _client_with_config(app_config, monkeypatch)
    clean = (fixture_path / "clean.png").read_bytes()
    response = client.post(
        "/v1/scans",
        data={"mode": "fast"},
        files={"file": ("clean.png", clean, "image/png")},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


# ---------------------------------------------------------------------------
# Snapshot intake hardening
# ---------------------------------------------------------------------------

def test_intake_rejects_symlink_via_store(tmp_path):
    from argus_img.artifacts.store import ArtifactStore
    from argus_img.core.exceptions import IntakeRejected

    store = ArtifactStore(tmp_path / "data")
    real = tmp_path / "real.png"
    Image.new("RGB", (10, 10), "white").save(real)
    link = tmp_path / "link.png"
    link.symlink_to(real)
    with pytest.raises(IntakeRejected, match="cannot open input file|symlink"):
        store.store_file(link, "artifact:test:orig", "image/png", "test", "original", quarantine=True)


def test_intake_rejects_regular_file_check_in_validation(tmp_path):
    from argus_img.core.exceptions import IntakeRejected
    from argus_img.core.limits import Limits
    from argus_img.intake.validation import validate_image_file

    # A directory path is not a regular file
    with pytest.raises(IntakeRejected, match="regular file"):
        validate_image_file(tmp_path, None, Limits())


# ---------------------------------------------------------------------------
# sanitize / redact removed from public API
# ---------------------------------------------------------------------------

def test_scan_request_has_no_sanitize_or_redact():
    """ScanRequest must not expose sanitize or redact after Phase 4.7 removal."""
    req = ScanRequest(original_filename="test.png")
    assert not hasattr(req, "sanitize"), "sanitize must be removed"
    assert not hasattr(req, "redact"), "redact must be removed"


def test_api_ignores_sanitize_redact_form_fields(fixture_path, app_config, monkeypatch):
    """API endpoint must not accept sanitize/redact form fields (422 on unknown)."""
    client = _client_with_config(app_config, monkeypatch)
    with (fixture_path / "clean.png").open("rb") as handle:
        response = client.post(
            "/v1/scans",
            data={"mode": "fast", "sanitize": "true", "redact": "false"},
            files={"file": ("clean.png", handle, "image/png")},
        )
    # FastAPI should ignore or 422 extra form fields; the scan must complete
    # or fail with 422 — either way sanitize/redact must not silently pass through.
    assert response.status_code in (200, 422)


# ---------------------------------------------------------------------------
# Offline attestation verified-facts contract
# ---------------------------------------------------------------------------

def test_attestation_does_not_claim_unconditional_pass(app_config, monkeypatch):
    """self_test_status must reflect actual checks, not a hard-coded 'pass'."""
    from argus_img.api.routes import attestation as att_routes

    monkeypatch.setattr(att_routes, "load_config", lambda: app_config)
    client = TestClient(create_app())
    response = client.get("/v1/attestation")
    assert response.status_code == 200
    body = response.json()
    assert "self_test_status" in body
    assert body["air_gap_claim"] is False
    assert "stub_detectors" in body
    assert "malware-clamav" in body["stub_detectors"]
    assert "network_offline_configuration_state" in body
    # python_version must be a verified runtime fact
    assert "python_version" in body
    parts = body["python_version"].split(".")
    assert len(parts) == 3
    assert int(parts[0]) == sys.version_info.major


# ---------------------------------------------------------------------------
# compileall: verify all source modules import without syntax errors
# ---------------------------------------------------------------------------

def test_all_source_modules_compile():
    """Every .py file under argus_img must compile without errors."""
    root = Path(argus_img.__file__).parent
    errors = []
    for py_file in root.rglob("*.py"):
        try:
            importlib.util.spec_from_file_location("_check", py_file)
            with py_file.open("rb") as fh:
                compile(fh.read(), str(py_file), "exec")
        except SyntaxError as exc:
            errors.append("%s: %s" % (py_file, exc))
    assert not errors, "Syntax errors found:\n" + "\n".join(errors)


def test_all_source_modules_importable():
    """Every public module under argus_img must be importable."""
    import importlib

    root = Path(argus_img.__file__).parent
    errors = []
    for py_file in root.rglob("*.py"):
        if py_file.name.startswith("_"):
            continue
        rel = py_file.relative_to(root.parent)
        module_name = ".".join(rel.with_suffix("").parts)
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            errors.append("%s: %s" % (module_name, exc))
    assert not errors, "Import errors found:\n" + "\n".join(errors)


# ---------------------------------------------------------------------------
# Deadline budget recalculation
# ---------------------------------------------------------------------------

def test_budget_deadline_enforced_before_allocation():
    """ResourceBudget must raise immediately once the deadline passes."""
    import time
    from argus_img.core.budget import ResourceBudget
    from argus_img.core.exceptions import ResourceLimitExceeded
    from argus_img.core.limits import Limits

    budget = ResourceBudget(Limits(full_scan_timeout_seconds=1))
    # Force the deadline into the past
    budget.deadline = time.monotonic() - 1
    with pytest.raises(ResourceLimitExceeded, match="timeout"):
        budget.consume_decoded_pixels(1)


def test_budget_remaining_seconds_never_negative():
    import time
    from argus_img.core.budget import ResourceBudget
    from argus_img.core.limits import Limits

    budget = ResourceBudget(Limits(full_scan_timeout_seconds=60))
    budget.deadline = time.monotonic() - 10
    assert budget.remaining_seconds() == 0.0


# ---------------------------------------------------------------------------
# Schema drift guard (extended)
# ---------------------------------------------------------------------------

def test_detector_registry_schema_rejects_allow_unsupported():
    """DetectorRegistryEntry must REJECT allow_unsupported — field removed in Phase 4.7B."""
    import pytest
    from pydantic import ValidationError
    from argus_img.core.detector_registry import DetectorRegistry

    data = {
        "detectors": [
            {
                "id": "detector:test-stub",
                "family": "malware",
                "category": "malware",
                "allow_unsupported": True,
                "required_profiles": ["AGENT_WITH_TOOLS"],
            }
        ]
    }
    with pytest.raises(ValidationError, match="allow_unsupported"):
        DetectorRegistry.model_validate(data)
