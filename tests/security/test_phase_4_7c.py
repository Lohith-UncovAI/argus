"""Phase 4.7C security invariant tests.

Covers:
- ClamAV DETECTED produces QUARANTINE and a finding with signature name
- YARA DETECTED produces QUARANTINE and a finding with rule-id/namespace/tags/bundle-hash
- Binwalk nested executable detection produces QUARANTINE
- Binwalk does NOT produce a finding for offset-zero outer image signature
- DETECTED execution without a finding fails closed (no grant, BLOCK)
- No detected-malware scan can produce a release grant
- VLM_READ_ONLY always returns UNSUPPORTED
- RAG_INGESTION is a strict profile (malware tools required)
- Fast and deep modes produce materially different transform sets
- Forensic mode produces different detector set from fast
- Atomic final persistence: report + grants committed together
- Retention: expire_old_reports and revoke_expired_grants work
- Worker launcher: communicate(timeout) path, no blocking pipe hang
- Control-side artifact verification: hash mismatch blocked
"""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import List, Optional
from unittest.mock import MagicMock, patch

import pytest

from argus_img.core.enums import DetectorStatus, EpistemicState, PolicyAction, ScanMode, UseProfile
from argus_img.core.models import (
    DetectorExecution,
    DetectorFinding,
    ScanRequest,
)
from argus_img.orchestration.pipeline import scan_file
from argus_img.policy.coverage import (
    STRICT_PROFILES,
    detected_without_finding,
    detected_without_finding_decision,
    mandatory_coverage_decision,
)
from argus_img.core.detector_registry import load_detector_registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _exec(detector_id: str, status: DetectorStatus, state: EpistemicState) -> DetectorExecution:
    return DetectorExecution(detector_id=detector_id, status=status, state=state)


def _finding(detector_ids: List[str], category: str = "malware") -> DetectorFinding:
    return DetectorFinding(
        finding_id="finding:test:1",
        category=category,
        type="test",
        state=EpistemicState.CONFIRMED,
        severity="high",
        source_artifact_ids=["artifact:test:orig"],
        detector_ids=detector_ids,
        reason_codes=["TEST"],
        recommended_action=PolicyAction.QUARANTINE,
    )


# ---------------------------------------------------------------------------
# Detection-to-policy invariant
# ---------------------------------------------------------------------------

def test_detected_without_finding_is_identified():
    executions = [
        _exec("detector:malware-clamav", DetectorStatus.DETECTED, EpistemicState.CONFIRMED),
        _exec("detector:malware-yara", DetectorStatus.NO_EVIDENCE, EpistemicState.NO_EVIDENCE_FOUND),
    ]
    findings: List[DetectorFinding] = []
    orphans = detected_without_finding(executions, findings)
    assert "detector:malware-clamav" in orphans
    assert "detector:malware-yara" not in orphans


def test_detected_with_finding_is_not_flagged():
    executions = [
        _exec("detector:malware-clamav", DetectorStatus.DETECTED, EpistemicState.CONFIRMED),
    ]
    findings = [_finding(["detector:malware-clamav"])]
    orphans = detected_without_finding(executions, findings)
    assert not orphans


def test_detected_without_finding_decision_returns_block():
    executions = [
        _exec("detector:malware-clamav", DetectorStatus.DETECTED, EpistemicState.CONFIRMED),
    ]
    decision = detected_without_finding_decision(executions, [])
    assert decision is not None
    assert decision.action == PolicyAction.BLOCK
    assert "DETECTED_WITHOUT_FINDING" in decision.reason_codes
    assert "detector:malware-clamav" in decision.explanation


def test_detected_with_finding_has_no_dwf_decision():
    executions = [
        _exec("detector:malware-clamav", DetectorStatus.DETECTED, EpistemicState.CONFIRMED),
    ]
    findings = [_finding(["detector:malware-clamav"])]
    decision = detected_without_finding_decision(executions, findings)
    assert decision is None


# ---------------------------------------------------------------------------
# ClamAV finding emission
# ---------------------------------------------------------------------------

def test_clamav_detected_produces_finding_with_signature():
    from argus_img.subprocesses.runner import ToolResult
    from argus_img.detectors.malware import run_clamav

    fake_result = ToolResult(
        args=["clamscan", "/tmp/snapshot"],
        stdout="/tmp/snapshot: Eicar-Test-Signature FOUND\n",
        stderr="",
        returncode=1,
        timed_out=False,
        duration_ms=50.0,
        error=None,
    )
    with patch("argus_img.detectors.malware._clamav_path", return_value="/usr/bin/clamscan"), \
         patch("argus_img.detectors.malware.executable_version", return_value="0.103.x"), \
         patch("argus_img.detectors.malware.run_tool", return_value=fake_result):
        report = run_clamav(Path("/tmp/snapshot"), "artifact:scan:orig", "scan:test:1", 30.0)

    assert report.execution.status == DetectorStatus.DETECTED
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.category == "malware"
    assert finding.type == "malware_signature"
    assert finding.state == EpistemicState.CONFIRMED
    assert finding.recommended_action == PolicyAction.QUARANTINE
    assert "detector:malware-clamav" in finding.detector_ids
    assert "signature_name" in finding.evidence
    assert "Eicar-Test-Signature" in finding.evidence["signature_name"]


def test_clamav_clean_produces_no_finding():
    from argus_img.subprocesses.runner import ToolResult
    from argus_img.detectors.malware import run_clamav

    fake_result = ToolResult(
        args=["clamscan", "/tmp/snapshot"],
        stdout="", stderr="", returncode=0, timed_out=False, duration_ms=30.0, error=None,
    )
    with patch("argus_img.detectors.malware._clamav_path", return_value="/usr/bin/clamscan"), \
         patch("argus_img.detectors.malware.executable_version", return_value="0.103.x"), \
         patch("argus_img.detectors.malware.run_tool", return_value=fake_result):
        report = run_clamav(Path("/tmp/snapshot"), "artifact:scan:orig", "scan:test:2", 30.0)

    assert report.execution.status == DetectorStatus.NO_EVIDENCE
    assert report.findings == []


# ---------------------------------------------------------------------------
# YARA finding emission
# ---------------------------------------------------------------------------

def test_yara_detected_produces_finding_with_rule_id(tmp_path):
    from argus_img.subprocesses.runner import ToolResult
    from argus_img.detectors.malware import run_yara

    rule_bundle = tmp_path / "rules.yar"
    rule_bundle.write_bytes(b"rule TestRule { condition: true }")
    bundle_hash = "sha256:" + hashlib.sha256(rule_bundle.read_bytes()).hexdigest()

    fake_result = ToolResult(
        args=["yara", str(rule_bundle), "/tmp/snapshot"],
        stdout="MalwareRule /tmp/snapshot\n",
        stderr="",
        returncode=0,
        timed_out=False,
        duration_ms=40.0,
        error=None,
    )
    with patch("argus_img.detectors.malware._yara_path", return_value="/usr/bin/yara"), \
         patch("argus_img.detectors.malware.executable_version", return_value="4.x"), \
         patch("argus_img.detectors.malware.run_tool", return_value=fake_result):
        report = run_yara(
            Path("/tmp/snapshot"), "artifact:scan:orig", "scan:test:3", 30.0,
            rule_bundle_path=rule_bundle,
            rule_bundle_sha256=bundle_hash,
        )

    assert report.execution.status == DetectorStatus.DETECTED
    assert len(report.findings) >= 1
    f = report.findings[0]
    assert f.recommended_action == PolicyAction.QUARANTINE
    assert "rule_id" in f.evidence
    assert "namespace" in f.evidence
    assert "rule_bundle_hash" in f.evidence


def test_yara_bundle_hash_mismatch_returns_error(tmp_path):
    from argus_img.detectors.malware import run_yara

    rule_bundle = tmp_path / "rules.yar"
    rule_bundle.write_bytes(b"rule TestRule { condition: true }")
    wrong_hash = "sha256:" + "a" * 64

    with patch("argus_img.detectors.malware._yara_path", return_value="/usr/bin/yara"):
        report = run_yara(
            Path("/tmp/snapshot"), "artifact:scan:orig", "scan:test:4", 30.0,
            rule_bundle_path=rule_bundle,
            rule_bundle_sha256=wrong_hash,
        )

    assert report.execution.status == DetectorStatus.ERROR
    assert "hash_mismatch" in (report.execution.reason or "")


# ---------------------------------------------------------------------------
# Binwalk: offset-zero exclusion and nested-executable quarantine
# ---------------------------------------------------------------------------

def test_binwalk_offset_zero_outer_container_not_reported():
    from argus_img.detectors.embedded_content import _parse_binwalk_data_lines

    # Binwalk output where first line is offset 0 JPEG
    stdout = """DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard
12345         0x3039          ELF, 64-bit LSB executable"""
    matches = _parse_binwalk_data_lines(stdout)
    assert len(matches) == 1, "offset-zero JPEG should be excluded, nested ELF should remain"
    assert matches[0][0] == 12345
    assert "ELF" in matches[0][1]


def test_binwalk_no_nested_payload_is_clean():
    from argus_img.detectors.embedded_content import _parse_binwalk_data_lines

    stdout = """DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 800 x 600, 8-bit/color RGB"""
    matches = _parse_binwalk_data_lines(stdout)
    assert matches == [], "offset-zero PNG outer container must not produce a match"


def test_binwalk_nested_elf_produces_quarantine_finding():
    from argus_img.subprocesses.runner import ToolResult
    from argus_img.detectors.embedded_content import run_binwalk

    fake_result = ToolResult(
        args=["binwalk", "--quiet", "/tmp/snapshot"],
        stdout=(
            "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
            "--------------------------------------------------------------------------------\n"
            "0             0x0             JPEG image data\n"
            "9999          0x270F          ELF, 64-bit LSB executable\n"
        ),
        stderr="",
        returncode=0,
        timed_out=False,
        duration_ms=60.0,
        error=None,
    )
    with patch("argus_img.detectors.embedded_content._binwalk_path", return_value="/usr/bin/binwalk"), \
         patch("argus_img.detectors.embedded_content.executable_version", return_value="2.x"), \
         patch("argus_img.detectors.embedded_content.run_tool", return_value=fake_result):
        report = run_binwalk(Path("/tmp/snapshot"), "artifact:scan:orig", "scan:test:5", 30.0)

    assert report.execution.status == DetectorStatus.DETECTED
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.type == "embedded_executable"
    assert f.recommended_action == PolicyAction.QUARANTINE
    assert f.evidence["offset"] == 9999


# ---------------------------------------------------------------------------
# No release grant on detected malware
# ---------------------------------------------------------------------------

def test_clamav_detection_pipeline_quarantines_no_grant(fixture_path, app_config):
    """Simulate ClamAV detecting malware in pipeline — no grant must be issued."""
    from argus_img.subprocesses.runner import ToolResult

    fake_detected = ToolResult(
        args=["clamscan", "/data/snapshot"],
        stdout="/data/snapshot: EICAR.Test.File FOUND\n",
        stderr="",
        returncode=1,
        timed_out=False,
        duration_ms=50.0,
        error=None,
    )

    with patch("argus_img.orchestration.pipeline.run_clamav") as mock_clamav:
        # Build a DetectorReport as if ClamAV actually detected malware
        from argus_img.core.models import DetectorReport, DetectorManifest
        from argus_img.detectors.malware import _make_clamav_finding

        def _detected_clamav(snapshot_path, artifact_id, scan_id, timeout, max_output_bytes=512000):
            execution = DetectorExecution(
                detector_id="detector:malware-clamav",
                status=DetectorStatus.DETECTED,
                state=EpistemicState.CONFIRMED,
                family="malware",
                category="malware",
            )
            return DetectorReport(
                manifest=DetectorManifest(
                    detector_id="detector:malware-clamav",
                    name="ClamAV",
                    family="malware",
                ),
                execution=execution,
                findings=[_make_clamav_finding(artifact_id, scan_id, "EICAR.Test.File", None)],
            )

        mock_clamav.side_effect = _detected_clamav
        request = ScanRequest(
            original_filename="clean.png",
            use_profile=UseProfile.HUMAN_VIEW,
        )
        report = scan_file(fixture_path / "clean.png", request, app_config)

    assert report.release_grants == [], "detected malware must produce no release grants"
    assert report.decision.action in {PolicyAction.QUARANTINE, PolicyAction.BLOCK}
    malware_findings = [f for f in report.findings if f.category == "malware"]
    assert malware_findings, "must have at least one malware finding"
    clamav_exec = next(
        (e for e in report.detector_executions if e.detector_id == "detector:malware-clamav"), None
    )
    assert clamav_exec is not None
    assert clamav_exec.status == DetectorStatus.DETECTED


def test_yara_detection_pipeline_quarantines_no_grant(fixture_path, app_config, tmp_path):
    """Simulate YARA matching in pipeline — no grant must be issued."""
    from argus_img.subprocesses.runner import ToolResult

    rule_bundle = tmp_path / "rules.yar"
    rule_bundle.write_bytes(b"rule TestMalware { condition: true }")
    bundle_hash = "sha256:" + hashlib.sha256(rule_bundle.read_bytes()).hexdigest()

    app_config.yara.enabled = True
    app_config.yara.rule_bundle_path = str(rule_bundle)
    app_config.yara.rule_bundle_sha256 = bundle_hash

    with patch("argus_img.orchestration.pipeline.run_yara") as mock_yara:
        from argus_img.core.models import DetectorReport, DetectorManifest
        from argus_img.detectors.malware import _make_yara_findings

        def _detected_yara(snapshot_path, artifact_id, scan_id, timeout, rule_bundle_path=None,
                           rule_bundle_sha256=None, max_output_bytes=512000):
            execution = DetectorExecution(
                detector_id="detector:malware-yara",
                status=DetectorStatus.DETECTED,
                state=EpistemicState.CONFIRMED,
                family="malware",
                category="malware",
            )
            findings = _make_yara_findings(
                artifact_id, scan_id,
                [{"rule_id": "SuspiciousRule", "namespace": "default", "tags": [], "filepath": ""}],
                rule_bundle,
                bundle_hash,
            )
            return DetectorReport(
                manifest=DetectorManifest(
                    detector_id="detector:malware-yara",
                    name="YARA",
                    family="malware",
                ),
                execution=execution,
                findings=findings,
            )

        mock_yara.side_effect = _detected_yara
        request = ScanRequest(
            original_filename="clean.png",
            use_profile=UseProfile.HUMAN_VIEW,
        )
        report = scan_file(fixture_path / "clean.png", request, app_config)

    assert report.release_grants == [], "YARA detection must produce no release grants"
    assert report.decision.action in {PolicyAction.QUARANTINE, PolicyAction.BLOCK}


def test_detected_without_finding_in_pipeline_blocks_grant(fixture_path, app_config):
    """If a detector returns DETECTED but the adapter produces no finding, pipeline must BLOCK."""
    from argus_img.subprocesses.runner import ToolResult
    from argus_img.detectors import malware as malware_module
    from argus_img.core.models import DetectorExecution, DetectorReport, DetectorManifest

    def _bad_clamav(*args, **kwargs):
        # Returns DETECTED but no findings — simulates a broken adapter
        execution = DetectorExecution(
            detector_id="detector:malware-clamav",
            status=DetectorStatus.DETECTED,
            state=EpistemicState.CONFIRMED,
            family="malware",
            category="malware",
        )
        return DetectorReport(
            manifest=DetectorManifest(
                detector_id="detector:malware-clamav",
                name="ClamAV",
                family="malware",
            ),
            execution=execution,
            findings=[],  # Intentionally no findings — invariant violation
        )

    with patch("argus_img.orchestration.pipeline.run_clamav", side_effect=_bad_clamav):
        request = ScanRequest(
            original_filename="clean.png",
            use_profile=UseProfile.HUMAN_VIEW,
        )
        report = scan_file(fixture_path / "clean.png", request, app_config)

    assert report.release_grants == [], "DETECTED without finding must produce no grants"
    assert report.decision.action in {PolicyAction.BLOCK, PolicyAction.QUARANTINE, PolicyAction.UNSUPPORTED}


# ---------------------------------------------------------------------------
# VLM_READ_ONLY always UNSUPPORTED
# ---------------------------------------------------------------------------

def test_vlm_read_only_always_unsupported(fixture_path, app_config):
    request = ScanRequest(original_filename="clean.png", use_profile=UseProfile.VLM_READ_ONLY)
    report = scan_file(fixture_path / "clean.png", request, app_config)
    assert report.decision.action == PolicyAction.UNSUPPORTED
    assert report.release_grants == []
    assert "VLM_ANALYZER_NOT_AVAILABLE" in report.decision.reason_codes


def test_vlm_read_only_coverage_returns_unsupported():
    registry = load_detector_registry()
    executions = [
        _exec("detector:metadata-builtin", DetectorStatus.NO_EVIDENCE, EpistemicState.NO_EVIDENCE_FOUND),
        _exec("detector:prompt-rules", DetectorStatus.NO_EVIDENCE, EpistemicState.NO_EVIDENCE_FOUND),
    ]
    decision = mandatory_coverage_decision(UseProfile.VLM_READ_ONLY, registry, executions)
    assert decision is not None
    assert decision.action == PolicyAction.UNSUPPORTED
    assert "VLM_ANALYZER_NOT_AVAILABLE" in decision.reason_codes


# ---------------------------------------------------------------------------
# RAG_INGESTION is strict
# ---------------------------------------------------------------------------

def test_rag_ingestion_is_in_strict_profiles():
    assert UseProfile.RAG_INGESTION in STRICT_PROFILES


def test_rag_ingestion_fails_without_malware_coverage():
    registry = load_detector_registry()
    executions = [
        _exec("detector:metadata-builtin", DetectorStatus.NO_EVIDENCE, EpistemicState.NO_EVIDENCE_FOUND),
        _exec("detector:prompt-rules", DetectorStatus.NO_EVIDENCE, EpistemicState.NO_EVIDENCE_FOUND),
        # malware detectors absent
    ]
    decision = mandatory_coverage_decision(UseProfile.RAG_INGESTION, registry, executions)
    assert decision is not None
    assert decision.action == PolicyAction.UNSUPPORTED


# ---------------------------------------------------------------------------
# Mode differentiation
# ---------------------------------------------------------------------------

def test_fast_mode_does_not_run_otsu_or_enlargement(fixture_path, app_config):
    request = ScanRequest(original_filename="clean.png", mode=ScanMode.FAST, use_profile=UseProfile.HUMAN_VIEW)
    report = scan_file(fixture_path / "clean.png", request, app_config)
    artifact_roles = set(report.artifacts.keys())
    # Fast mode must NOT produce these deep-only transforms
    assert "otsu-threshold" not in artifact_roles, "fast mode must not run Otsu threshold"
    assert "inverted-grayscale" not in artifact_roles, "fast mode must not run inverted grayscale"
    assert "2x-enlargement" not in artifact_roles, "fast mode must not run 2x enlargement"


def test_fast_mode_produces_channel_views(fixture_path, app_config):
    request = ScanRequest(original_filename="clean.png", mode=ScanMode.FAST, use_profile=UseProfile.HUMAN_VIEW)
    report = scan_file(fixture_path / "clean.png", request, app_config)
    artifact_roles = set(report.artifacts.keys())
    for channel in ("red-channel", "green-channel", "blue-channel"):
        assert channel in artifact_roles, "fast mode must produce %s" % channel


def test_deep_mode_produces_otsu_and_enlargement(fixture_path, app_config):
    request = ScanRequest(original_filename="clean.png", mode=ScanMode.DEEP, use_profile=UseProfile.HUMAN_VIEW)
    report = scan_file(fixture_path / "clean.png", request, app_config)
    artifact_roles = set(report.artifacts.keys())
    assert "otsu-threshold" in artifact_roles, "deep mode must run Otsu threshold"
    assert "2x-enlargement" in artifact_roles, "deep mode must run 2x enlargement"


def test_forensic_mode_has_more_detectors_than_fast():
    from argus_img.orchestration.mode_plan import FAST_PLAN, FORENSIC_PLAN
    assert FAST_PLAN.active_detectors < FORENSIC_PLAN.active_detectors


def test_deep_mode_artifact_count_exceeds_fast(fixture_path, app_config):
    fast_report = scan_file(
        fixture_path / "clean.png",
        ScanRequest(original_filename="clean.png", mode=ScanMode.FAST, use_profile=UseProfile.HUMAN_VIEW),
        app_config,
    )
    deep_report = scan_file(
        fixture_path / "clean.png",
        ScanRequest(original_filename="clean.png", mode=ScanMode.DEEP, use_profile=UseProfile.HUMAN_VIEW),
        app_config,
    )
    assert len(deep_report.artifacts) > len(fast_report.artifacts), (
        "deep mode must produce more artifacts than fast mode"
    )


# ---------------------------------------------------------------------------
# Atomic persistence
# ---------------------------------------------------------------------------

def test_atomic_persistence_report_and_grant_committed_together(fixture_path, app_config):
    from argus_img.artifacts.store import ArtifactStore
    from argus_img.core.models import ReleaseGrant

    request = ScanRequest(original_filename="clean.png", use_profile=UseProfile.HUMAN_VIEW)
    report = scan_file(fixture_path / "clean.png", request, app_config)

    store = ArtifactStore(Path(app_config.data_dir))
    # Report must be persisted
    loaded = store.load_report(report.scan_id)
    assert report.scan_id in loaded

    # Grants in DB must match report
    db_grants = store.grants_for_scan(report.scan_id)
    assert len(db_grants) == len(report.release_grants)
    if db_grants:
        db_ids = {g.artifact_id for g in db_grants}
        report_ids = {g.artifact_id for g in report.release_grants}
        assert db_ids == report_ids


# ---------------------------------------------------------------------------
# Retention and grant revocation
# ---------------------------------------------------------------------------

def test_revoke_expired_grants(app_config):
    from argus_img.artifacts.store import ArtifactStore
    from argus_img.core.models import Artifact, PolicyDecision

    store = ArtifactStore(Path(app_config.data_dir))

    # Create a dummy artifact and grant it
    data = b"fake jpeg content" * 100
    artifact = store.store_bytes(
        data,
        artifact_id="artifact:scan-expire:canonical_lossy",
        media_type="image/jpeg",
        created_by="test",
        role="canonical_lossy",
        release_eligible=False,
    )
    # Manually insert a grant with old timestamp
    import sqlite3, json
    from argus_img.core.models import ReleaseGrant
    grant = ReleaseGrant(
        grant_id="grant:scan-expire:test",
        scan_id="scan-expire",
        artifact_id=artifact.artifact_id,
        sha256=artifact.sha256,
        role=artifact.role,
        action=PolicyAction.ALLOW_RECONSTRUCTED_ONLY,
        media_type=artifact.media_type,
        reason="test",
    )
    conn = sqlite3.connect(str(store.db_path))
    conn.row_factory = sqlite3.Row
    old_ts = time.time() - 10000  # 10000s ago
    conn.execute(
        "INSERT OR REPLACE INTO release_grants (grant_id, scan_id, artifact_id, payload, created_at) VALUES (?,?,?,?,?)",
        (grant.grant_id, grant.scan_id, grant.artifact_id, grant.model_dump_json(), old_ts),
    )
    conn.execute(
        "UPDATE artifacts SET release_eligible = 1 WHERE artifact_id = ?",
        (artifact.artifact_id,),
    )
    conn.commit()
    conn.close()

    revoked = store.revoke_expired_grants(grant_max_age_seconds=100)
    assert grant.grant_id in revoked

    # Artifact should no longer be release_eligible
    a2 = store.get_artifact(artifact.artifact_id, release_only=False)
    assert a2.release_eligible is False


def test_expire_old_reports(app_config):
    from argus_img.artifacts.store import ArtifactStore

    store = ArtifactStore(Path(app_config.data_dir))
    # Insert an old report
    import sqlite3
    conn = sqlite3.connect(str(store.db_path))
    old_ts = time.time() - 9999
    conn.execute(
        "INSERT OR REPLACE INTO reports (scan_id, payload, created_at) VALUES (?,?,?)",
        ("scan-old-expired", '{"expired": true}', old_ts),
    )
    conn.commit()
    conn.close()
    (store.reports_dir / "scan-old-expired.json").write_text('{"expired": true}')

    deleted = store.expire_old_reports(max_age_seconds=100)
    assert "scan-old-expired" in deleted
    # Report file should be gone
    assert not (store.reports_dir / "scan-old-expired.json").exists()


# ---------------------------------------------------------------------------
# Worker launcher: timeout via communicate
# ---------------------------------------------------------------------------

def test_worker_timeout_raises_worker_timeout_error(tmp_path):
    """Worker that sleeps forever must raise WorkerTimeoutError, not hang."""
    from argus_img.workers.launcher import launch_parser_worker
    from argus_img.workers.protocol import WorkerRequest
    from argus_img.workers.errors import WorkerTimeoutError
    import subprocess

    request = WorkerRequest(
        scan_id="scan:worker-timeout:1",
        job_dir=str(tmp_path),
        snapshot_path=str(tmp_path / "snap.png"),
    )

    # Patch Popen to use a subprocess that sleeps indefinitely (or exits after a delay)
    real_popen = subprocess.Popen

    class SlowPopen:
        def __init__(self, *args, **kwargs):
            import sys
            self._proc = real_popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.pid = self._proc.pid
            self.stdin = self._proc.stdin
            self.stdout = self._proc.stdout
            self.stderr = self._proc.stderr
            self.returncode = None

        def communicate(self, input=None, timeout=None):
            raise subprocess.TimeoutExpired(cmd="test", timeout=timeout)

        def kill(self):
            try:
                self._proc.kill()
                self._proc.wait(timeout=2)
            except Exception:
                pass

    with patch("argus_img.workers.launcher.subprocess.Popen", SlowPopen):
        with pytest.raises(WorkerTimeoutError):
            launch_parser_worker(request, tmp_path, wall_clock_timeout=0.1)


# ---------------------------------------------------------------------------
# Control-side artifact verification: hash mismatch
# ---------------------------------------------------------------------------

def test_control_verification_rejects_hash_mismatch(tmp_path):
    """Artifact whose SHA-256 doesn't match claimed value must be rejected."""
    from argus_img.workers.validation import _verify_artifact
    from argus_img.workers.protocol import ArtifactRecord
    from argus_img.workers.errors import WorkerResponseError

    artifact_file = tmp_path / "artifact.png"
    artifact_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

    record = ArtifactRecord(
        artifact_id="artifact:test:bad-hash",
        sha256="sha256:" + "a" * 64,  # wrong hash
        role="canonical_lossless",
        media_type="image/png",
        size_bytes=len(artifact_file.read_bytes()),
        path=str(artifact_file),
    )

    with pytest.raises(WorkerResponseError, match="SHA-256 mismatch"):
        _verify_artifact(record, tmp_path)


def test_control_verification_rejects_path_escape(tmp_path):
    """Artifact path outside job_dir must be rejected."""
    from argus_img.workers.validation import _verify_artifact
    from argus_img.workers.protocol import ArtifactRecord
    from argus_img.workers.errors import WorkerPathEscapeError

    outside_file = tmp_path.parent / "escape.png"
    try:
        outside_file.write_bytes(b"x" * 10)
        record = ArtifactRecord(
            artifact_id="artifact:test:escape",
            sha256="sha256:" + "a" * 64,
            role="canonical_lossless",
            media_type="image/png",
            size_bytes=10,
            path=str(outside_file),
        )
        with pytest.raises(WorkerPathEscapeError):
            _verify_artifact(record, tmp_path)
    finally:
        if outside_file.exists():
            outside_file.unlink()


def test_control_verification_rejects_nonexistent_file(tmp_path):
    """Artifact file that does not exist must be rejected."""
    from argus_img.workers.validation import _verify_artifact
    from argus_img.workers.protocol import ArtifactRecord
    from argus_img.workers.errors import WorkerResponseError

    record = ArtifactRecord(
        artifact_id="artifact:test:missing",
        sha256="sha256:" + "a" * 64,
        role="canonical_lossless",
        media_type="image/png",
        size_bytes=10,
        path=str(tmp_path / "nonexistent.png"),
    )
    with pytest.raises(WorkerResponseError, match="does not exist"):
        _verify_artifact(record, tmp_path)
