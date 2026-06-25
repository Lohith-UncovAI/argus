"""Real embedded-content detector adapter for Binwalk.

Runs binwalk in analysis-only mode (no extraction) against the immutable
snapshot. Extraction, when needed for forensic mode, must occur inside the
isolated worker with its own resource limits.
"""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus_img.core.enums import DetectorStatus, EpistemicState
from argus_img.core.models import DetectorExecution, DetectorReport, ModuleStatus
from argus_img.subprocesses.runner import ToolResult, executable_version, run_tool


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _binwalk_path() -> Optional[str]:
    return shutil.which("binwalk")


def embedded_tool_statuses() -> dict:
    return {
        "binwalk": ModuleStatus(
            name="binwalk",
            status=EpistemicState.NOT_TESTED if _binwalk_path() else EpistemicState.UNSUPPORTED,
            reason=None if _binwalk_path() else "tool_not_installed",
        )
    }


def _parse_binwalk_output(result: ToolResult) -> tuple[DetectorStatus, EpistemicState, Optional[str]]:
    """Parse binwalk stdout into (status, state, reason)."""
    if result.timed_out:
        return DetectorStatus.TIMEOUT, EpistemicState.INCONCLUSIVE, "binwalk timed out"
    if result.error:
        return DetectorStatus.ERROR, EpistemicState.ERROR, result.error
    returncode = result.returncode
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if returncode is None:
        return DetectorStatus.ERROR, EpistemicState.ERROR, "binwalk did not complete"
    if returncode != 0:
        msg = stderr or stdout or "binwalk error: rc=%s" % returncode
        return DetectorStatus.ERROR, EpistemicState.ERROR, msg
    # Binwalk output contains table rows for each found signature.
    # A file with no embedded payloads produces only header lines (DECIMAL, etc.)
    data_lines = [
        line for line in stdout.splitlines()
        if line.strip() and not line.strip().startswith("DECIMAL") and not line.strip().startswith("-")
    ]
    if data_lines:
        return DetectorStatus.DETECTED, EpistemicState.CONFIRMED, data_lines[0][:200]
    return DetectorStatus.NO_EVIDENCE, EpistemicState.NO_EVIDENCE_FOUND, None


def run_binwalk(
    snapshot_path: Path,
    artifact_id: str,
    scan_id: str,
    timeout: float,
    max_output_bytes: int = 512_000,
) -> DetectorReport:
    from argus_img.core.models import DetectorManifest

    started = _utc_now()
    binwalk_bin = _binwalk_path()
    if not binwalk_bin:
        execution = DetectorExecution(
            detector_id="detector:embedded-binwalk",
            status=DetectorStatus.UNSUPPORTED,
            state=EpistemicState.UNSUPPORTED,
            family="embedded_payload",
            category="embedded_payload",
            required=False,
            started_at=started,
            completed_at=_utc_now(),
            reason="tool_not_installed",
        )
        return DetectorReport(
            manifest=DetectorManifest(
                detector_id="detector:embedded-binwalk",
                name="Binwalk",
                family="embedded_payload",
            ),
            execution=execution,
        )

    version = executable_version(binwalk_bin, "--help", timeout=min(2.0, timeout))
    # Run in signature-only mode — no extraction, no recursive analysis
    result = run_tool(
        [binwalk_bin, "--quiet", str(snapshot_path)],
        timeout=timeout,
        max_output_bytes=max_output_bytes,
    )
    completed = _utc_now()
    status, state, reason = _parse_binwalk_output(result)
    execution = DetectorExecution(
        detector_id="detector:embedded-binwalk",
        status=status,
        state=state,
        family="embedded_payload",
        category="embedded_payload",
        required=False,
        started_at=started,
        completed_at=completed,
        duration_ms=result.duration_ms,
        reason=reason,
        tool_version=version,
    )
    return DetectorReport(
        manifest=DetectorManifest(
            detector_id="detector:embedded-binwalk",
            name="Binwalk",
            family="embedded_payload",
            version=version or "unknown",
        ),
        execution=execution,
        errors=[reason] if status == DetectorStatus.ERROR else [],
    )
