"""Real embedded-content detector adapter for Binwalk.

Runs binwalk in analysis-only mode (no extraction) against the immutable
snapshot. Extraction, when needed for forensic mode, must occur inside the
isolated worker with its own resource limits.

Offset-zero invariant: the outer image signature at byte offset 0 is expected
and is NOT treated as an embedded payload. Only nested, appended or anomalous
signatures (non-zero offset) produce findings.
"""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from argus_img.core.enums import DetectorStatus, EpistemicState, PolicyAction
from argus_img.core.models import DetectorExecution, DetectorFinding, DetectorReport, ModuleStatus
from argus_img.subprocesses.runner import ToolResult, executable_version, run_tool

# These description fragments indicate the outer container (not an embedded payload).
_OUTER_CONTAINER_DESCRIPTIONS = frozenset({
    "jpeg", "png", "gif", "webp", "bmp", "tiff", "tif", "avif", "heif", "heic",
    "jfif", "exif", "image data", "bitmap",
})


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


def _is_outer_container_at_zero(line: str) -> bool:
    """Return True if this binwalk line looks like the expected outer container at offset 0."""
    parts = line.strip().split()
    if not parts:
        return False
    # First token is decimal offset, second is hex offset, rest is description
    try:
        offset = int(parts[0])
    except ValueError:
        return False
    if offset != 0:
        return False
    description = " ".join(parts[2:]).lower() if len(parts) > 2 else ""
    for keyword in _OUTER_CONTAINER_DESCRIPTIONS:
        if keyword in description:
            return True
    return False


def _parse_binwalk_data_lines(stdout: str) -> List[Tuple[int, str]]:
    """Return (offset, description) pairs for non-header, non-outer lines."""
    results = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("DECIMAL") or stripped.startswith("-"):
            continue
        if _is_outer_container_at_zero(stripped):
            continue
        parts = stripped.split()
        try:
            offset = int(parts[0])
        except (ValueError, IndexError):
            continue
        description = " ".join(parts[2:]) if len(parts) > 2 else stripped
        results.append((offset, description))
    return results


def _make_binwalk_findings(
    artifact_id: str,
    scan_id: str,
    matches: List[Tuple[int, str]],
) -> List[DetectorFinding]:
    findings = []
    for i, (offset, description) in enumerate(matches):
        desc_lower = description.lower()
        sig_type = "embedded_executable" if any(
            kw in desc_lower for kw in ("executable", "elf", "pe32", "mz ", "dos ", "script", "shell")
        ) else "embedded_payload"
        findings.append(DetectorFinding(
            finding_id="finding:%s:binwalk-%d" % (scan_id, i),
            category="embedded_payload",
            type=sig_type,
            state=EpistemicState.CONFIRMED,
            severity="critical" if sig_type == "embedded_executable" else "high",
            evidence_quality=0.85,
            attack_likelihood=0.85,
            impact="critical",
            source_artifact_ids=[artifact_id],
            detector_ids=["detector:embedded-binwalk"],
            reason_codes=["NESTED_PAYLOAD_DETECTED"],
            recommended_action=PolicyAction.QUARANTINE,
            evidence={"offset": offset, "description": description[:300]},
        ))
    return findings


def _parse_binwalk_output(
    result: ToolResult,
) -> tuple[DetectorStatus, EpistemicState, Optional[str], List[Tuple[int, str]]]:
    """Parse binwalk stdout into (status, state, reason, matches)."""
    if result.timed_out:
        return DetectorStatus.TIMEOUT, EpistemicState.INCONCLUSIVE, "binwalk timed out", []
    if result.error:
        return DetectorStatus.ERROR, EpistemicState.ERROR, result.error, []
    returncode = result.returncode
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if returncode is None:
        return DetectorStatus.ERROR, EpistemicState.ERROR, "binwalk did not complete", []
    if returncode != 0:
        msg = stderr or stdout or "binwalk error: rc=%s" % returncode
        return DetectorStatus.ERROR, EpistemicState.ERROR, msg, []
    # Only nested/appended/anomalous signatures (non-zero offset) count
    matches = _parse_binwalk_data_lines(stdout)
    if matches:
        reason = "embedded payload at offset %d: %s" % (matches[0][0], matches[0][1][:100])
        return DetectorStatus.DETECTED, EpistemicState.CONFIRMED, reason, matches
    return DetectorStatus.NO_EVIDENCE, EpistemicState.NO_EVIDENCE_FOUND, None, []


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
    status, state, reason, matches = _parse_binwalk_output(result)
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
    findings: List[DetectorFinding] = []
    if status == DetectorStatus.DETECTED:
        findings = _make_binwalk_findings(artifact_id, scan_id, matches)
    return DetectorReport(
        manifest=DetectorManifest(
            detector_id="detector:embedded-binwalk",
            name="Binwalk",
            family="embedded_payload",
            version=version or "unknown",
        ),
        execution=execution,
        findings=findings,
        errors=[reason] if status == DetectorStatus.ERROR else [],
    )
