from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from PIL import ExifTags, Image

from argus_img.core.enums import DetectorStatus, EpistemicState, PolicyAction
from argus_img.core.models import DetectorFinding, DetectorReport, ModuleStatus, TextObservation
from argus_img.detectors.base import detector_report
from argus_img.detectors.prompt.normalizer import normalize_text
from argus_img.reporting.excerpts import text_evidence
from argus_img.subprocesses.runner import executable_version, run_tool


TEXT_KEYS = {"title", "subject", "description", "comment", "usercomment", "keywords", "author", "software"}
LOCATION_KEYS = {
    "gpslatitude",
    "gpslongitude",
    "gpsposition",
    "gpsaltitude",
    "gpslatituderef",
    "gpslongituderef",
    "gpscoordinates",
    "location",
}
IDENTITY_KEYS = {"artist", "author", "creator", "ownername", "serialnumber", "copyright"}
WORKFLOW_KEYS = {"software", "creator tool", "history", "processingsoftware", "imagedescription"}
PROVENANCE_KEYS = {"c2pa", "jumbf", "xmp", "photoshop", "iptc", "creatorworkurl"}
FREE_TEXT_KEYS = TEXT_KEYS | IDENTITY_KEYS | WORKFLOW_KEYS | {"caption", "headline", "label", "credit", "source", "rights"}
MAX_METADATA_TEXT_CHARS = 100_000


def _canonical_key(key: str) -> str:
    leaf = key.rsplit(":", 1)[-1]
    return leaf.replace(" ", "").replace("_", "").replace("-", "").lower()


def _stringify_metadata_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        scalar_values = [str(item) for item in value if isinstance(item, (str, int, float, bool))]
        return ", ".join(scalar_values) if scalar_values else None
    return None


def classify_metadata_field(key: str, value: Any) -> str:
    canonical = _canonical_key(key)
    if canonical in LOCATION_KEYS or canonical.startswith("gps"):
        return "location_data"
    if canonical in IDENTITY_KEYS:
        return "identity_data"
    if canonical in WORKFLOW_KEYS:
        return "workflow_data"
    if any(marker in canonical for marker in PROVENANCE_KEYS):
        return "provenance_data"
    if isinstance(value, (dict, tuple)):
        return "unexpected_structure"
    if isinstance(value, (bytes, bytearray)):
        return "binary_blob"
    text = _stringify_metadata_value(value)
    if text is None:
        return "binary_blob"
    if canonical in FREE_TEXT_KEYS:
        return "free_text"
    if len(text) > 40 and any(ch.isspace() for ch in text):
        return "free_text"
    return "ordinary_camera_data"


def _should_emit_text_observation(classification: str) -> bool:
    return classification in {"free_text", "identity_data", "workflow_data", "provenance_data"}


def _gps_present(fields: Iterable[Tuple[str, Any]]) -> bool:
    return any(classify_metadata_field(key, value) == "location_data" for key, value in fields)


def _privacy_reason_for_classification(classification: str) -> Optional[str]:
    if classification == "identity_data":
        return "IDENTITY_METADATA_PRESENT"
    if classification == "location_data":
        return "GPS_PRESENT"
    return None


def _metadata_pairs(path: Path) -> Tuple[List[Tuple[str, str]], bool]:
    pairs: List[Tuple[str, str]] = []
    gps_present = False
    with Image.open(path) as image:
        for key, value in image.info.items():
            if isinstance(value, str):
                pairs.append((str(key), value))
            elif isinstance(value, bytes):
                try:
                    decoded = value.decode("utf-8")
                    if decoded.strip():
                        pairs.append((str(key), decoded))
                except UnicodeDecodeError:
                    pass
        exif = image.getexif()
        if exif:
            for key, value in exif.items():
                name = ExifTags.TAGS.get(key, str(key))
                if name == "GPSInfo":
                    gps_present = True
                    continue
                lower = str(name).lower()
                if lower in TEXT_KEYS or isinstance(value, str):
                    pairs.append((str(name), str(value)))
    return pairs, gps_present


def analyze_builtin_metadata(
    path: Path,
    artifact_id: str,
    scan_id: str,
    include_raw_text: bool = False,
) -> DetectorReport:
    observations: List[TextObservation] = []
    findings: List[DetectorFinding] = []
    try:
        pairs, gps_present = _metadata_pairs(path)
    except Exception as exc:
        return detector_report(
            "detector:metadata-builtin",
            "metadata",
            DetectorStatus.ERROR,
            EpistemicState.ERROR,
            reason=str(exc),
            category="privacy",
            required=True,
        )
    for index, (key, value) in enumerate(pairs):
        text = value[:100_000]
        obs = TextObservation(
            observation_id="observation:%s:metadata:%03d" % (scan_id, index),
            source_artifact_id=artifact_id,
            detector_id="detector:metadata-builtin",
            raw_text=text,
            normalized_text=normalize_text(text).normalized,
            engine="pillow-metadata",
            confidence=1.0,
            value={"metadata_key": key, "classification": "free_text"},
        )
        observations.append(obs)
    if gps_present:
        findings.append(
            DetectorFinding(
                finding_id="finding:%s:gps-metadata" % scan_id,
                category="privacy",
                type="gps_metadata",
                state=EpistemicState.CONFIRMED,
                severity="medium",
                evidence_quality=0.9,
                impact="medium",
                source_artifact_ids=[artifact_id],
                detector_ids=["detector:metadata-builtin"],
                reason_codes=["GPS_PRESENT"],
                recommended_action=PolicyAction.ALLOW_WITH_REDACTION,
                evidence={"gps_present": True, "precision": "unknown", "value_redacted": True},
            )
        )
    state = EpistemicState.CONFIRMED if observations or findings else EpistemicState.NO_EVIDENCE_FOUND
    status = DetectorStatus.SUCCESS if observations or findings else DetectorStatus.NO_EVIDENCE
    return detector_report(
        "detector:metadata-builtin",
        "metadata",
        status,
        state,
        findings,
        observations,
        category="privacy",
        required=True,
    )


def _exiftool_privacy_finding(
    scan_id: str,
    artifact_id: str,
    classification: str,
    reason_code: str,
    observation_ids: Optional[List[str]] = None,
) -> DetectorFinding:
    if reason_code == "GPS_PRESENT":
        finding_type = "gps_metadata"
        evidence = {"gps_present": True, "precision": "exact_or_declared", "value_redacted": True}
    else:
        finding_type = "identity_metadata"
        evidence = {"classification": classification, "value_redacted": True}
    return DetectorFinding(
        finding_id="finding:%s:exiftool:%s" % (scan_id, reason_code.lower().replace("_", "-")),
        category="privacy",
        type=finding_type,
        state=EpistemicState.CONFIRMED,
        severity="medium",
        evidence_quality=0.9,
        impact="medium",
        source_artifact_ids=[artifact_id],
        observation_ids=observation_ids or [],
        detector_ids=["detector:exiftool"],
        reason_codes=[reason_code],
        recommended_action=PolicyAction.ALLOW_WITH_REDACTION,
        evidence=evidence,
    )


def _parse_exiftool_records(stdout: str) -> Dict[str, Any]:
    parsed = json.loads(stdout)
    if not isinstance(parsed, list) or not parsed:
        return {}
    first = parsed[0]
    if not isinstance(first, dict):
        return {}
    return first


def analyze_with_exiftool(
    path: Path,
    artifact_id: str,
    scan_id: str,
    timeout_seconds: int,
    max_metadata_bytes: int,
    include_raw_text: bool = False,
    executable: str = "exiftool",
) -> DetectorReport:
    """Run ExifTool in JSON mode and convert metadata into evidence.

    ExifTool runs only through the central subprocess runner. This adapter does
    not extract embedded files and never fetches remote resources.
    """

    if not shutil.which(executable) and "/" not in executable:
        return detector_report(
            "detector:exiftool",
            "metadata",
            DetectorStatus.TOOL_NOT_INSTALLED,
            EpistemicState.UNSUPPORTED,
            reason="tool_not_installed",
            optional=True,
            category="privacy",
        )
    result = run_tool(
        [executable, "-config", os.devnull, "-j", "-G1", "-s", "-charset", "filename=utf8", str(path)],
        timeout=timeout_seconds,
        cwd=path.parent,
        max_output_bytes=max_metadata_bytes,
    )
    version = executable_version(executable, "-ver") if "/" not in executable else None
    if result.timed_out:
        report = detector_report(
            "detector:exiftool",
            "metadata",
            DetectorStatus.TIMEOUT,
            EpistemicState.ERROR,
            reason="timeout",
            optional=True,
            category="privacy",
        )
        report.execution.tool_version = version
        return report
    if result.error == "executable_not_found":
        return detector_report(
            "detector:exiftool",
            "metadata",
            DetectorStatus.TOOL_NOT_INSTALLED,
            EpistemicState.UNSUPPORTED,
            reason="tool_not_installed",
            optional=True,
            category="privacy",
        )
    if result.returncode not in (0,):
        report = detector_report(
            "detector:exiftool",
            "metadata",
            DetectorStatus.ERROR,
            EpistemicState.ERROR,
            reason=(result.stderr or result.error or "exiftool_failed")[:300],
            optional=True,
            category="privacy",
        )
        report.execution.tool_version = version
        return report
    try:
        fields = _parse_exiftool_records(result.stdout)
    except json.JSONDecodeError as exc:
        report = detector_report(
            "detector:exiftool",
            "metadata",
            DetectorStatus.ERROR,
            EpistemicState.ERROR,
            reason="invalid_json: %s" % exc,
            optional=True,
            category="privacy",
        )
        report.execution.tool_version = version
        return report

    observations: List[TextObservation] = []
    findings: List[DetectorFinding] = []
    privacy_observation_ids: Dict[str, List[str]] = {}
    metadata_fields = [(key, value) for key, value in fields.items() if key != "SourceFile"]
    for key, value in metadata_fields:
        classification = classify_metadata_field(key, value)
        reason_code = _privacy_reason_for_classification(classification)
        text = _stringify_metadata_value(value)
        observation_id = None
        if text and _should_emit_text_observation(classification):
            bounded_text = text[:MAX_METADATA_TEXT_CHARS]
            if classification == "location_data":
                bounded_text = "[redacted-location-metadata]"
            observation = TextObservation(
                observation_id="observation:%s:exiftool:%03d" % (scan_id, len(observations)),
                source_artifact_id=artifact_id,
                detector_id="detector:exiftool",
                raw_text=bounded_text,
                normalized_text=normalize_text(bounded_text).normalized,
                engine="exiftool",
                engine_version=version,
                confidence=1.0,
                value={"metadata_key": key, "classification": classification},
            )
            observations.append(observation)
            observation_id = observation.observation_id
        if reason_code:
            privacy_observation_ids.setdefault(reason_code, [])
            if observation_id:
                privacy_observation_ids[reason_code].append(observation_id)

    if _gps_present(metadata_fields):
        findings.append(
            _exiftool_privacy_finding(
                scan_id,
                artifact_id,
                "location_data",
                "GPS_PRESENT",
                privacy_observation_ids.get("GPS_PRESENT", []),
            )
        )
    if privacy_observation_ids.get("IDENTITY_METADATA_PRESENT"):
        findings.append(
            _exiftool_privacy_finding(
                scan_id,
                artifact_id,
                "identity_data",
                "IDENTITY_METADATA_PRESENT",
                privacy_observation_ids["IDENTITY_METADATA_PRESENT"],
            )
        )
    state = EpistemicState.CONFIRMED if observations or findings else EpistemicState.NO_EVIDENCE_FOUND
    status = DetectorStatus.SUCCESS if observations or findings else DetectorStatus.NO_EVIDENCE
    report = detector_report(
        "detector:exiftool",
        "metadata",
        status,
        state,
        findings,
        observations,
        optional=True,
        category="privacy",
    )
    report.execution.tool_version = version
    return report


def exiftool_status(report: Optional[DetectorReport] = None) -> ModuleStatus:
    if report is not None:
        return ModuleStatus(
            name="exiftool",
            status=report.execution.state,
            reason=report.execution.reason,
            version=report.execution.tool_version,
        )
    if shutil.which("exiftool"):
        return ModuleStatus(name="exiftool", status=EpistemicState.NOT_TESTED, reason="adapter not run")
    return ModuleStatus(name="exiftool", status=EpistemicState.UNSUPPORTED, reason="tool_not_installed")


def metadata_prompt_evidence(text: str, include_raw_text: bool) -> dict:
    evidence = text_evidence(text, include_raw_text=include_raw_text)
    evidence["source"] = "metadata"
    return evidence
