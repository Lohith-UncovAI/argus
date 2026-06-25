from __future__ import annotations

from pathlib import Path
from typing import Iterable, List
from urllib.parse import urlparse

from argus_img.core.enums import DetectorStatus, EpistemicState, PolicyAction
from argus_img.core.models import Artifact, DetectorFinding, DetectorReport, TextObservation
from argus_img.detectors.base import detector_report
from argus_img.detectors.prompt.normalizer import normalize_text
from argus_img.reporting.excerpts import text_evidence


def _local_url_analysis(text: str) -> dict:
    parsed = urlparse(text)
    if not parsed.scheme:
        return {"is_url": False}
    host = parsed.hostname or ""
    return {
        "is_url": True,
        "scheme": parsed.scheme,
        "hostname_sha256": text_evidence(host)["text_sha256"] if host else None,
        "has_embedded_credentials": bool(parsed.username or parsed.password),
        "ip_literal": host.replace(".", "").isdigit(),
        "file_url": parsed.scheme == "file",
        "suspicious_terms": [term for term in ["login", "verify", "password", "wallet", "update"] if term in parsed.path.lower()],
    }


def analyze_qr(artifact_paths: Iterable[tuple], scan_id: str, include_raw_text: bool = False) -> DetectorReport:
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
    except Exception:
        return detector_report(
            "detector:qr-pyzbar",
            "QR/barcode",
            DetectorStatus.TOOL_NOT_INSTALLED,
            EpistemicState.UNSUPPORTED,
            reason="tool_not_installed",
            optional=True,
        )
    observations: List[TextObservation] = []
    findings: List[DetectorFinding] = []
    for label, artifact, path in artifact_paths:
        try:
            decoded = decode(Image.open(Path(path)))
        except Exception:
            continue
        for item in decoded:
            try:
                text = item.data.decode("utf-8")
            except UnicodeDecodeError:
                text = item.data.hex()
            obs = TextObservation(
                observation_id="observation:%s:qr:%03d" % (scan_id, len(observations)),
                source_artifact_id=artifact.artifact_id,
                detector_id="detector:qr-pyzbar",
                raw_text=text,
                normalized_text=normalize_text(text).normalized,
                engine="pyzbar",
                confidence=1.0,
                transformation_id=artifact.transformation.transformation_id if artifact.transformation else None,
                value={"artifact_label": label, "decoded_type": item.type, "url_analysis": _local_url_analysis(text)},
            )
            observations.append(obs)
            findings.append(
                DetectorFinding(
                    finding_id="finding:%s:qr:%03d" % (scan_id, len(findings)),
                    category="embedded_payload",
                    type="qr_payload",
                    state=EpistemicState.CONFIRMED,
                    severity="medium",
                    evidence_quality=0.9,
                    impact="medium",
                    source_artifact_ids=[artifact.artifact_id],
                    observation_ids=[obs.observation_id],
                    detector_ids=["detector:qr-pyzbar"],
                    reason_codes=["QR_PAYLOAD"],
                    recommended_action=PolicyAction.REVIEW,
                    evidence=text_evidence(text, include_raw_text=include_raw_text),
                )
            )
    status = DetectorStatus.SUCCESS if observations else DetectorStatus.NO_EVIDENCE
    state = EpistemicState.CONFIRMED if observations else EpistemicState.NO_EVIDENCE_FOUND
    return detector_report("detector:qr-pyzbar", "QR/barcode", status, state, findings, observations, optional=True)

