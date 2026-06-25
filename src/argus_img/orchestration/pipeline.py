from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from argus_img import __version__
from argus_img.artifacts.cleanup import cleanup_job_dir
from argus_img.artifacts.release import apply_release_grants
from argus_img.artifacts.store import ArtifactStore
from argus_img.core.budget import ResourceBudget
from argus_img.core.config import AppConfig, load_config
from argus_img.core.detector_registry import load_detector_registry
from argus_img.core.enums import DetectorStatus, EpistemicState, PolicyAction
from argus_img.core.exceptions import IntakeRejected
from argus_img.core.hashing import sha256_file
from argus_img.core.models import (
    Artifact,
    CategoryAssessment,
    CoverageAssessment,
    DetectorExecution,
    DetectorFinding,
    DetectorReport,
    ErrorRecord,
    FileDescriptor,
    Limitation,
    ModuleStatus,
    PolicyDecision,
    ScanReport,
    ScanRequest,
    ScannerInfo,
    TextObservation,
)
from argus_img.core.offline_guard import OfflineGuard
from argus_img.decoding.differential import compare_decoders
from argus_img.decoding.frames import extract_frames
from argus_img.detectors.embedded_content import embedded_tool_statuses
from argus_img.detectors.machine_codes.qr import analyze_qr
from argus_img.detectors.malware import malware_tool_statuses
from argus_img.detectors.metadata import analyze_builtin_metadata, analyze_with_exiftool, exiftool_status
from argus_img.detectors.ocr.merge import merge_text_observations
from argus_img.detectors.ocr.paddle import paddle_status
from argus_img.detectors.ocr.tesseract import analyze_with_tesseract
from argus_img.detectors.phishing import analyze_phishing
from argus_img.detectors.privacy import analyze_privacy
from argus_img.detectors.prompt.decoders import derive_text_candidates
from argus_img.detectors.prompt.rules import PromptRuleBundle
from argus_img.detectors.provenance import provenance_status
from argus_img.detectors.redaction_analysis import redaction_analysis_status
from argus_img.detectors.steganography.statistics import image_entropy_summary
from argus_img.detectors.steganography.structural import detect_trailing_bytes
from argus_img.detectors.steganography.zsteg import zsteg_status
from argus_img.detectors.watermarks.registry import watermark_registry_status
from argus_img.detectors.watermarks.visible import analyze_visible_watermarks
from argus_img.evidence.assessment import build_assessments
from argus_img.evidence.deduplication import deduplicate_findings
from argus_img.evidence.graph import build_evidence_graph
from argus_img.intake.mime import detect_magic
from argus_img.intake.validation import validate_image_file
from argus_img.orchestration.context import create_scan_context
from argus_img.policy.engine import PolicyEngine
from argus_img.policy.coverage import mandatory_coverage_decision
from argus_img.reconstruction.canonical import create_canonical_artifacts
from argus_img.reporting.serialization import report_to_json
from argus_img.transforms.registry import generate_fast_transformations
from argus_img.transforms.stability import baseline_stability_status


def _scanner_info(request: ScanRequest, config_hash: str) -> ScannerInfo:
    return ScannerInfo(
        version=__version__,
        mode=request.mode,
        use_profile=request.use_profile,
        configuration_hash=config_hash,
    )


def _execution(
    detector_id: str,
    status: DetectorStatus,
    state: EpistemicState,
    family: str,
    category: str,
    required: bool = False,
    reason: Optional[str] = None,
) -> DetectorExecution:
    now = datetime.now(timezone.utc)
    return DetectorExecution(
        detector_id=detector_id,
        status=status,
        state=state,
        family=family,
        category=category,
        required=required,
        started_at=now,
        completed_at=now,
        reason=reason,
    )


def _record_detector_report(
    report: DetectorReport,
    executions: List[DetectorExecution],
    findings: List[DetectorFinding],
    observations: List[TextObservation],
) -> None:
    executions.append(report.execution)
    findings.extend(report.findings)
    observations.extend([obs for obs in report.observations if isinstance(obs, TextObservation)])


def _consume_text_budget(budget: ResourceBudget, observations: List[TextObservation]) -> None:
    for observation in observations:
        budget.consume_text(observation.raw_text)


def _rejected_report(
    scan_id: str,
    request: ScanRequest,
    config_hash: str,
    file_descriptor: FileDescriptor,
    artifacts: Dict[str, Artifact],
    reason: str,
) -> ScanReport:
    finding = DetectorFinding(
        finding_id="finding:%s:intake-rejected" % scan_id,
        category="file_security",
        type="intake_rejected",
        state=EpistemicState.CONFIRMED,
        severity="high",
        evidence_quality=0.9,
        impact="high",
        source_artifact_ids=[artifact.artifact_id for artifact in artifacts.values()],
        detector_ids=["detector:intake-validation"],
        reason_codes=["INTAKE_REJECTED"],
        recommended_action=PolicyAction.QUARANTINE,
        evidence={"reason": reason},
    )
    execution = _execution(
        "detector:intake-validation",
        DetectorStatus.ERROR,
        EpistemicState.ERROR,
        family="intake",
        category="file_security",
        required=True,
        reason=reason,
    )
    assessments = build_assessments([finding], [execution])
    decision = PolicyDecision(
        action=PolicyAction.QUARANTINE,
        safe_claim=False,
        reason_codes=["INTAKE_REJECTED"],
        triggered_policy_rules=["quarantine-intake-rejected"],
        winning_rule_id="quarantine-intake-rejected",
        winning_rule_priority=10000,
        summary="Input was rejected before semantic analysis.",
        explanation=reason,
    )
    return ScanReport(
        scan_id=scan_id,
        scanner=_scanner_info(request, config_hash),
        input=file_descriptor,
        decision=decision,
        assessments=assessments,
        findings=[finding],
        artifacts=artifacts,
        observations=[],
        detector_executions=[execution],
        release_grants=[],
        coverage=CoverageAssessment(original_container="low", universal_absence_claim=False),
        module_status={
            "intake": ModuleStatus(name="intake", status=EpistemicState.ERROR, reason=reason)
        },
        limitations=[
            Limitation(
                limitation_id="limitation:semantic-not-run",
                category="coverage",
                description="Semantic detectors did not run because intake validation failed.",
            )
        ],
        errors=[ErrorRecord(source="intake", message=reason)],
    )


def scan_file(path: Path, request: Optional[ScanRequest] = None, config: Optional[AppConfig] = None) -> ScanReport:
    request = request or ScanRequest(original_filename=path.name)
    config = config or load_config()
    registry = load_detector_registry()
    budget = ResourceBudget(config.limits)
    store = ArtifactStore(Path(config.data_dir))
    context = create_scan_context(store, request, config)
    scan_id = context.scan_id
    started = time.monotonic()
    artifacts: Dict[str, Artifact] = {}
    observations: List[TextObservation] = []
    findings: List[DetectorFinding] = []
    detector_executions: List[DetectorExecution] = []
    module_status: Dict[str, ModuleStatus] = {"artifact_store": store.capability_status()}
    errors: List[ErrorRecord] = []
    limitations: List[Limitation] = [
        Limitation(
            limitation_id="limitation:universal-safety",
            category="global",
            description="No report can prove an image is universally safe.",
        ),
        Limitation(
            limitation_id="limitation:unknown-steganography",
            category="steganography",
            description="Arbitrary encrypted steganography cannot be excluded.",
        ),
        Limitation(
            limitation_id="limitation:unknown-watermarks",
            category="watermarks",
            description="Unknown watermark schemes are not exhaustively detectable.",
        ),
    ]
    try:
        OfflineGuard(strict=config.offline.strict).reject_remote_input(str(path))
        path = Path(path)
        detected_mime, format_name = detect_magic(path)
        original = store.store_file(
            path,
            artifact_id="artifact:%s:original" % scan_id,
            media_type=detected_mime,
            created_by="intake",
            role="original",
            quarantine=True,
            release_eligible=False,
            max_bytes=config.limits.max_input_bytes,
        )
        budget.consume_artifact(original.size_bytes)
        artifacts["original"] = original
        try:
            file_descriptor = validate_image_file(path, request.declared_mime, config.limits)
            file_descriptor.original_filename = request.original_filename or path.name
        except IntakeRejected as exc:
            file_descriptor = FileDescriptor(
                original_filename=request.original_filename or path.name,
                size_bytes=path.stat().st_size,
                sha256=sha256_file(path),
                declared_mime=request.declared_mime,
                detected_mime=detected_mime,
                format=format_name,
                width=None,
                height=None,
                frames=0,
            )
            report = _rejected_report(scan_id, request, context.config_hash, file_descriptor, artifacts, str(exc))
            store.save_report(scan_id, report_to_json(report))
            return report
        budget.consume_decoded_pixels((file_descriptor.width or 0) * (file_descriptor.height or 0) * max(file_descriptor.frames, 1))

        trailing = detect_trailing_bytes(path, file_descriptor.format, original.artifact_id, "finding:%s:trailing-bytes" % scan_id)
        if trailing:
            findings.append(trailing)
        differential_findings, opencv_status = compare_decoders(path, original.artifact_id, "finding:%s:decoder-differential" % scan_id)
        findings.extend(differential_findings)
        module_status["opencv_decoder"] = opencv_status

        canonical = create_canonical_artifacts(store, original, path, scan_id, budget)
        artifacts.update(canonical)
        canonical_path = store.resolve_path(canonical["canonical_lossless"])
        if request.mode.value in {"deep", "forensic"} and file_descriptor.frames > 1:
            artifacts.update(extract_frames(store, original, path, scan_id, config.limits.max_frames, budget))
        transforms = generate_fast_transformations(store, canonical["canonical_lossless"], canonical_path, scan_id, budget)
        artifacts.update(transforms)

        metadata_report = analyze_builtin_metadata(path, original.artifact_id, scan_id, include_raw_text=False)
        _record_detector_report(metadata_report, detector_executions, findings, observations)
        module_status["metadata_builtin"] = ModuleStatus(
            name="metadata_builtin",
            status=metadata_report.execution.state,
            reason=metadata_report.execution.reason,
        )
        exiftool_report = analyze_with_exiftool(
            path,
            original.artifact_id,
            scan_id,
            min(config.limits.parser_timeout_seconds, max(1, int(budget.remaining_seconds()))),
            config.limits.max_metadata_bytes,
            include_raw_text=False,
        )
        _record_detector_report(exiftool_report, detector_executions, findings, observations)
        module_status["exiftool"] = exiftool_status(exiftool_report)
        for error in exiftool_report.errors:
            errors.append(ErrorRecord(source="exiftool", message=error))
        module_status.update(embedded_tool_statuses())
        module_status.update(malware_tool_statuses())
        module_status["c2pa"] = provenance_status()
        module_status["paddleocr"] = paddle_status()
        module_status["zsteg"] = zsteg_status()
        module_status["watermark_registry"] = watermark_registry_status()
        module_status["redaction_analysis"] = redaction_analysis_status()
        module_status["adversarial_stability"] = baseline_stability_status()
        module_status["visual_analyzer"] = ModuleStatus(
            name="visual_analyzer",
            status=EpistemicState.NOT_TESTED,
            reason="NullVisualAnalyzer configured",
        )

        ocr_inputs = [
            ("canonical_lossless", canonical["canonical_lossless"], canonical_path),
            ("flattened_white", canonical["flattened_white"], store.resolve_path(canonical["flattened_white"])),
            ("flattened_black", canonical["flattened_black"], store.resolve_path(canonical["flattened_black"])),
        ] + [(label, artifact, store.resolve_path(artifact)) for label, artifact in transforms.items()]
        ocr_report = analyze_with_tesseract(
            ocr_inputs,
            scan_id,
            min(config.limits.detector_timeout_seconds, max(1, int(budget.remaining_seconds()))),
            config.limits.max_subprocess_output_bytes,
        )
        _record_detector_report(ocr_report, detector_executions, findings, observations)
        module_status["tesseract"] = ModuleStatus(
            name="tesseract",
            status=ocr_report.execution.state,
            reason=ocr_report.execution.reason,
            version=ocr_report.execution.tool_version,
        )
        for error in ocr_report.errors:
            errors.append(ErrorRecord(source="tesseract", message=error))

        qr_report = analyze_qr(ocr_inputs, scan_id, include_raw_text=False)
        _record_detector_report(qr_report, detector_executions, findings, observations)
        module_status["qr"] = ModuleStatus(name="qr", status=qr_report.execution.state, reason=qr_report.execution.reason)

        observations = merge_text_observations(observations)
        _consume_text_budget(budget, observations)
        derived_map = {}
        for obs in observations:
            derived = derive_text_candidates(obs)
            if derived:
                derived_map[obs.observation_id] = [item.text for item in derived]
                for item in derived:
                    budget.consume_text(item.text)
        rules = PromptRuleBundle.load_default()
        prompt_findings = rules.analyze_texts(observations, scan_id, include_raw_text=False, derived_texts=derived_map)
        findings.extend(prompt_findings)
        detector_executions.append(
            _execution(
                "detector:prompt-rules",
                DetectorStatus.SUCCESS if prompt_findings else DetectorStatus.NO_EVIDENCE,
                EpistemicState.CONFIRMED if prompt_findings else EpistemicState.NO_EVIDENCE_FOUND,
                family="prompt",
                category="prompt_injection",
                required=True,
            )
        )
        privacy_findings = analyze_privacy(observations, scan_id, include_raw_text=False)
        findings.extend(privacy_findings)
        detector_executions.append(
            _execution(
                "detector:privacy-rules",
                DetectorStatus.SUCCESS if privacy_findings else DetectorStatus.NO_EVIDENCE,
                EpistemicState.CONFIRMED if privacy_findings else EpistemicState.NO_EVIDENCE_FOUND,
                family="privacy",
                category="privacy",
            )
        )
        phishing_findings = analyze_phishing(observations, scan_id, include_raw_text=False)
        findings.extend(phishing_findings)
        detector_executions.append(
            _execution(
                "detector:phishing-rules",
                DetectorStatus.SUCCESS if phishing_findings else DetectorStatus.NO_EVIDENCE,
                EpistemicState.CONFIRMED if phishing_findings else EpistemicState.NO_EVIDENCE_FOUND,
                family="phishing",
                category="phishing",
            )
        )
        watermark_findings = analyze_visible_watermarks(observations, scan_id)
        findings.extend(watermark_findings)
        detector_executions.append(
            _execution(
                "detector:visible-watermark-rules",
                DetectorStatus.SUCCESS if watermark_findings else DetectorStatus.NO_EVIDENCE,
                EpistemicState.CONFIRMED if watermark_findings else EpistemicState.NO_EVIDENCE_FOUND,
                family="watermarks",
                category="watermarks",
            )
        )

        try:
            module_status["steganalysis_statistics"] = ModuleStatus(
                name="steganalysis_statistics",
                status=EpistemicState.CONFIRMED,
                reason=str(image_entropy_summary(canonical_path)),
            )
        except Exception as exc:
            module_status["steganalysis_statistics"] = ModuleStatus(
                name="steganalysis_statistics",
                status=EpistemicState.ERROR,
                reason=str(exc),
            )

        findings = deduplicate_findings(findings)
        assessments = build_assessments(findings, detector_executions)
        decision = PolicyEngine.load_for_profile(request.use_profile).decide(findings)
        coverage_decision = mandatory_coverage_decision(request.use_profile, registry, detector_executions)
        if coverage_decision is not None:
            decision = coverage_decision
        release_grants = apply_release_grants(store, scan_id, artifacts, decision)
        timings = {"total_ms": (time.monotonic() - started) * 1000}
        report = ScanReport(
            scan_id=scan_id,
            scanner=_scanner_info(request, context.config_hash),
            input=file_descriptor,
            decision=decision,
            assessments=assessments,
            findings=findings,
            artifacts=artifacts,
            observations=[observation.to_public() for observation in observations],
            detector_executions=detector_executions,
            release_grants=release_grants,
            coverage=CoverageAssessment(
                original_container="high",
                all_frames="complete" if file_descriptor.frames <= 1 else "partial",
                visible_text="medium" if module_status["tesseract"].status != EpistemicState.UNSUPPORTED else "low",
                low_contrast_text="medium",
                metadata_text="medium",
                known_embedded_formats="low",
                common_steganography="low",
                unknown_steganography="low",
                registered_watermark_schemes="low",
                unknown_watermarks="unsupported",
                model_specific_adversarial_attacks="not_tested",
                universal_attack_absence="impossible",
                universal_absence_claim=False,
            ),
            module_status=module_status,
            limitations=limitations,
            errors=errors,
            timings_ms=timings,
            evidence_graph=build_evidence_graph(artifacts, observations, findings),
        )
        report.internal_observations = observations
        store.save_report(scan_id, report_to_json(report))
        return report
    finally:
        cleanup_job_dir(Path(context.job_dir))
