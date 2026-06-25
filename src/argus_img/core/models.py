from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, SerializeAsAny

from .enums import DetectorStatus, EpistemicState, PolicyAction, ScanMode, UseProfile


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanRequest(BaseModel):
    original_filename: Optional[str] = None
    declared_mime: Optional[str] = None
    mode: ScanMode = ScanMode.FAST
    use_profile: UseProfile = UseProfile.AGENT_WITH_TOOLS
    sanitize: bool = True
    redact: bool = False
    include_raw_text: bool = False


class ScanContext(BaseModel):
    scan_id: str
    created_at: datetime = Field(default_factory=utc_now)
    mode: ScanMode = ScanMode.FAST
    use_profile: UseProfile = UseProfile.AGENT_WITH_TOOLS
    sanitize: bool = True
    redact: bool = False
    include_raw_text: bool = False
    job_dir: str
    data_dir: str
    config_hash: str
    model_config = ConfigDict(arbitrary_types_allowed=True)


class FileDescriptor(BaseModel):
    original_filename: Optional[str] = None
    size_bytes: int
    sha256: str
    declared_mime: Optional[str] = None
    detected_mime: str
    format: str
    width: Optional[int] = None
    height: Optional[int] = None
    frames: int = 0


class ArtifactTransformation(BaseModel):
    transformation_id: str
    type: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    inverse_coordinate_mapping: Optional[str] = None
    reliability_class: str = "forensic"
    resource_cost_class: str = "low"


class Artifact(BaseModel):
    artifact_id: str
    sha256: str
    media_type: str
    size_bytes: int
    created_by: str
    derived_from: Optional[str] = None
    transformation: Optional[ArtifactTransformation] = None
    storage_reference: str
    release_eligible: bool = False
    role: str = "derived"
    width: Optional[int] = None
    height: Optional[int] = None
    frame_index: Optional[int] = None


class Observation(BaseModel):
    observation_id: str
    type: str
    source_artifact_id: str
    detector_id: str
    value: Dict[str, Any] = Field(default_factory=dict)
    confidence: Optional[float] = None
    transformation_id: Optional[str] = None


class TextObservation(Observation):
    type: str = "text"
    raw_text: str
    normalized_text: str
    engine: str
    engine_version: Optional[str] = None
    language: Optional[str] = None
    bounding_polygon: Optional[List[List[float]]] = None
    original_image_polygon: Optional[List[List[float]]] = None
    character_alternatives: Optional[List[str]] = None
    context: str = "ambiguous"


class DerivedText(BaseModel):
    source_text_id: str
    derived_text_id: str
    transformation: str
    depth: int
    confidence: float
    decoded_bytes: int
    printable_ratio: float
    text: str


class DetectorManifest(BaseModel):
    detector_id: str
    name: str
    version: str = "0.1.0"
    family: str
    description: str = ""
    optional: bool = False


class DetectorExecution(BaseModel):
    detector_id: str
    status: DetectorStatus
    state: EpistemicState
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    reason: Optional[str] = None
    tool_version: Optional[str] = None


class DetectorFinding(BaseModel):
    finding_id: str
    category: str
    type: str
    state: EpistemicState
    severity: str
    detector_confidence: Optional[float] = None
    evidence_quality: Optional[float] = None
    attack_likelihood: Optional[float] = None
    impact: str = "medium"
    source_artifact_ids: List[str] = Field(default_factory=list)
    observation_ids: List[str] = Field(default_factory=list)
    detector_ids: List[str] = Field(default_factory=list)
    reason_codes: List[str] = Field(default_factory=list)
    recommended_action: Optional[PolicyAction] = None
    limitations: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class DetectorReport(BaseModel):
    manifest: DetectorManifest
    execution: DetectorExecution
    findings: List[DetectorFinding] = Field(default_factory=list)
    observations: List[SerializeAsAny[Observation]] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class SupportResult(BaseModel):
    supported: bool
    status: EpistemicState
    reason: Optional[str] = None


class CategoryAssessment(BaseModel):
    state: EpistemicState
    likelihood: Optional[float] = None
    impact: Optional[str] = None
    coverage: str = "low"
    finding_ids: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    summary: str = ""


class CoverageAssessment(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    original_container: str = "medium"
    all_frames: str = "partial"
    visible_text: str = "low"
    low_contrast_text: str = "low"
    metadata_text: str = "low"
    known_embedded_formats: str = "low"
    common_steganography: str = "low"
    unknown_steganography: str = "low"
    registered_watermark_schemes: str = "low"
    unknown_watermarks: str = "unsupported"
    model_specific_adversarial_attacks: str = "not_tested"
    universal_attack_absence: str = "impossible"
    universal_absence_claim: bool = False


class Limitation(BaseModel):
    limitation_id: str
    category: str
    description: str


class PolicyDecision(BaseModel):
    action: PolicyAction
    safe_claim: bool = False
    reason_codes: List[str] = Field(default_factory=list)
    triggered_policy_rules: List[str] = Field(default_factory=list)
    winning_rule_id: Optional[str] = None
    winning_rule_priority: Optional[int] = None
    summary: str = ""
    explanation: str = ""


class ModuleStatus(BaseModel):
    name: str
    status: EpistemicState
    reason: Optional[str] = None
    version: Optional[str] = None


class TimingRecord(BaseModel):
    name: str
    duration_ms: float


class ErrorRecord(BaseModel):
    source: str
    message: str
    state: EpistemicState = EpistemicState.ERROR


class ScannerInfo(BaseModel):
    name: str = "argus-img"
    version: str = "0.1.0"
    offline_mode: bool = True
    mode: ScanMode
    use_profile: UseProfile
    configuration_hash: str


class ScanReport(BaseModel):
    schema_version: str = "1.0.0"
    scan_id: str
    created_at: datetime = Field(default_factory=utc_now)
    scanner: ScannerInfo
    input: FileDescriptor
    decision: PolicyDecision
    assessments: Dict[str, CategoryAssessment]
    findings: List[DetectorFinding] = Field(default_factory=list)
    artifacts: Dict[str, Artifact] = Field(default_factory=dict)
    observations: List[SerializeAsAny[Observation]] = Field(default_factory=list)
    coverage: CoverageAssessment = Field(default_factory=CoverageAssessment)
    module_status: Dict[str, ModuleStatus] = Field(default_factory=dict)
    limitations: List[Limitation] = Field(default_factory=list)
    errors: List[ErrorRecord] = Field(default_factory=list)
    timings_ms: Dict[str, float] = Field(default_factory=dict)
    evidence_graph: Dict[str, Any] = Field(default_factory=dict)
