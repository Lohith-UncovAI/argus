/*
 *           _____       _____
 *      ,-'``_.-'` \   / `'-._``'-.
 *    ,`   .'      |`-'|      `.   `.
 *  ,`    (    /\  |   |  /\    )    `.
 * /       `--'  `-'   `-'  `--'       \
 * |                                   |
 * \      .--.  ,--.   ,--.  ,--.      /
 *  `.   (    \/ lt.\ /    \/    )   ,'
 *    `._ `--.___    V    ___.--' _,'
 *       `'----'`         `'----'`
 */

# Master Implementation Prompt: ARGUS-IMG

You are a senior software architect, application-security engineer, digital-forensics engineer, and machine-learning systems engineer.

Your task is to design and implement **ARGUS-IMG**, a completely offline image-security analysis and content-disarm system.

Do not respond with only a design document. Build a functioning, tested implementation in the current repository.

## 1. Mission

ARGUS-IMG accepts an untrusted image and produces:

1. A structured JSON security report.
2. A reconstructed, metadata-free image when reconstruction succeeds.
3. Optional redaction masks and analysis artifacts.
4. Explicit coverage and limitation information.
5. A deterministic policy decision appropriate for the intended downstream use.

The system must detect, analyze, or report evidence related to:

* Visible text and instructions.
* Hidden, tiny, transparent, rotated, mirrored, low-contrast, or channel-specific text.
* Prompt injection.
* Jailbreak instructions.
* System-prompt override attempts.
* Tool-use requests.
* Data-exfiltration requests.
* Credential theft.
* Phishing and deceptive user interfaces.
* QR codes and barcodes.
* Metadata-based instructions.
* Embedded and appended payloads.
* Malformed image containers.
* Polyglot files.
* Known malware indicators.
* Common steganographic techniques.
* Statistical steganography anomalies.
* Visible watermarks.
* Registered invisible-watermark schemes.
* C2PA provenance information.
* Privacy-sensitive information.
* Suspicious redactions.
* Adversarial visual instability.
* Unsupported or inconclusive conditions.

The system must not claim that an image is universally safe.

Use these epistemic states:

```text
CONFIRMED
HIGHLY_LIKELY
POSSIBLE
NO_EVIDENCE_FOUND
INCONCLUSIVE
NOT_TESTED
UNSUPPORTED
ERROR
```

`NO_EVIDENCE_FOUND` must never be interpreted as proof of absence.

---

# 2. Current implementation priority

Focus on implementation, correctness, modularity, testing, and security boundaries.

Do not optimize for a particular GPU yet.

Do not make the system dependent on a GPU or installed VLM.

The initial implementation must be CPU-first and runnable without any large model.

Create clean interfaces for:

* Local prompt-injection classifiers.
* Local vision-language models.
* GPU scheduling.
* Watermark detectors.
* Steganalysis models.
* AI-generated-image classifiers.

Initially provide:

* A `NullVLMAnalyzer`.
* A deterministic `MockVLMAnalyzer`.
* A generic `LocalVLMAnalyzer` protocol.
* A generic `PromptClassifier` protocol.
* A generic `WatermarkDetector` protocol.
* A generic `SteganalysisDetector` protocol.

A real local VLM and GPU execution will be integrated later without changing the public API or core evidence model.

---

# 3. Non-negotiable security principles

Implement the following principles throughout the codebase.

## 3.1 Treat every uploaded byte as hostile

The original image may contain:

* Malformed structures.
* Parser exploits.
* Excessive dimensions.
* Excessive frame counts.
* Embedded files.
* Appended data.
* Malicious metadata.
* Contradictory representations.
* Prompt-injection content.

Do not trust:

* Filename.
* File extension.
* Declared MIME type.
* Metadata.
* Decoder output.
* OCR text.
* Model output.
* Extracted payloads.

## 3.2 Separate original bytes from reconstructed pixels

Maintain two analysis paths:

```text
Original-byte path
    structural analysis
    metadata
    embedded content
    malware
    provenance
    steganography

Decoded-pixel path
    OCR
    QR detection
    visual transformations
    semantic analysis
    watermark analysis
    reconstruction
```

No downstream semantic model may receive the original uploaded container.

Models receive only validated, bounded, reconstructed pixel artifacts.

## 3.3 Evidence before verdict

Detectors must produce observations and findings.

Detectors must not directly set the final policy action.

The deterministic policy engine is the only component permitted to produce the final action.

## 3.4 No universal safety claim

The JSON response must include:

```json
{
  "safe_claim": false
}
```

The system must explicitly state that arbitrary encrypted steganography, unknown watermark schemes, and model-specific adversarial perturbations cannot be completely excluded.

## 3.5 No runtime network dependency

The runtime implementation must:

* Make no cloud API calls.
* Download no models.
* Download no threat signatures.
* Fetch no URLs decoded from images.
* Perform no DNS lookups.
* Perform no remote C2PA retrieval.
* Perform no telemetry.
* Perform no automatic updates.

All external tools and models must be accessed through local paths.

## 3.6 Models are untrusted witnesses

A local VLM or classifier may submit evidence, but it cannot:

* Execute tools.
* Open files outside the assigned job.
* Access secrets.
* Use the network.
* modify policy.
* choose the final decision.
* execute commands.
* request dynamic plugins.

## 3.7 Release reconstructed content only

The original upload remains quarantined.

When policy allows image release, release only a newly encoded image generated from validated pixels.

---

# 4. Implementation strategy

Use a Python-first architecture for the initial implementation.

The design must preserve the option of replacing the intake gateway or selected workers with Rust later.

Use:

```text
Python 3.12+
FastAPI
Pydantic v2
Typer
OpenCV
Pillow
python-magic or libmagic
PyYAML
pytest
Hypothesis
structlog or standard structured JSON logging
```

Optional local integrations must use adapters:

```text
ExifTool
Tesseract
PaddleOCR
ZXing or ZBar
ClamAV
YARA
Binwalk
zsteg
c2pa-rs or c2pa-python
ONNX Runtime
```

The application must still start when optional tools are unavailable.

Unavailable optional tools return:

```json
{
  "status": "UNSUPPORTED",
  "reason": "tool_not_installed"
}
```

Do not silently treat a missing detector as a clean result.

Use `pyproject.toml` with pinned dependencies and a reproducible lock file.

---

# 5. Required repository structure

Create or evolve the repository toward this structure:

```text
argus-img/
├── pyproject.toml
├── README.md
├── LICENSE
├── Makefile
├── .env.example
├── .gitignore
├── docker/
│   ├── Dockerfile.api
│   ├── Dockerfile.worker
│   ├── docker-compose.offline.yml
│   └── seccomp/
├── config/
│   ├── default.yaml
│   ├── policies/
│   │   ├── archive-only.yaml
│   │   ├── human-view.yaml
│   │   ├── vlm-read-only.yaml
│   │   ├── rag-ingestion.yaml
│   │   ├── agent-with-tools.yaml
│   │   └── forensic.yaml
│   ├── prompt_rules/
│   │   ├── en.yaml
│   │   └── generic.yaml
│   └── detector_registry.yaml
├── schemas/
│   ├── scan-report.schema.json
│   ├── detector-report.schema.json
│   └── policy.schema.json
├── src/
│   └── argus_img/
│       ├── __init__.py
│       ├── api/
│       │   ├── app.py
│       │   ├── dependencies.py
│       │   ├── errors.py
│       │   └── routes/
│       │       ├── scans.py
│       │       ├── artifacts.py
│       │       ├── health.py
│       │       ├── capabilities.py
│       │       └── attestation.py
│       ├── cli/
│       │   └── main.py
│       ├── core/
│       │   ├── config.py
│       │   ├── enums.py
│       │   ├── models.py
│       │   ├── protocols.py
│       │   ├── exceptions.py
│       │   ├── hashing.py
│       │   ├── limits.py
│       │   └── offline_guard.py
│       ├── artifacts/
│       │   ├── store.py
│       │   ├── lineage.py
│       │   └── cleanup.py
│       ├── intake/
│       │   ├── upload.py
│       │   ├── mime.py
│       │   ├── validation.py
│       │   ├── format_policy.py
│       │   └── structure.py
│       ├── decoding/
│       │   ├── pillow_decoder.py
│       │   ├── opencv_decoder.py
│       │   ├── differential.py
│       │   ├── frames.py
│       │   └── thumbnails.py
│       ├── reconstruction/
│       │   ├── canonical.py
│       │   ├── sanitizer.py
│       │   └── redaction.py
│       ├── transforms/
│       │   ├── registry.py
│       │   ├── photometric.py
│       │   ├── geometric.py
│       │   ├── channels.py
│       │   ├── bitplanes.py
│       │   └── stability.py
│       ├── detectors/
│       │   ├── base.py
│       │   ├── registry.py
│       │   ├── file_structure.py
│       │   ├── metadata.py
│       │   ├── embedded_content.py
│       │   ├── malware.py
│       │   ├── provenance.py
│       │   ├── ocr/
│       │   │   ├── base.py
│       │   │   ├── tesseract.py
│       │   │   ├── paddle.py
│       │   │   └── merge.py
│       │   ├── machine_codes/
│       │   │   ├── qr.py
│       │   │   └── barcode.py
│       │   ├── prompt/
│       │   │   ├── normalizer.py
│       │   │   ├── decoders.py
│       │   │   ├── rules.py
│       │   │   ├── classifier.py
│       │   │   └── intent.py
│       │   ├── visual/
│       │   │   ├── base.py
│       │   │   ├── null.py
│       │   │   ├── mock.py
│       │   │   └── local.py
│       │   ├── steganography/
│       │   │   ├── structural.py
│       │   │   ├── zsteg.py
│       │   │   ├── statistics.py
│       │   │   └── learned.py
│       │   ├── watermarks/
│       │   │   ├── base.py
│       │   │   ├── visible.py
│       │   │   └── registry.py
│       │   ├── phishing.py
│       │   ├── privacy.py
│       │   └── redaction_analysis.py
│       ├── evidence/
│       │   ├── graph.py
│       │   ├── deduplication.py
│       │   ├── calibration.py
│       │   ├── correlation.py
│       │   └── assessment.py
│       ├── policy/
│       │   ├── engine.py
│       │   ├── conditions.py
│       │   ├── profiles.py
│       │   └── decisions.py
│       ├── orchestration/
│       │   ├── pipeline.py
│       │   ├── scheduler.py
│       │   ├── context.py
│       │   └── timeouts.py
│       ├── reporting/
│       │   ├── builder.py
│       │   ├── excerpts.py
│       │   ├── json_schema.py
│       │   └── serialization.py
│       └── subprocesses/
│           ├── runner.py
│           ├── limits.py
│           └── parsers.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── fixtures/
│   ├── golden/
│   └── conftest.py
├── scripts/
│   ├── generate_test_images.py
│   ├── verify_offline.py
│   ├── verify_dependencies.py
│   └── export_json_schema.py
├── examples/
│   ├── scan_image.py
│   ├── scan_with_curl.sh
│   └── reports/
└── docs/
    ├── architecture.md
    ├── threat-model.md
    ├── detector-development.md
    ├── policy-language.md
    ├── offline-deployment.md
    ├── limitations.md
    └── implementation-status.md
```

Adjust the tree only when there is a concrete engineering reason. Preserve the same module boundaries.

---

# 6. Core domain model

Implement strongly typed Pydantic models.

## 6.1 Enums

Implement at least:

```python
class EpistemicState(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGHLY_LIKELY = "HIGHLY_LIKELY"
    POSSIBLE = "POSSIBLE"
    NO_EVIDENCE_FOUND = "NO_EVIDENCE_FOUND"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"


class PolicyAction(str, Enum):
    ALLOW_ORIGINAL = "ALLOW_ORIGINAL"
    ALLOW_RECONSTRUCTED_ONLY = "ALLOW_RECONSTRUCTED_ONLY"
    ALLOW_WITH_REDACTION = "ALLOW_WITH_REDACTION"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    UNSUPPORTED = "UNSUPPORTED"


class UseProfile(str, Enum):
    ARCHIVE_ONLY = "ARCHIVE_ONLY"
    HUMAN_VIEW = "HUMAN_VIEW"
    OCR_EXTRACTION = "OCR_EXTRACTION"
    VLM_READ_ONLY = "VLM_READ_ONLY"
    RAG_INGESTION = "RAG_INGESTION"
    AGENT_WITH_TOOLS = "AGENT_WITH_TOOLS"
    SECURITY_FORENSICS = "SECURITY_FORENSICS"
    PUBLIC_REPUBLISHING = "PUBLIC_REPUBLISHING"
```

## 6.2 Required entities

Implement:

```text
ScanRequest
ScanContext
FileDescriptor
Artifact
ArtifactTransformation
Observation
TextObservation
DetectorManifest
DetectorExecution
DetectorFinding
CategoryAssessment
CoverageAssessment
Limitation
PolicyDecision
ScanReport
ModuleStatus
TimingRecord
ErrorRecord
```

Every artifact must have:

```text
artifact_id
sha256
media_type
size_bytes
created_by
derived_from
transformation
storage_reference
release_eligible
```

Every finding must have:

```text
finding_id
category
type
state
severity
detector_confidence
evidence_quality
attack_likelihood
impact
source_artifact_ids
observation_ids
detector_ids
reason_codes
recommended_action
limitations
```

Do not require every detector to produce a probability.

A rule-based detector may provide:

```json
{
  "state": "CONFIRMED",
  "detector_confidence": null
}
```

## 6.3 Detector protocol

Create a common detector interface:

```python
class Detector(Protocol):
    manifest: DetectorManifest

    def supports(
        self,
        artifact: Artifact,
        context: ScanContext,
    ) -> SupportResult:
        ...

    async def analyze(
        self,
        artifact: Artifact,
        context: ScanContext,
    ) -> DetectorReport:
        ...
```

A detector report must distinguish:

* Successful execution with no evidence.
* Unsupported input.
* Missing optional dependency.
* Timeout.
* Internal error.
* Findings produced.

Detector failure must not silently become a clean result.

---

# 7. Content-addressed artifact storage

Implement a local content-addressed artifact store.

Suggested layout:

```text
data/
├── quarantine/
├── artifacts/
│   └── sha256/
│       └── ab/
│           └── cd/
│               └── full-hash
├── reports/
├── jobs/
└── temporary/
```

Requirements:

* Generate filenames internally.
* Do not use the uploaded filename as a path.
* Reject path traversal.
* Do not follow symlinks.
* Use atomic writes.
* Hash files while streaming.
* Apply maximum upload size during streaming.
* Preserve the original as immutable.
* Track complete transformation lineage.
* Apply configurable retention.
* Remove temporary job directories after completion.
* Prevent one scan from accessing another scan’s files.

---

# 8. Intake and format policy

Initial supported raster formats:

```text
JPEG
PNG
WebP
GIF
TIFF
BMP
```

Initially reject or route elsewhere:

```text
SVG
PDF
PostScript
PSD
unknown formats
```

SVG is active structured content and must not enter the normal raster pipeline.

Validate:

* Actual magic bytes.
* Declared MIME type.
* Extension.
* File size.
* Width.
* Height.
* Total decoded pixels.
* Frame count.
* Metadata size.
* Decoder success.
* Format allowlist.
* Excessive aspect ratio.
* Truncation.
* Unexpected bytes after logical end-of-file when detectable.
* Conflicting embedded signatures.

Suggested default limits:

```yaml
limits:
  max_input_bytes: 25000000
  max_pixels_per_frame: 50000000
  max_total_decoded_pixels: 150000000
  max_width: 16384
  max_height: 16384
  max_frames: 30
  max_metadata_bytes: 5000000
  max_extracted_objects: 100
  max_extracted_total_bytes: 50000000
  max_recursive_depth: 3
  max_text_bytes_per_source: 100000
  parser_timeout_seconds: 10
  detector_timeout_seconds: 30
  full_scan_timeout_seconds: 120
```

Limits must be configurable.

---

# 9. Differential decoding

Implement two independent decoding paths where possible.

Initial paths:

```text
Pillow
OpenCV
```

Make a future `LibVipsDecoder` adapter possible.

Compare:

* Decode success.
* Dimensions.
* Frame count.
* Orientation.
* Channel count.
* Alpha presence.
* Normalized pixel digest.
* Decoder warnings.

Produce a `decoder_differential` finding when results materially disagree.

The system must use the canonical reconstructed artifact for subsequent semantic analysis, not whichever representation is most convenient.

If only one decoder is installed, report reduced coverage.

---

# 10. Canonical reconstruction

Generate trusted derivatives from validated pixel arrays.

Create:

```text
canonical_lossless.png
canonical_lossy.jpg
flattened_white.png
flattened_black.png
```

The reconstruction process must:

* Apply orientation.
* Convert to RGB8 or RGBA8.
* Remove metadata.
* Remove profiles unless explicitly preserved by policy.
* Bound dimensions.
* Use a trusted encoder.
* Reconstruct every allowed frame.
* Flatten alpha against both white and black backgrounds.
* Record exact transformation parameters.
* Generate new SHA-256 hashes.
* Never overwrite the original.

The lossy JPEG derivative is useful for disrupting fragile pixel-level payloads, but the report must not claim it removes all hidden information.

---

# 11. Representation discovery

Inspect separately:

* Main decoded image.
* Every permitted animation frame.
* Embedded thumbnails.
* EXIF preview images.
* Alpha channel.
* Red channel.
* Green channel.
* Blue channel.
* Palette data where relevant.
* Flattened white representation.
* Flattened black representation.

Create explicit artifact records for these representations.

---

# 12. Transformation bank

Implement a configurable transformation registry.

## Fast transformations

```text
original canonical image
grayscale
2x enlargement
Otsu threshold
adaptive threshold
inverted grayscale
red channel
green channel
blue channel
alpha channel
alpha flattened on white
alpha flattened on black
```

## Deep transformations

```text
4x enlargement
CLAHE
gamma variants
local contrast enhancement
edge-enhanced version
90-degree rotation
180-degree rotation
270-degree rotation
mirror candidate
deskew candidate
channel differences: R-G, R-B, G-B
selected bit planes
overlapping tiles
high-pass residual
low-pass residual
JPEG recompression
small resize cycle
median-filtered version
color-quantized version
```

Each transformation must provide:

* Stable identifier.
* Source artifact ID.
* Parameters.
* Inverse coordinate mapping where applicable.
* Reliability class.
* Resource cost class.

Do not use generative super-resolution in the baseline implementation.

If added later, label it as non-forensic and low-reliability.

---

# 13. Metadata analysis

Implement an `ExifToolDetector` adapter.

Run ExifTool safely in JSON mode when installed.

Inspect:

```text
EXIF
XMP
IPTC
PNG textual chunks
JPEG comments
ICC descriptions
Photoshop resources
JUMBF
embedded thumbnails
maker notes
titles
subjects
keywords
descriptions
user comments
GPS data
workflow fields
```

Classify metadata values into:

```text
ordinary_camera_data
location_data
identity_data
workflow_data
provenance_data
free_text
binary_blob
unexpected_structure
```

Pass all free-text metadata through the text-normalization and instruction-analysis pipeline.

Do not return precise GPS coordinates by default.

Return:

```json
{
  "gps_present": true,
  "precision": "exact",
  "value_redacted": true
}
```

---

# 14. Provenance analysis

Create a `ProvenanceDetector` protocol and a local C2PA adapter.

The baseline implementation may report `UNSUPPORTED` when the local C2PA tool is not available.

Support these states:

```text
absent
present_valid
present_invalid
signature_valid_signer_untrusted
asset_hash_mismatch
manifest_malformed
unsupported_assertion
```

C2PA absence is neutral.

A valid C2PA signature must not be interpreted as proof that the depicted event is true.

Record:

* Manifest presence.
* Signature status.
* Asset hash status.
* Claim generator.
* Declared actions.
* Local signer trust.
* Whether live revocation was checked.
* Age of local revocation data.

No network revocation checks are permitted.

---

# 15. Embedded-content and malware analysis

Implement safe adapters for:

```text
ClamAV
YARA
Binwalk
```

All subprocess execution must use the central safe-subprocess runner.

Inspect:

* Original file.
* Metadata binary blobs when extractable.
* Embedded thumbnails.
* Appended content.
* Extracted objects.
* ICC profiles.
* application markers.

Extracted objects are treated as new untrusted artifacts.

Recursive analysis must enforce:

* Maximum depth.
* Maximum object count.
* Maximum total extracted size.
* Per-tool timeout.
* No execution.
* No shell.
* No network.
* No archive path traversal.

A known malicious payload or embedded executable should normally trigger quarantine in strict profiles.

Do not include real malware samples in the repository.

Use harmless fixtures and mocked detector output in tests.

---

# 16. OCR architecture

Implement:

```text
TesseractOCRDetector
PaddleOCRDetector adapter
OCR merge and deduplication
```

Tesseract should be the first runnable OCR backend.

PaddleOCR may initially be optional.

Every OCR observation must contain:

```text
raw_text
normalized_text
engine
engine_version
confidence
language
source_artifact_id
transformation_id
bounding_polygon
original_image_polygon
character_alternatives when available
```

Merge observations using:

* Text similarity.
* Polygon overlap.
* Shared artifact lineage.
* Engine independence.
* Language consistency.
* Character alternatives.

Do not count the same region found in many transformations as many independent findings.

Low-confidence OCR findings must not be discarded automatically.

Hidden text may produce low confidence.

---

# 17. QR and barcode analysis

Implement a local QR/barcode adapter using one of:

```text
ZXing-C++
pyzbar/ZBar
OpenCV QR detector
```

Scan:

* Canonical image.
* Grayscale image.
* Threshold variants.
* Rotations.
* Tiles.
* Frames.
* Thumbnails.

Decode but never open:

* URLs.
* email links.
* telephone links.
* Wi-Fi credentials.
* payment data.
* application links.
* binary payloads.

Perform local-only URL analysis:

* Scheme.
* hostname.
* IP literal.
* punycode.
* embedded credentials.
* suspicious path terms.
* file URL.
* local network address.
* command-like query values.

All decoded textual content enters the prompt-analysis pipeline.

---

# 18. Text normalization and bounded decoding

Implement a deterministic text derivation engine.

Supported transformations:

```text
Unicode NFKC
zero-width-character detection and removal candidate
bidirectional-control detection
whitespace normalization
HTML entity decoding
URL-percent decoding
Base64 candidate decoding
hex candidate decoding
ROT13
reversed-text candidate
homoglyph candidate mapping
leetspeak candidate mapping
common OCR substitution candidates
```

Preserve both raw and derived forms.

Every derived text must record:

```text
source_text_id
derived_text_id
transformation
depth
confidence
decoded_bytes
printable_ratio
```

Enforce:

```yaml
text_decoding:
  max_depth: 3
  max_candidates_per_source: 20
  max_expansion_ratio: 10
  maximum_decoded_bytes: 100000
  minimum_printable_ratio: 0.80
```

Avoid recursive decoding bombs.

Do not execute any decoded content.

---

# 19. Prompt-injection analysis

Implement three independent layers.

## 19.1 Deterministic multilingual rules

Load rules from YAML.

Initial categories:

```text
instruction_override
role_override
system_prompt_request
secret_extraction
credential_request
tool_invocation
network_request
file_access
code_execution
policy_bypass
secrecy_request
impersonation
data_exfiltration
model_manipulation
```

Example rule:

```yaml
- id: PI-INSTRUCTION-OVERRIDE-EN-001
  category: instruction_override
  severity: high
  languages:
    - en
  patterns:
    - '\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b'
    - '\boverride\s+(the\s+)?(system|developer)\s+(prompt|message)\b'
```

Compile regexes safely.

Reject malformed rule bundles at startup.

## 19.2 Classifier interface

Create:

```python
class PromptClassifier(Protocol):
    async def classify(
        self,
        text: str,
        context: TextClassificationContext,
    ) -> PromptClassification:
        ...
```

Provide:

```text
NullPromptClassifier
MockPromptClassifier
ONNXPromptClassifier placeholder
TransformersPromptClassifier placeholder
```

The application must run without a real model.

Long input must be segmented with overlap.

Do not hardcode a specific model repository or download behavior.

## 19.3 Intent extraction

Implement a rule-based initial intent extractor.

Return fields such as:

```json
{
  "speaker_claim": "system",
  "requested_action": "tool_call",
  "target": "email",
  "authority_override": true,
  "secrecy_requested": true,
  "data_exfiltration": false,
  "credential_request": false,
  "quoted_or_active": "active"
}
```

Support these contextual values:

```text
active
quoted
discussed
warning
code_example
ambiguous
```

Context may reduce attack likelihood but must not erase the underlying evidence.

---

# 20. Visual-language model interface

Do not integrate a real GPU model during the initial implementation.

Create this abstraction:

```python
class VisualAnalyzer(Protocol):
    async def literal_inventory(
        self,
        image: Artifact,
        context: ScanContext,
    ) -> VisualInventory:
        ...

    async def analyze_instructions(
        self,
        image: Artifact,
        context: ScanContext,
    ) -> VisualInstructionReport:
        ...

    async def analyze_deception(
        self,
        image: Artifact,
        context: ScanContext,
    ) -> DeceptionReport:
        ...

    async def verify_ocr_regions(
        self,
        image: Artifact,
        observations: list[TextObservation],
        context: ScanContext,
    ) -> OCRVerificationReport:
        ...

    async def run_shadow_test(
        self,
        image: Artifact,
        test_context: ShadowTestContext,
    ) -> ShadowTestReport:
        ...
```

Implement:

```text
NullVisualAnalyzer
MockVisualAnalyzer
```

`NullVisualAnalyzer` returns `NOT_TESTED`.

`MockVisualAnalyzer` uses deterministic fixture mappings for integration tests.

The future real implementation must be able to use separate fresh contexts for:

1. Literal visual inventory.
2. Instruction analysis.
3. Deception analysis.
4. OCR contradiction analysis.
5. Shadow execution.

The future model must never receive operational tools.

---

# 21. Shadow-execution interface

Implement the domain models and orchestration interface now, even though real model execution is deferred.

A shadow test uses:

* Synthetic system prompt.
* Fake canary secret.
* Fake file names.
* Fake tools.
* No real tools.
* No real credentials.
* No network.

Record:

```text
performed
target_match
target_model_id
canary_disclosed
simulated_tool_call_attempted
instruction_override_observed
attacker_instruction_followed
original_attack_score
reconstructed_attack_score
text_masked_attack_score
limitations
```

The mock analyzer must support test cases in which:

* A canary is disclosed.
* A fake tool call is attempted.
* No attack succeeds.
* Reconstruction lowers simulated exploitability.

---

# 22. Steganography architecture

Create separate findings for:

```text
known_method_detection
statistical_anomaly
payload_recovery
```

Do not collapse them into one result.

Implement baseline structural analysis for:

* Trailing bytes.
* PNG ancillary chunks.
* unusual alpha data.
* suspicious palette use.
* JPEG marker anomalies.
* high-entropy appended regions.
* unexpected embedded signatures.

Create adapters for:

```text
zsteg
future spatial steganalysis model
future JPEG steganalysis model
```

Implement basic statistical features where practical:

```text
per-channel entropy
bit-plane entropy
LSB balance
neighbor correlation
channel covariance
local entropy map summary
```

These features must be treated as weak evidence.

Do not block solely because an image has high entropy.

If a payload is recovered, recursively analyze it as a new untrusted artifact.

The report must state:

```json
{
  "universal_absence_claim": false
}
```

---

# 23. Watermark architecture

Implement a plugin registry.

Watermark detector results must use:

```text
DETECTED
NOT_DETECTED
INVALID_MESSAGE
UNSUPPORTED
ERROR
```

Create support for:

* Visible OCR-based watermarks.
* Repeated low-opacity patterns.
* Corner attribution.
* Stock-photo watermark indicators.
* Platform overlays.
* Timestamps.
* Known logo templates.
* Future invisible-watermark plugins.

A `NOT_DETECTED` result applies only to the specific detector and scheme.

It must not mean that no watermark exists.

Create a generic plugin protocol:

```python
class WatermarkDetector(Protocol):
    scheme_id: str

    async def detect(
        self,
        artifact: Artifact,
        context: ScanContext,
    ) -> WatermarkDetection:
        ...
```

Do not include secret watermark keys in source control.

---

# 24. Phishing and deceptive-interface analysis

Implement a baseline deterministic analyzer using:

* OCR text.
* URL findings.
* QR findings.
* detected form-like regions when available.
* local logo labels when configured.
* instruction intent.

Detect indicators such as:

```text
password request
seed phrase request
payment request
urgent security warning
fake software update
fake login form
remote support request
brand/domain mismatch
suspicious QR payment
credential collection
```

Return evidence, not a categorical accusation without support.

---

# 25. Privacy analysis

Implement configurable detectors for:

* GPS metadata.
* email addresses.
* telephone numbers.
* API-key-like strings.
* private-key headers.
* payment-card-like numbers with validation.
* visible credentials.
* faces through an optional local detector.
* license plates through an optional detector.
* identity-document indicators.
* internal system screenshots.
* QR data containing private information.

Redact sensitive values from logs and default reports.

Return hashes and short excerpts where appropriate.

---

# 26. Redaction analysis

Detect apparent redactions that may be weak:

* Semi-transparent overlays.
* Blur-only redactions.
* pixelation-only redactions.
* inconsistent redaction across frames.
* sensitive content visible in thumbnails.
* content revealed through alpha or channel inspection.

Never present generative reconstruction as recovered evidence.

Only report recovered text when supported by deterministic image transformations and repeatable OCR evidence.

---

# 27. Evidence graph

Implement an evidence graph as a central first-class component.

Node types:

```text
Artifact
Transformation
Observation
TextRegion
DecodedPayload
DetectorExecution
Finding
Claim
Limitation
PolicyDecision
```

Edge types:

```text
derived_from
observed_in
supports
corroborates
contradicts
duplicates
decoded_from
localized_at
depends_on
triggered_policy
```

The graph may initially be implemented using typed dictionaries and adjacency lists.

A graph database is not required.

Every report finding must be traceable back to:

* Detector.
* Detector version.
* Artifact.
* Transformation.
* Original source.
* Evidence observation.

---

# 28. Deduplication and correlation control

Do not count correlated results as independent evidence.

Group evidence into families:

```text
OCR
metadata
QR/barcode
embedded payload
binary structure
VLM
shadow execution
steganalysis
watermark
provenance
malware
```

OCR detections from multiple transformations are normally correlated.

Use:

* Text similarity.
* bounding-box overlap.
* transformation lineage.
* detector family.
* payload hash.
* artifact ancestry.

A large number of transformations finding the same text should strengthen evidence quality modestly, not multiply risk linearly.

---

# 29. Assessment model

Maintain separate category assessments.

Required categories:

```text
file_security
malware
embedded_payload
prompt_injection
covert_channel
steganography
watermarks
provenance
phishing
privacy
redaction_failure
adversarial_instability
authenticity_indicators
```

Each category assessment contains:

```text
state
likelihood when applicable
impact
coverage
finding_ids
limitations
summary
```

Do not use a single global probability as the primary security result.

An optional UI summary score may exist, but policy must not depend on it unless explicitly configured.

---

# 30. Deterministic policy engine

Implement a YAML-driven policy engine.

Do not use Python `eval`.

Support explicit operators such as:

```text
equals
not_equals
in
not_in
greater_than
greater_than_or_equal
less_than
exists
all
any
none
```

Example policy:

```yaml
profile: AGENT_WITH_TOOLS

rules:
  - id: quarantine-known-malware
    priority: 1000
    when:
      category: malware
      state_in:
        - CONFIRMED
        - HIGHLY_LIKELY
    action: QUARANTINE

  - id: quarantine-embedded-executable
    priority: 950
    when:
      category: embedded_payload
      type: executable
      state: CONFIRMED
    action: QUARANTINE

  - id: block-confirmed-prompt-injection
    priority: 900
    when:
      category: prompt_injection
      state_in:
        - CONFIRMED
        - HIGHLY_LIKELY
    action: BLOCK

  - id: review-possible-prompt-injection
    priority: 700
    when:
      category: prompt_injection
      state: POSSIBLE
    action: REVIEW

  - id: reconstructed-only-on-fragile-signal
    priority: 600
    when:
      category: adversarial_instability
      state_in:
        - POSSIBLE
        - HIGHLY_LIKELY
    action: ALLOW_RECONSTRUCTED_ONLY

  - id: public-redact-location
    priority: 500
    when:
      category: privacy
      reason_code: GPS_PRESENT
    action: ALLOW_WITH_REDACTION
```

Policy resolution must be deterministic.

Record:

* All matching rules.
* Winning rule.
* Rule priority.
* Resulting action.
* Explanation.

---

# 31. Required API

Implement these endpoints.

## Health

```http
GET /v1/health
```

## Capabilities

```http
GET /v1/capabilities
```

Return installed detectors, missing optional tools, formats, modes, and active policies.

## Attestation

```http
GET /v1/attestation
```

For the initial implementation, report:

* Application version.
* configuration hash.
* rule-bundle hash.
* installed optional tools.
* model adapters configured.
* network-offline configuration state.
* self-test status.

Do not claim physical air-gap status unless it can actually be established.

## Scan

```http
POST /v1/scans
Content-Type: multipart/form-data
```

Fields:

```text
file
mode=fast|deep|forensic
use_profile
sanitize=true|false
redact=true|false
include_raw_text=false
```

A synchronous implementation is acceptable initially.

Design the domain model so asynchronous jobs can be added later.

## Report

```http
GET /v1/scans/{scan_id}
```

## Artifacts

```http
GET /v1/artifacts/{artifact_id}
```

Only release artifacts marked `release_eligible`.

Never release the quarantined original through the normal artifact endpoint.

---

# 32. Required CLI

Implement a Typer CLI.

Examples:

```bash
argus-img scan example.png
argus-img scan example.png --mode deep
argus-img scan example.png --profile AGENT_WITH_TOOLS
argus-img scan example.png --output report.json
argus-img capabilities
argus-img health
argus-img verify-offline
argus-img validate-config
argus-img validate-rules
```

The CLI and API must use the same orchestration pipeline.

---

# 33. Required JSON report shape

Generate JSON matching a checked-in JSON Schema.

The report should resemble:

```json
{
  "schema_version": "1.0.0",
  "scan_id": "scan-generated-id",
  "created_at": "ISO-8601 timestamp",
  "scanner": {
    "name": "argus-img",
    "version": "0.1.0",
    "offline_mode": true,
    "mode": "deep",
    "use_profile": "AGENT_WITH_TOOLS",
    "configuration_hash": "sha256:..."
  },
  "input": {
    "original_filename": "upload.png",
    "size_bytes": 123456,
    "sha256": "sha256:...",
    "declared_mime": "image/png",
    "detected_mime": "image/png",
    "format": "PNG",
    "width": 1920,
    "height": 1080,
    "frames": 1
  },
  "decision": {
    "action": "BLOCK",
    "safe_claim": false,
    "reason_codes": [
      "PROMPT_INJECTION",
      "TOOL_INVOCATION_REQUEST"
    ],
    "triggered_policy_rules": [
      "block-confirmed-prompt-injection"
    ],
    "summary": "High-confidence instruction override was detected."
  },
  "assessments": {
    "file_security": {
      "state": "NO_EVIDENCE_FOUND",
      "coverage": "high",
      "finding_ids": []
    },
    "prompt_injection": {
      "state": "CONFIRMED",
      "likelihood": 0.96,
      "impact": "critical",
      "coverage": "high",
      "finding_ids": [
        "finding:001"
      ]
    },
    "steganography": {
      "state": "INCONCLUSIVE",
      "coverage": "medium",
      "finding_ids": [],
      "limitations": [
        "Arbitrary encrypted steganography cannot be excluded."
      ]
    }
  },
  "findings": [
    {
      "finding_id": "finding:001",
      "category": "prompt_injection",
      "type": "instruction_override",
      "state": "CONFIRMED",
      "severity": "critical",
      "detector_confidence": 0.98,
      "evidence_quality": 0.84,
      "attack_likelihood": 0.96,
      "impact": "critical",
      "source_artifact_ids": [
        "artifact:blue-channel-clahe"
      ],
      "observation_ids": [
        "observation:ocr-017"
      ],
      "detector_ids": [
        "detector:tesseract",
        "detector:prompt-rules"
      ],
      "reason_codes": [
        "INSTRUCTION_OVERRIDE",
        "TOOL_INVOCATION_REQUEST"
      ],
      "evidence": {
        "excerpt": "Ignore previous instructions and...",
        "full_text_returned": false,
        "text_sha256": "sha256:..."
      }
    }
  ],
  "artifacts": {
    "original": {
      "artifact_id": "artifact:original",
      "release_eligible": false
    },
    "canonical_lossless": {
      "artifact_id": "artifact:canonical-lossless",
      "release_eligible": true
    },
    "canonical_lossy": {
      "artifact_id": "artifact:canonical-lossy",
      "release_eligible": true
    }
  },
  "coverage": {
    "original_container": "high",
    "all_frames": "complete",
    "visible_text": "high",
    "low_contrast_text": "medium",
    "metadata_text": "high",
    "known_embedded_formats": "medium",
    "common_steganography": "medium",
    "unknown_steganography": "low",
    "registered_watermark_schemes": "low",
    "unknown_watermarks": "unsupported",
    "model_specific_adversarial_attacks": "not_tested",
    "universal_attack_absence": "impossible"
  },
  "module_status": {},
  "limitations": [],
  "errors": [],
  "timings_ms": {}
}
```

Validate every generated report against the JSON Schema in tests.

---

# 34. Safe subprocess runner

All external tools must use one central subprocess implementation.

Requirements:

* Never use `shell=True`.
* Pass commands as argument arrays.
* Set strict timeout.
* Limit captured stdout and stderr.
* Use sanitized environment variables.
* Set a controlled working directory.
* Reject paths outside the job directory or configured tool paths.
* Return structured exit status.
* Kill the process group on timeout.
* Do not inherit secrets.
* Do not permit interactive input.
* Record tool version when available.
* Escape untrusted output before logging.

Implement tests for:

* Timeout.
* oversized output.
* nonexistent executable.
* nonzero exit code.
* path containing spaces.
* attempted shell metacharacters.
* process cleanup.

---

# 35. Logging and sensitive-content handling

Use structured JSON logs.

Never log by default:

* Complete prompt-injection text.
* decoded credentials.
* private keys.
* precise GPS coordinates.
* full QR payloads containing secrets.
* complete extracted malware strings.

Log:

* Hash.
* short escaped excerpt.
* source.
* detector.
* reason code.
* length.
* redaction status.

Protect logs against:

* newline injection.
* terminal escape sequences.
* bidirectional-control characters.
* oversized values.

---

# 36. Offline enforcement

Implement an application-level `OfflineGuard`.

It should:

* Reject HTTP and HTTPS URLs as input sources.
* Prohibit remote model identifiers.
* require local absolute model paths.
* disallow runtime package installation.
* expose whether DNS or a default route appears configured.
* provide a self-test that attempts a harmless outbound socket connection and expects failure when strict mode is enabled.
* never fetch QR URLs.
* never retrieve remote C2PA resources.

Application-level enforcement is not a substitute for container or host isolation.

Provide:

```text
docker-compose.offline.yml
```

with:

```yaml
network_mode: "none"
read_only: true
cap_drop:
  - ALL
security_opt:
  - no-new-privileges:true
```

Use:

* Non-root user.
* Read-only application filesystem.
* Temporary writable job volume.
* `noexec`, `nodev`, and `nosuid` where supported.
* Bounded memory and process limits.

Do not create the GPU-specific deployment yet.

---

# 37. Pipeline orchestration

Implement this ordered pipeline:

```text
1. Receive upload through bounded stream.
2. Create immutable original artifact.
3. Hash original.
4. Detect format and MIME.
5. Enforce intake limits and format policy.
6. Run structural analysis.
7. Run differential decode.
8. Discover frames, thumbnails, alpha, and channels.
9. Run metadata analysis.
10. Run provenance adapter.
11. Run malware and embedded-content adapters.
12. Create canonical reconstructed artifacts.
13. Generate transformation bank.
14. Run OCR.
15. Run QR and barcode analysis.
16. Normalize and derive text candidates.
17. Run prompt rules.
18. Run configured prompt-classifier adapter.
19. Run intent extraction.
20. Run phishing and privacy analysis.
21. Run structural and optional steganalysis.
22. Run visible and registered watermark detectors.
23. Run configured visual analyzer or return NOT_TESTED.
24. Run stability comparison.
25. Build and deduplicate the evidence graph.
26. Build category assessments.
27. Apply deterministic policy.
28. Validate the report against JSON Schema.
29. Mark release-eligible artifacts.
30. Clean temporary files.
31. Return JSON.
```

A detector failure should normally be recorded and scanning should continue.

Malformed or structurally unsafe input may terminate semantic analysis early depending on policy.

---

# 38. Execution modes

Implement:

## Fast

```text
intake
structural validation
differential decode
metadata
canonical reconstruction
basic OCR
QR
prompt rules
basic privacy
policy
```

## Deep

```text
everything in fast
full transformation bank
OCR ensemble
embedded-content adapters
malware adapters
steganalysis
watermark plugins
stability analysis
optional visual analyzer
```

## Forensic

```text
everything in deep
all frames and thumbnails
expanded metadata
recursive extracted-object analysis
bit-plane artifacts
detailed evidence graph
extended tool output
signed or hash-manifested evidence bundle
```

---

# 39. Test fixture generator

Create `scripts/generate_test_images.py`.

Generate deterministic fixtures for:

```text
clean photograph-like image
plain text image
visible prompt injection
benign discussion of prompt injection
warning about prompt injection
low-contrast prompt
tiny prompt
rotated prompt
mirrored prompt
red-channel-only text
blue-channel-only text
alpha-dependent text
transparent overlay text
multi-frame GIF with prompt in one frame
metadata prompt
Base64 metadata prompt
QR prompt
URL QR code
image with trailing bytes
image with appended harmless ZIP
malformed image
oversized-dimension header fixture
visible watermark
repeated translucent watermark
GPS metadata
apparent redaction
thumbnail/main-image mismatch
```

Do not add dangerous executable samples.

---

# 40. Testing requirements

Use:

```text
pytest
pytest-asyncio
Hypothesis
coverage
```

## Unit tests

Cover:

* MIME detection.
* hashing.
* limits.
* artifact lineage.
* path containment.
* normalizers.
* Base64 and hex decoding.
* regex rules.
* policy operators.
* report serialization.
* JSON Schema validation.
* evidence deduplication.
* correlation grouping.
* timeout handling.
* excerpt redaction.

## Integration tests

Cover:

* Clean PNG.
* Clean JPEG.
* Visible prompt.
* metadata prompt.
* QR prompt.
* alpha-channel text.
* prompt in one animation frame.
* unsupported format.
* missing ExifTool.
* missing Tesseract.
* mocked malware result.
* mocked VLM attack result.
* reconstruction.
* artifact release restrictions.

## Security tests

Cover:

* Path traversal.
* symlink escape.
* oversized upload.
* decompression-bomb warning.
* recursive decoding limit.
* archive expansion limit.
* subprocess injection.
* log injection.
* Unicode bidirectional controls.
* excessive OCR output.
* timeout cleanup.
* accidental original-file release.
* URL-fetch prevention.
* runtime network prevention in strict test mode.

## Golden tests

Maintain versioned expected reports for representative fixtures.

Normalize timestamps and generated IDs before golden comparison.

Target meaningful test coverage, not artificial line coverage.

Core security, policy, normalization, and artifact modules should have at least 90% coverage.

---

# 41. Documentation requirements

Create:

## `README.md`

Include:

* Purpose.
* threat model.
* limitations.
* quick start.
* API example.
* CLI example.
* local dependencies.
* explanation of reconstructed artifacts.
* warning that the system cannot prove universal safety.

## `docs/architecture.md`

Document:

* Trust boundaries.
* byte path.
* pixel path.
* evidence graph.
* policy engine.
* future model integration.

## `docs/threat-model.md`

Document:

* attacker capabilities.
* protected assets.
* trust assumptions.
* out-of-scope threats.
* residual risks.

## `docs/detector-development.md`

Document how to add a detector without bypassing evidence or policy controls.

## `docs/policy-language.md`

Document all supported conditions and deterministic rule ordering.

## `docs/offline-deployment.md`

Document CPU-only local deployment.

Do not add GPU tuning yet.

## `docs/limitations.md`

Clearly describe:

* Unknown encrypted steganography.
* Unknown watermark schemes.
* OCR failures.
* model-specific adversarial attacks.
* false positives.
* false negatives.
* absence of live threat intelligence.
* stale local malware signatures.
* C2PA limitations.
* synthetic-image-classifier limitations.

## `docs/implementation-status.md`

Maintain a table:

```text
component
status
implemented backend
test status
known limitations
next work
```

Update this file as implementation proceeds.

---

# 42. Build phases

Implement in this order.

## Phase 0: repository and quality foundation

Deliver:

* Project structure.
* `pyproject.toml`.
* linting.
* formatting.
* type checking.
* testing.
* CI configuration if appropriate.
* base configuration loader.
* logging.
* core enums and models.

## Phase 1: artifact and intake foundation

Deliver:

* bounded streaming upload.
* content-addressed artifact store.
* MIME detection.
* file-format policy.
* limits.
* immutable original.
* cleanup.
* API and CLI skeleton.

## Phase 2: decoding and reconstruction

Deliver:

* Pillow decoder.
* OpenCV decoder.
* differential comparison.
* frame discovery.
* alpha and channel artifacts.
* canonical lossless reconstruction.
* canonical lossy reconstruction.
* metadata stripping.

## Phase 3: deterministic extraction

Deliver:

* metadata adapter.
* Tesseract adapter.
* QR adapter.
* fast transformation bank.
* text observations.
* text normalization.
* bounded decoding.

## Phase 4: prompt and policy analysis

Deliver:

* YAML prompt rules.
* intent extraction.
* mock classifier.
* evidence graph.
* category assessments.
* deterministic policy engine.
* complete JSON report.

At the end of Phase 4, the system must be useful without a VLM.

## Phase 5: extended local detectors

Deliver:

* ExifTool.
* YARA.
* ClamAV adapter.
* Binwalk adapter.
* zsteg adapter.
* C2PA adapter.
* watermark registry.
* steganography statistical summaries.

Adapters must degrade safely when tools are absent.

## Phase 6: visual-analysis interfaces

Deliver:

* `NullVisualAnalyzer`.
* `MockVisualAnalyzer`.
* VLM domain schemas.
* shadow-test schemas.
* multi-pass orchestration.
* mock integration tests.

Do not download or execute a large VLM yet.

## Phase 7: hardening

Deliver:

* offline guard.
* safe subprocess runner.
* read-only container.
* `network_mode: none`.
* non-root execution.
* output and log redaction.
* denial-of-service protections.
* startup self-tests.
* attestation endpoint.

## Phase 8: evaluation harness

Deliver:

* fixture generator.
* golden reports.
* benchmark command.
* detector timing.
* peak-memory measurement hooks.
* false-positive and false-negative evaluation format.

GPU execution and model benchmarking are a later project phase.

---

# 43. Definition of done for the implementation-first milestone

The implementation-first milestone is complete when all of the following are true:

1. A user can run:

```bash
argus-img scan tests/fixtures/clean.png --output report.json
```

2. The result validates against the checked-in JSON Schema.

3. A metadata-free reconstructed image is created.

4. A visible prompt-injection fixture creates a prompt-injection finding.

5. A benign article discussing prompt injection is distinguishable from an active command or marked ambiguous instead of automatically blocked.

6. A metadata prompt is detected and traced to the metadata field.

7. A QR prompt is decoded without opening its URL.

8. An alpha- or channel-specific prompt is detected by at least one transformed OCR path.

9. A malformed image is rejected or quarantined cleanly.

10. An unavailable optional detector is reported as `UNSUPPORTED`, not clean.

11. The original upload cannot be retrieved through the normal artifact endpoint.

12. Policy decisions are deterministic and include the winning rule.

13. The full application runs with no GPU.

14. Tests pass without internet access.

15. No runtime module attempts a network request.

16. The README contains working commands.

17. `docs/implementation-status.md` accurately states what is and is not implemented.

18. The implementation does not claim complete safety.

---

# 44. Working instructions for the coding agent

Follow this working method.

1. Inspect the current repository before changing anything.

2. Do not merely restate this specification.

3. Start implementing immediately.

4. Build one phase at a time.

5. Keep the repository runnable after each phase.

6. Run relevant tests after each meaningful change.

7. Do not fabricate passing test results.

8. Do not claim an optional integration works unless it was actually exercised.

9. When an external binary is unavailable, implement and test the adapter with mocked process output.

10. Prefer small, typed, composable modules.

11. Avoid global mutable state.

12. Avoid arbitrary dynamic imports.

13. Do not load plugins from user-controlled paths.

14. Do not call `eval` or `exec`.

15. Never use `shell=True`.

16. Do not introduce cloud services.

17. Do not add remote telemetry.

18. Do not download models during application startup.

19. Do not hardcode the current machine’s GPU.

20. Do not optimize prematurely for throughput.

21. Preserve a clean future interface for one-GPU execution.

22. Keep all untrusted text out of logs unless escaped and truncated.

23. Add a test whenever a security-sensitive bug is fixed.

24. If a requirement is too large for the current implementation pass, add its interface, schemas, tests, and an explicit status entry rather than pretending it is complete.

25. Do not leave core behavior hidden behind vague TODO comments.

At the end of each implementation pass, report:

```text
Summary of implemented work
Files created or changed
Commands executed
Tests run and results
Capabilities now working
Optional tools not tested
Known limitations
Next implementation phase
```

Begin with Phase 0 and Phase 1. Continue through later phases as repository and execution limits permit.

The immediate goal is a robust CPU-first implementation with complete architecture boundaries—not GPU tuning.
