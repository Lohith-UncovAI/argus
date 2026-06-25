from __future__ import annotations

from typing import Any, Dict, List, Protocol

from .models import (
    Artifact,
    DetectorManifest,
    DetectorReport,
    ScanContext,
    SupportResult,
    TextObservation,
)


class Detector(Protocol):
    manifest: DetectorManifest

    def supports(self, artifact: Artifact, context: ScanContext) -> SupportResult:
        ...

    async def analyze(self, artifact: Artifact, context: ScanContext) -> DetectorReport:
        ...


class TextClassificationContext(Protocol):
    source: str


class PromptClassifier(Protocol):
    async def classify(self, text: str, context: TextClassificationContext) -> Dict[str, Any]:
        ...


class WatermarkDetector(Protocol):
    scheme_id: str

    async def detect(self, artifact: Artifact, context: ScanContext) -> Dict[str, Any]:
        ...


class SteganalysisDetector(Protocol):
    detector_id: str

    async def analyze(self, artifact: Artifact, context: ScanContext) -> DetectorReport:
        ...


class VisualAnalyzer(Protocol):
    async def literal_inventory(self, image: Artifact, context: ScanContext) -> Dict[str, Any]:
        ...

    async def analyze_instructions(self, image: Artifact, context: ScanContext) -> Dict[str, Any]:
        ...

    async def analyze_deception(self, image: Artifact, context: ScanContext) -> Dict[str, Any]:
        ...

    async def verify_ocr_regions(
        self,
        image: Artifact,
        observations: List[TextObservation],
        context: ScanContext,
    ) -> Dict[str, Any]:
        ...

    async def run_shadow_test(self, image: Artifact, test_context: Dict[str, Any]) -> Dict[str, Any]:
        ...

