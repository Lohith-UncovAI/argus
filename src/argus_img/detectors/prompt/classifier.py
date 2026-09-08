"""Prompt-injection text classifiers.

ARGUS-IMG's prompt layer has three signals, in increasing order of recall and
decreasing order of determinism:

  1. ``rules.py``      — regex bundle. Deterministic. Produces ``CONFIRMED``.
  2. ``semantic.py``   — token/bigram/structural heuristic scorer. Produces
                         ``HIGHLY_LIKELY`` at most.
  3. this module       — an optional local ML classifier. Produces
                         ``HIGHLY_LIKELY`` at most, and only ever *evidence*:
                         the deterministic policy engine still decides.

The classifier is optional in exactly the same way ExifTool / Tesseract /
ClamAV are: if no local model directory is configured it reports ``NOT_TESTED``
and the pipeline is unchanged. Nothing is ever downloaded at scan time —
``local_files_only=True`` is passed to every ``from_pretrained`` call, mirroring
``detectors/ocr/vlm_detector.py``.

Configuration (environment, so it needs no schema change):

  ARGUS_PROMPT_CLASSIFIER_PATH
      Absolute path to a local directory holding a HuggingFace
      sequence-classification model (config.json + tokenizer + weights).
      Unset  -> classifier disabled, pipeline unaffected.

  ARGUS_PROMPT_CLASSIFIER_LABELMAP
      Optional absolute path to a JSON label map (see ``LabelMap`` below).
      When absent, the model's own ``id2label`` is used with a built-in
      heuristic mapping from common label names ("INJECTION", "JAILBREAK",
      "LEGIT", ...) to ARGUS reason codes.

  ARGUS_PROMPT_CLASSIFIER_BACKEND
      "transformers" (default) or "onnx". "onnx" additionally requires
      ``onnxruntime`` to be importable and a ``model.onnx`` in the model dir.

The label map lets one adapter serve both a plain binary detector
(ProtectAI deberta-v3-prompt-injection, Meta Prompt Guard) and a multi-label
model trained on ARGUS's own policy categories, without code changes.
"""
from __future__ import annotations

import json
import logging
import hashlib
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

__all__ = [
    "THRESHOLD_BLOCK", "THRESHOLD_REVIEW", "ARGUS_MULTILABEL",
    "LabelMap", "LabelSpec", "PromptClassification",
    "LocalTransformerClassifier", "NullPromptClassifier", "MockPromptClassifier",
    "ONNXPromptClassifier", "TransformersPromptClassifier",
    "load_prompt_classifier", "load_label_map",
    "prompt_classifier_available", "classifier_model_dir", "classifier_fingerprint",
    "classifier_status",
]

# ── Decision thresholds (calibratable; see tools/evaluation/calibrate_prompt_detectors.py)
# A model probability at or above BLOCK maps to a HIGHLY_LIKELY / BLOCK finding;
# at or above REVIEW, a POSSIBLE / REVIEW finding; below REVIEW, no finding.
THRESHOLD_BLOCK = float(os.environ.get("ARGUS_PROMPT_CLASSIFIER_BLOCK", "0.60"))
THRESHOLD_REVIEW = float(os.environ.get("ARGUS_PROMPT_CLASSIFIER_REVIEW", "0.35"))

# Text longer than this many characters is scored in overlapping windows and the
# per-window scores are max-pooled — an injection in one paragraph of a long OCR
# dump should still light up the whole observation.
_WINDOW_CHARS = 900
_WINDOW_OVERLAP = 200

_ENV_PATH = "ARGUS_PROMPT_CLASSIFIER_PATH"
_ENV_LABELMAP = "ARGUS_PROMPT_CLASSIFIER_LABELMAP"
_ENV_BACKEND = "ARGUS_PROMPT_CLASSIFIER_BACKEND"


# ── Label mapping ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LabelSpec:
    """How one model output label maps into an ARGUS finding."""

    name: str
    benign: bool = False
    severity: str = "high"
    reason_codes: Tuple[str, ...] = ("PROMPT_INJECTION",)


@dataclass
class Calibration:
    """Post-hoc probability calibration fitted on a held-out split.

    Raw classifier probabilities are usually over-confident. ``temperature``
    divides the logits before the sigmoid/softmax; ``platt`` applies
    ``sigmoid(a * logit + b)`` to the max non-benign logit. ``method="none"``
    (default) leaves probabilities untouched.
    """

    method: str = "none"          # "none" | "temperature" | "platt"
    temperature: float = 1.0
    a: float = 1.0
    b: float = 0.0

    def apply_logits(self, logits: Sequence[float]) -> List[float]:
        if self.method == "temperature" and self.temperature not in (0.0, 1.0):
            return [x / self.temperature for x in logits]
        return list(logits)

    def apply_score(self, score: float, raw_max_logit: Optional[float]) -> float:
        if self.method == "platt" and raw_max_logit is not None:
            return _sigmoid(self.a * raw_max_logit + self.b)
        return score


@dataclass
class LabelMap:
    problem_type: str = "single_label_classification"  # or "multi_label_classification"
    labels: Dict[int, LabelSpec] = field(default_factory=dict)
    threshold_block: float = THRESHOLD_BLOCK
    threshold_review: float = THRESHOLD_REVIEW
    calibration: Calibration = field(default_factory=Calibration)

    @property
    def multi_label(self) -> bool:
        return self.problem_type == "multi_label_classification"

    def spec(self, index: int) -> LabelSpec:
        return self.labels.get(index, LabelSpec(name="label_%d" % index))


# Common off-the-shelf label names -> ARGUS reason codes. Used when a model ships
# no ARGUS label map of its own (ProtectAI, Meta Prompt Guard, deepset, ...).
_NAME_HEURISTICS: List[Tuple[re.Pattern, LabelSpec]] = [
    (re.compile(r"benign|legit|safe|clean|negative|no[_-]?injection|label_0$", re.I),
     LabelSpec(name="benign", benign=True, reason_codes=())),
    (re.compile(r"jailbreak", re.I),
     LabelSpec(name="jailbreak", severity="critical",
               reason_codes=("PROMPT_INJECTION", "INSTRUCTION_OVERRIDE", "POLICY_BYPASS"))),
    (re.compile(r"instruction|override|hijack", re.I),
     LabelSpec(name="instruction_override", severity="critical",
               reason_codes=("PROMPT_INJECTION", "INSTRUCTION_OVERRIDE"))),
    (re.compile(r"credential|secret|password|exfil|leak", re.I),
     LabelSpec(name="data_exfiltration", severity="high",
               reason_codes=("PROMPT_INJECTION", "DATA_EXFILTRATION"))),
    (re.compile(r"tool|function[_-]?call", re.I),
     LabelSpec(name="tool_invocation", severity="critical",
               reason_codes=("PROMPT_INJECTION", "TOOL_INVOCATION_REQUEST"))),
    (re.compile(r"inject|prompt[_-]?injection|malicious|attack|unsafe|positive|label_1$", re.I),
     LabelSpec(name="prompt_injection", severity="critical",
               reason_codes=("PROMPT_INJECTION",))),
]

# ARGUS-native multi-label schema — the categories the policy engine already
# distinguishes. A model trained by tools/training/train_prompt_classifier.py
# emits exactly these, in this order (index 0 = benign).
ARGUS_MULTILABEL = LabelMap(
    problem_type="multi_label_classification",
    labels={
        0: LabelSpec("benign", benign=True, reason_codes=()),
        1: LabelSpec("instruction_override", severity="critical",
                     reason_codes=("PROMPT_INJECTION", "INSTRUCTION_OVERRIDE")),
        2: LabelSpec("credential_request", severity="high",
                     reason_codes=("PROMPT_INJECTION", "CREDENTIAL_REQUEST")),
        3: LabelSpec("tool_invocation", severity="critical",
                     reason_codes=("PROMPT_INJECTION", "TOOL_INVOCATION_REQUEST")),
        4: LabelSpec("data_exfiltration", severity="high",
                     reason_codes=("PROMPT_INJECTION", "DATA_EXFILTRATION")),
        5: LabelSpec("policy_bypass", severity="critical",
                     reason_codes=("PROMPT_INJECTION", "POLICY_BYPASS")),
    },
)


def _labelspec_from_name(index: int, name: str) -> LabelSpec:
    for pattern, template in _NAME_HEURISTICS:
        if pattern.search(name or ""):
            return LabelSpec(name=name or template.name, benign=template.benign,
                             severity=template.severity, reason_codes=template.reason_codes)
    # Unknown non-benign label: treat as a generic injection signal.
    return LabelSpec(name=name or "label_%d" % index,
                     reason_codes=("PROMPT_INJECTION",))


def load_label_map(model_dir: Path, override_path: Optional[str]) -> LabelMap:
    """Resolve the label map: explicit JSON override > model config > heuristics."""
    if override_path:
        return _label_map_from_json(json.loads(Path(override_path).read_text(encoding="utf-8")))

    argus_map = model_dir / "argus_label_map.json"
    if argus_map.is_file():
        return _label_map_from_json(json.loads(argus_map.read_text(encoding="utf-8")))

    config_path = model_dir / "config.json"
    problem_type = "single_label_classification"
    id2label: Dict[str, str] = {}
    if config_path.is_file():
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        problem_type = cfg.get("problem_type") or problem_type
        id2label = cfg.get("id2label") or {}
    labels = {
        int(idx): _labelspec_from_name(int(idx), name)
        for idx, name in id2label.items()
    }
    if not labels:
        # Binary fallback: index 0 benign, index 1 injection.
        labels = {0: _NAME_HEURISTICS[0][1], 1: _labelspec_from_name(1, "prompt_injection")}
    return LabelMap(problem_type=problem_type, labels=labels)


def _label_map_from_json(data: Dict) -> LabelMap:
    labels = {}
    for idx, spec in data.get("labels", {}).items():
        labels[int(idx)] = LabelSpec(
            name=spec.get("name", "label_%s" % idx),
            benign=bool(spec.get("benign", False)),
            severity=spec.get("severity", "high"),
            reason_codes=tuple(spec.get("reason_codes", ("PROMPT_INJECTION",))),
        )
    cal_raw = data.get("calibration") or {}
    calibration = Calibration(
        method=cal_raw.get("method", "none"),
        temperature=float(cal_raw.get("temperature", 1.0)),
        a=float(cal_raw.get("a", 1.0)),
        b=float(cal_raw.get("b", 0.0)),
    )
    return LabelMap(
        problem_type=data.get("problem_type", "single_label_classification"),
        labels=labels,
        threshold_block=float(data.get("threshold_block", THRESHOLD_BLOCK)),
        threshold_review=float(data.get("threshold_review", THRESHOLD_REVIEW)),
        calibration=calibration,
    )


# ── Availability ────────────────────────────────────────────────────────────

def classifier_model_dir() -> Optional[Path]:
    raw = os.environ.get(_ENV_PATH, "").strip()
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_dir() else None


def prompt_classifier_available() -> bool:
    """True only when a local model dir is configured AND its backend imports."""
    model_dir = classifier_model_dir()
    if model_dir is None:
        return False
    backend = os.environ.get(_ENV_BACKEND, "transformers").strip().lower()
    try:
        if backend == "onnx":
            import onnxruntime  # noqa: F401
            import transformers  # noqa: F401  (tokenizer only)
            return (model_dir / "model.onnx").is_file()
        import transformers  # noqa: F401
        return True
    except ImportError:
        return False


_FINGERPRINT_FILES = ("config.json", "argus_label_map.json", "tokenizer.json",
                      "tokenizer_config.json", "special_tokens_map.json")
_FINGERPRINT_WEIGHTS = ("model.safetensors", "pytorch_model.bin", "model.onnx")


def classifier_fingerprint(model_dir: Optional[Path] = None) -> Optional[str]:
    """A cheap, stable identity for the configured model.

    sha256 over the bytes of the small config/tokenizer files plus a manifest of
    ``(name, size)`` for the weight files — enough to detect a swapped model or
    changed label map without hashing gigabytes of weights. Returned in the
    attestation payload and on every classifier finding so a report is tied to a
    reproducible model.
    """
    model_dir = model_dir or classifier_model_dir()
    if model_dir is None:
        return None
    model_dir = Path(model_dir)
    if not model_dir.is_dir():
        return None
    h = hashlib.sha256()
    for name in _FINGERPRINT_FILES:
        p = model_dir / name
        if p.is_file():
            h.update(b"%s\0" % name.encode())
            h.update(p.read_bytes())
    for name in _FINGERPRINT_WEIGHTS:
        p = model_dir / name
        if p.is_file():
            h.update(b"%s\0%d\0" % (name.encode(), p.stat().st_size))
    return "sha256:" + h.hexdigest()


def classifier_status() -> Dict[str, object]:
    """Structured status for the /v1/capabilities and attestation endpoints."""
    model_dir = classifier_model_dir()
    if model_dir is None:
        return {"configured": False, "adapter": "NullPromptClassifier",
                "reason": "ARGUS_PROMPT_CLASSIFIER_PATH unset"}
    available = prompt_classifier_available()
    status: Dict[str, object] = {
        "configured": True,
        "available": available,
        "backend": os.environ.get(_ENV_BACKEND, "transformers").strip().lower(),
        "model_fingerprint": classifier_fingerprint(model_dir),
    }
    if not available:
        status["reason"] = "backend import failed or model.onnx missing"
        status["adapter"] = "NullPromptClassifier"
        return status
    clf = LocalTransformerClassifier.from_env()
    status["adapter"] = "LocalTransformerClassifier"
    if clf is not None:
        lm = clf.label_map
        status["problem_type"] = lm.problem_type
        status["labels"] = [lm.spec(i).name for i in sorted(lm.labels)]
        status["threshold_block"] = lm.threshold_block
        status["threshold_review"] = lm.threshold_review
        status["calibration"] = lm.calibration.method
    return status


# ── Classification result ───────────────────────────────────────────────────

@dataclass
class PromptClassification:
    status: str                       # "SUCCESS" | "NOT_TESTED" | "UNSUPPORTED" | "ERROR"
    score: float = 0.0                # max non-benign probability
    label: str = "benign"             # dominant non-benign label name, or "benign"
    per_label: Dict[str, float] = field(default_factory=dict)
    reason: Optional[str] = None
    model_source: Optional[str] = None
    windows: int = 1

    def to_dict(self) -> Dict[str, object]:
        d: Dict[str, object] = {"status": self.status}
        if self.status == "SUCCESS":
            d.update(score=round(self.score, 4), label=self.label,
                     per_label={k: round(v, 4) for k, v in self.per_label.items()},
                     windows=self.windows, model_source=self.model_source)
        if self.reason:
            d["reason"] = self.reason
        return d


# ── Local transformer classifier ───────────────────────────────────────────

class LocalTransformerClassifier:
    """HuggingFace sequence-classification model, CPU, offline.

    Lazy singleton load (one model per process, reused across scans), matching
    ``vlm_detector._get_vlm``.
    """

    _cache: Dict[str, "LocalTransformerClassifier"] = {}

    def __init__(self, model_dir: Path, label_map: LabelMap, backend: str = "transformers") -> None:
        self.model_dir = model_dir
        self.label_map = label_map
        self.backend = backend
        self._runtime = None  # (tokenizer, model) or (tokenizer, onnx_session)

    @classmethod
    def from_env(cls) -> Optional["LocalTransformerClassifier"]:
        model_dir = classifier_model_dir()
        if model_dir is None:
            return None
        key = str(model_dir)
        if key not in cls._cache:
            label_map = load_label_map(model_dir, os.environ.get(_ENV_LABELMAP, "").strip() or None)
            backend = os.environ.get(_ENV_BACKEND, "transformers").strip().lower()
            cls._cache[key] = cls(model_dir, label_map, backend)
        return cls._cache[key]

    # -- runtime -----------------------------------------------------------

    def _load(self):
        if self._runtime is not None:
            return self._runtime
        source = str(self.model_dir)
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(source, local_files_only=True)
        if self.backend == "onnx":
            import onnxruntime
            session = onnxruntime.InferenceSession(
                str(self.model_dir / "model.onnx"),
                providers=["CPUExecutionProvider"],
            )
            # DeBERTa-v3 and many other encoders export without token_type_ids;
            # feeding an input the graph does not declare is a hard error.
            session._argus_input_names = {i.name for i in session.get_inputs()}
            self._runtime = (tokenizer, session)
        else:
            import torch  # noqa: F401
            from transformers import AutoModelForSequenceClassification
            model = AutoModelForSequenceClassification.from_pretrained(
                source, local_files_only=True
            )
            model.eval()
            self._runtime = (tokenizer, model)
        logger.info("prompt classifier loaded (%s) from %s", self.backend, source)
        return self._runtime

    def _logits(self, text: str) -> Sequence[float]:
        tokenizer, engine = self._load()
        enc = tokenizer(text, truncation=True, max_length=512, return_tensors=None)
        if self.backend == "onnx":
            import numpy as np
            allowed = getattr(engine, "_argus_input_names", {"input_ids", "attention_mask"})
            feeds = {
                k: np.asarray([v], dtype=np.int64)
                for k, v in enc.items()
                if k in allowed
            }
            outputs = engine.run(None, feeds)
            return list(map(float, outputs[0][0]))
        import torch
        inputs = {k: torch.tensor([v]) for k, v in enc.items()
                  if k in {"input_ids", "attention_mask", "token_type_ids"}}
        with torch.no_grad():
            logits = engine(**inputs).logits[0]
        return [float(x) for x in logits]

    # -- scoring ---------------------------------------------------------

    def classify_sync(self, text: str) -> PromptClassification:
        text = (text or "").strip()
        if not text:
            return PromptClassification(status="SUCCESS", model_source=str(self.model_dir))
        try:
            windows = _windows(text)
            scored = [self._probabilities(w) for w in windows]
            pooled = _max_pool([probs for probs, _ in scored])
            raw_max_logit = max((rl for _, rl in scored if rl is not None), default=None)
        except Exception as exc:  # noqa: BLE001 — a model failure must not abort the scan
            logger.warning("prompt classifier inference failed: %s", exc)
            return PromptClassification(status="ERROR", reason=str(exc),
                                        model_source=str(self.model_dir))

        per_label: Dict[str, float] = {}
        best_score = 0.0
        benign_name = next((s.name for s in self.label_map.labels.values() if s.benign), "benign")
        best_label = benign_name
        for idx, prob in enumerate(pooled):
            spec = self.label_map.spec(idx)
            per_label[spec.name] = prob
            if spec.benign:
                continue
            if prob > best_score:
                best_score, best_label = prob, spec.name

        best_score = min(max(self.label_map.calibration.apply_score(best_score, raw_max_logit), 0.0), 1.0)
        # Below the review threshold the dominant label is not "the attack class
        # at 0.02" — report it as benign so logs/evidence are not misleading.
        if best_score < self.label_map.threshold_review:
            best_label = benign_name
        return PromptClassification(
            status="SUCCESS", score=best_score, label=best_label,
            per_label=per_label, model_source=str(self.model_dir), windows=len(windows),
        )

    def _probabilities(self, text: str) -> Tuple[List[float], Optional[float]]:
        """Return (per-label probabilities, max non-benign raw logit)."""
        logits = list(self._logits(text))
        cal_logits = self.label_map.calibration.apply_logits(logits)
        non_benign = [logits[i] for i in range(len(logits)) if not self.label_map.spec(i).benign]
        raw_max_logit = max(non_benign) if non_benign else None
        if self.label_map.multi_label:
            return [_sigmoid(x) for x in cal_logits], raw_max_logit
        return _softmax(cal_logits), raw_max_logit

    async def classify(self, text: str, context=None) -> Dict[str, object]:  # protocol conformance
        return self.classify_sync(text).to_dict()


# ── Math helpers (no numpy dependency in the transformers path) ─────────────

def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


def _softmax(xs: Sequence[float]) -> List[float]:
    m = max(xs)
    exps = [math.exp(x - m) for x in xs]
    total = sum(exps) or 1.0
    return [e / total for e in exps]


def _windows(text: str) -> List[str]:
    if len(text) <= _WINDOW_CHARS:
        return [text]
    step = _WINDOW_CHARS - _WINDOW_OVERLAP
    return [text[i:i + _WINDOW_CHARS] for i in range(0, len(text), step) if text[i:i + _WINDOW_CHARS].strip()]


def _max_pool(per_window: List[List[float]]) -> List[float]:
    if not per_window:
        return []
    width = max(len(row) for row in per_window)
    return [max(row[i] if i < len(row) else 0.0 for row in per_window) for i in range(width)]


# ── Factory + stubs ────────────────────────────────────────────────────────

def load_prompt_classifier():
    """Return the configured classifier, or ``NullPromptClassifier`` if none."""
    if prompt_classifier_available():
        clf = LocalTransformerClassifier.from_env()
        if clf is not None:
            return clf
    return NullPromptClassifier()


class NullPromptClassifier:
    async def classify(self, text: str, context=None) -> Dict[str, object]:
        return {"status": "NOT_TESTED", "state": "NOT_TESTED", "reason": "no_local_model_configured"}

    def classify_sync(self, text: str) -> PromptClassification:
        return PromptClassification(status="NOT_TESTED", reason="no_local_model_configured")


class MockPromptClassifier:
    """Deterministic stand-in used by tests and the default attestation manifest."""

    async def classify(self, text: str, context=None) -> Dict[str, object]:
        return self.classify_sync(text).to_dict()

    def classify_sync(self, text: str) -> PromptClassification:
        lower = (text or "").lower()
        if "ignore previous instructions" in lower:
            score = 0.95
        elif "prompt injection" in lower:
            score = 0.4
        else:
            score = 0.02
        label = "prompt_injection" if score >= 0.5 else "benign"
        return PromptClassification(
            status="SUCCESS", score=score, label=label,
            per_label={"benign": 1.0 - score, "prompt_injection": score},
            model_source="mock",
        )


class ONNXPromptClassifier:
    """Kept for backwards compatibility — the real ONNX path is
    ``LocalTransformerClassifier(backend="onnx")``."""

    async def classify(self, text: str, context=None) -> Dict[str, object]:
        if prompt_classifier_available():
            return await LocalTransformerClassifier.from_env().classify(text, context)
        return {"status": "UNSUPPORTED", "reason": "local ONNX model path not configured"}


class TransformersPromptClassifier:
    async def classify(self, text: str, context=None) -> Dict[str, object]:
        if prompt_classifier_available():
            return await LocalTransformerClassifier.from_env().classify(text, context)
        return {"status": "UNSUPPORTED", "reason": "local transformers model path not configured"}
