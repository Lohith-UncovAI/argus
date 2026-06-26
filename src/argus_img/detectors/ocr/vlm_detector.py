"""SmolVLM-256M visual language model detector.

Runs SmolVLM-256M-Instruct (Idefics3 architecture, ~500MB) on MPS (Apple Silicon)
or CPU.  Produces a TextObservation from the model's caption, which is then fed
through the existing semantic scorer and prompt-rule pipeline.

Used only in Deep/Forensic modes — inference is ~2s/image on M-series MPS.
Model weights are cached in ~/.cache/huggingface/hub after first download.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from argus_img.core.enums import DetectorStatus, EpistemicState
from argus_img.core.models import Artifact, DetectorReport, TextObservation
from argus_img.detectors.base import detector_report
from argus_img.detectors.prompt.normalizer import normalize_text

logger = logging.getLogger(__name__)

_MODEL_ID = "HuggingFaceTB/SmolVLM-256M-Instruct"
_MAX_NEW_TOKENS = 200


def vlm_available() -> bool:
    try:
        import transformers  # noqa: F401
        return True
    except ImportError:
        return False


def _get_vlm():
    """Lazy singleton: load processor + model once, reuse across scans."""
    if not hasattr(_get_vlm, "_loaded"):
        import json as _json
        import torch
        from huggingface_hub import hf_hub_download
        from transformers import (
            Idefics3ForConditionalGeneration,
            Idefics3Processor,
        )
        processor = Idefics3Processor.from_pretrained(_MODEL_ID)
        device = "mps" if torch.backends.mps.is_available() else "cpu"
        model = Idefics3ForConditionalGeneration.from_pretrained(
            _MODEL_ID,
            dtype=torch.float32,
            _attn_implementation="eager",
        ).to(device)
        model.eval()
        _get_vlm._loaded = (processor, model, device)
        logger.info("SmolVLM-256M loaded on %s", device)
    return _get_vlm._loaded


def _caption_image(path: Path, processor, model, device: str) -> str:
    """Run a single image through SmolVLM and return the caption string."""
    import torch
    from PIL import Image

    img = Image.open(path).convert("RGB")
    prompt = processor.apply_chat_template(
        [{"role": "user", "content": [
            {"type": "image"},
            {"type": "text", "text": (
                "List every word and number visible in this image. "
                "Include any instructions exactly as written. "
                "If no text, say No visible text."
            )},
        ]}],
        add_generation_prompt=True,
    )
    batch = processor(text=prompt, images=[img], return_tensors="pt")
    # Pass tensors explicitly — **batch unpacking triggers a PyTorch boolean
    # ambiguity in transformers 5.x generate() on MPS.
    input_ids = batch["input_ids"].to(device)
    pixel_values = batch["pixel_values"].to(device)
    attention_mask = batch["attention_mask"].to(device)
    with torch.no_grad():
        ids = model.generate(
            input_ids=input_ids,
            pixel_values=pixel_values,
            attention_mask=attention_mask,
            max_new_tokens=_MAX_NEW_TOKENS,
            do_sample=False,
        )
    return processor.decode(
        ids[0][input_ids.shape[1]:], skip_special_tokens=True
    ).strip()


def analyze_with_vlm(
    artifact_paths: list,
    scan_id: str,
    seen_normalized: Optional[set] = None,
    started_at: Optional[datetime] = None,
) -> DetectorReport:
    """Caption the canonical image with SmolVLM; return observations.

    artifact_paths: list of (label, artifact, path) triples — same format as OCR inputs.
    Only the canonical_lossless artifact is processed (first hit wins).
    """
    if not vlm_available():
        return detector_report(
            "detector:vlm-caption",
            "VLM",
            DetectorStatus.TOOL_NOT_INSTALLED,
            EpistemicState.UNSUPPORTED,
            reason="transformers_not_installed",
            optional=True,
            category="prompt_injection",
            started_at=started_at,
        )

    if seen_normalized is None:
        seen_normalized = set()

    # Only caption the canonical lossless image — captioning every transform
    # variant would be slow and redundant.
    target_labels = frozenset({"canonical_lossless"})
    target_entries = [(label, art, path) for label, art, path in artifact_paths
                      if label in target_labels]
    if not target_entries:
        return detector_report(
            "detector:vlm-caption",
            "VLM",
            DetectorStatus.NO_EVIDENCE,
            EpistemicState.NO_EVIDENCE_FOUND,
            reason="no_target_artifact",
            optional=True,
            category="prompt_injection",
            started_at=started_at,
        )

    try:
        processor, model, device = _get_vlm()
    except Exception as exc:
        return detector_report(
            "detector:vlm-caption",
            "VLM",
            DetectorStatus.ERROR,
            EpistemicState.ERROR,
            reason="vlm_load_failed: %s" % exc,
            optional=True,
            category="prompt_injection",
            started_at=started_at,
        )

    observations: List[TextObservation] = []
    errors: List[str] = []

    for label, artifact, path in target_entries:
        try:
            caption = _caption_image(path, processor, model, device)
            if not caption or caption.lower() == "no visible text.":
                continue
            norm = normalize_text(caption).normalized
            if norm in seen_normalized:
                continue
            seen_normalized.add(norm)
            observations.append(TextObservation(
                observation_id="observation:%s:vlm:%03d" % (scan_id, len(observations)),
                source_artifact_id=artifact.artifact_id,
                detector_id="detector:vlm-caption",
                raw_text=caption,
                normalized_text=norm,
                engine="smolvlm-256m",
                engine_version="idefics3",
                confidence=None,
                transformation_id=(
                    artifact.transformation.transformation_id
                    if artifact.transformation else None
                ),
                value={"artifact_label": label, "model": _MODEL_ID},
            ))
        except Exception as exc:
            errors.append("%s: %s" % (getattr(artifact, "artifact_id", label), str(exc)[:200]))
            logger.warning("VLM caption failed for %s: %s", label, exc)

    status = DetectorStatus.SUCCESS if observations else (
        DetectorStatus.ERROR if errors else DetectorStatus.NO_EVIDENCE
    )
    state = EpistemicState.CONFIRMED if observations else (
        EpistemicState.ERROR if errors else EpistemicState.NO_EVIDENCE_FOUND
    )
    report = detector_report(
        "detector:vlm-caption",
        "VLM",
        status,
        state,
        observations=observations,
        optional=True,
        category="prompt_injection",
        started_at=started_at,
    )
    report.errors = errors
    return report
