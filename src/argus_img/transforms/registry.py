from __future__ import annotations

from pathlib import Path
from typing import Dict, FrozenSet, Optional

from PIL import Image, ImageOps

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.budget import ResourceBudget
from argus_img.core.models import Artifact, ArtifactTransformation
from argus_img.decoding.pillow_decoder import encode_png


def _otsu_threshold(gray: Image.Image) -> Image.Image:
    histogram = gray.histogram()
    total = sum(histogram)
    sum_total = sum(i * histogram[i] for i in range(256))
    sum_background = 0.0
    weight_background = 0
    max_variance = -1.0
    threshold = 127
    for i in range(256):
        weight_background += histogram[i]
        if weight_background == 0:
            continue
        weight_foreground = total - weight_background
        if weight_foreground == 0:
            break
        sum_background += i * histogram[i]
        mean_background = sum_background / weight_background
        mean_foreground = (sum_total - sum_background) / weight_foreground
        variance = weight_background * weight_foreground * (mean_background - mean_foreground) ** 2
        if variance > max_variance:
            max_variance = variance
            threshold = i
    return gray.point(lambda p: 255 if p > threshold else 0)


def generate_fast_transformations(
    store: ArtifactStore,
    source_artifact: Artifact,
    source_path: Path,
    scan_id: str,
    budget: Optional[ResourceBudget] = None,
    active_transformations: Optional[FrozenSet[str]] = None,
) -> Dict[str, Artifact]:
    """Generate transformation bank, filtered to active_transformations.

    When active_transformations is None, all transforms run (backward compatible).
    Pass mode_plan.active_transformations to enforce per-mode gating:
      - Fast: grayscale + RGBA channels only (no Otsu, no inversion, no enlargement)
      - Deep: all of the above plus Otsu, inverted-grayscale, 2x-enlargement
      - Forensic: same as deep (bit-plane analysis added separately)
    """
    with Image.open(source_path) as raw:
        image = raw.convert("RGBA")
    gray = ImageOps.grayscale(image)
    artifacts: Dict[str, Artifact] = {}

    def _active(label: str) -> bool:
        return active_transformations is None or label in active_transformations

    def store_transformed(label: str, transformed: Image.Image, parameters: Optional[dict] = None) -> None:
        if not _active(label):
            return
        if transformed.mode not in {"RGB", "RGBA"}:
            transformed = transformed.convert("RGB")
        data = encode_png(transformed)
        if budget:
            budget.consume_transformed_pixels(transformed.width * transformed.height)
            budget.consume_artifact(len(data))
        transformation = ArtifactTransformation(
            transformation_id="transform:%s" % label,
            type=label.replace("-", "_"),
            parameters=parameters or {},
            inverse_coordinate_mapping="identity",
            reliability_class="forensic",
            resource_cost_class="low",
        )
        artifacts[label] = store.store_bytes(
            data,
            artifact_id="artifact:%s:%s" % (scan_id, label),
            media_type="image/png",
            created_by="transformation-bank",
            role=label,
            release_eligible=False,
            derived_from=source_artifact.artifact_id,
            transformation=transformation,
            width=transformed.width,
            height=transformed.height,
            representation_id="repr:%s" % label,
        )

    # Always-mandatory transforms (run regardless of active_transformations filtering):
    store_transformed("grayscale", gray)

    # Deep/forensic-only transforms:
    store_transformed("otsu-threshold", _otsu_threshold(gray))
    store_transformed("inverted-grayscale", ImageOps.invert(gray))

    # RGBA channel views — mandatory for content analysis in fast+deep+forensic:
    channels = image.split()
    channel_names = ["red-channel", "green-channel", "blue-channel", "alpha-channel"]
    for name, channel in zip(channel_names, channels):
        store_transformed(name, channel, {"source_channel": name.removesuffix("-channel")})

    # Deep/forensic-only:
    if _active("2x-enlargement"):
        enlarged = image.resize((image.width * 2, image.height * 2), Image.Resampling.BICUBIC)
        store_transformed("2x-enlargement", enlarged)

    # OCR preprocessing variants — critical for recovering text overlaid on photos.
    # White-text extraction: inverts then binarises, surfacing white/light text on
    # complex backgrounds (the dominant CyberSecEval3 / real-world injection style).
    if _active("white-text-extract"):
        inv = ImageOps.invert(gray)
        white_extract = inv.point(lambda p: 255 if p > 60 else 0)
        store_transformed("white-text-extract", white_extract,
                          {"method": "invert_threshold", "threshold": 60})

    # High-contrast grayscale: divides each pixel by a blurred background estimate
    # (background normalisation / unsharp divide).  Recovers low-contrast text
    # overlaid on bright or textured backgrounds without over-darkening the image.
    if _active("bg-normalised"):
        import numpy as np
        from PIL import ImageFilter
        arr = np.array(gray).astype(np.float32)
        blur = gray.filter(ImageFilter.GaussianBlur(radius=25))
        blur_arr = np.array(blur).astype(np.float32) + 1.0
        normalised = np.clip((arr / blur_arr) * 175, 0, 255).astype(np.uint8)
        store_transformed("bg-normalised", Image.fromarray(normalised),
                          {"method": "background_divide", "radius": 25, "scale": 175})

    # Sharpen + contrast boost: recovers slightly blurred / low-resolution overlays.
    if _active("sharpen-contrast"):
        from PIL import ImageFilter, ImageEnhance
        sharpened = ImageEnhance.Sharpness(gray).enhance(2.0)
        boosted = ImageEnhance.Contrast(sharpened).enhance(3.0)
        store_transformed("sharpen-contrast", boosted,
                          {"sharpness": 2.0, "contrast": 3.0})

    # Low-contrast amplification: inverts the grayscale image then stretches the
    # range with autocontrast (cutoff=2).  This surfaces near-white or near-same-
    # colour text that was composited at low opacity into a light background — the
    # kind of text that survives flatten-to-white with no visible trace but still
    # differs slightly in RGB from the surrounding pixels.  The invert step brings
    # the faint dark-on-light text up from the bottom of the histogram; autocontrast
    # then stretches the tiny delta to full 0-255 so Tesseract can read it.
    if _active("alpha-amplified"):
        inv = ImageOps.invert(gray)
        amplified = ImageOps.autocontrast(inv, cutoff=2)
        store_transformed("alpha-amplified", amplified,
                          {"method": "invert_autocontrast", "cutoff": 2})

    # CLAHE (Contrast Limited Adaptive Histogram Equalization): recovers low-contrast
    # text on textured/photo backgrounds by equalising local tile contrast.
    # Particularly effective for obfuscated text injections blended into photos.
    if _active("clahe"):
        import numpy as np
        import cv2
        gray_arr = np.array(gray)
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
        clahe_arr = clahe.apply(gray_arr)
        store_transformed("clahe", Image.fromarray(clahe_arr),
                          {"method": "clahe", "clip_limit": 3.0, "tile_grid": 8})

    # Deskew + CLAHE: corrects rotated/skewed injected text then enhances contrast.
    # Hough-line deskew works on binary edges, then CLAHE makes it OCR-readable.
    if _active("deskew"):
        import numpy as np
        import cv2
        gray_arr = np.array(gray)
        # Edge detect for Hough
        edges = cv2.Canny(gray_arr, 50, 150, apertureSize=3)
        lines = cv2.HoughLinesP(edges, 1, np.pi / 180, threshold=80,
                                minLineLength=gray_arr.shape[1] // 4, maxLineGap=20)
        if lines is not None and len(lines) > 0:
            angles = [np.degrees(np.arctan2(y2 - y1, x2 - x1))
                      for x1, y1, x2, y2 in lines[:, 0]]
            # Keep only near-horizontal lines (within ±15°)
            horiz = [a for a in angles if abs(a) < 15]
            angle = float(np.median(horiz)) if horiz else 0.0
        else:
            angle = 0.0
        if abs(angle) > 0.3:
            h, w = gray_arr.shape
            M = cv2.getRotationMatrix2D((w / 2, h / 2), angle, 1.0)
            deskewed = cv2.warpAffine(gray_arr, M, (w, h),
                                     flags=cv2.INTER_LINEAR,
                                     borderMode=cv2.BORDER_REPLICATE)
        else:
            deskewed = gray_arr
        # Apply CLAHE after deskew
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
        deskewed = clahe.apply(deskewed)
        store_transformed("deskew", Image.fromarray(deskewed),
                          {"method": "deskew_clahe", "angle_corrected": round(angle, 2)})

    # Channel-difference transforms: isolate text hidden by adding to one channel
    # and subtracting from another (R+text, G-text → R-G reveals text).
    # Threshold at mean+2σ of the difference to suppress background noise and
    # produce a binary image readable by Tesseract.
    import numpy as np
    rgb_arr = np.array(image.convert("RGB")).astype(np.int32)
    _diff_pairs = [
        ("rg-difference", 0, 1),
        ("rb-difference", 0, 2),
        ("gb-difference", 1, 2),
    ]
    for diff_name, ch_a, ch_b in _diff_pairs:
        if _active(diff_name):
            diff = (rgb_arr[:, :, ch_a] - rgb_arr[:, :, ch_b]).astype(np.float32)
            mean, std = diff.mean(), diff.std()
            # Produce two thresholded views per channel pair: sigma=1.5 favours
            # low-noise images; sigma=2.0 favours noisier backgrounds.  Tesseract
            # runs on both; the scorer picks the highest-scoring observation.
            for sigma, label_suffix in [(1.5, diff_name), (2.0, diff_name + "-hi")]:
                if not _active(label_suffix):
                    continue
                binary = ((diff > mean + sigma * std) * 255).astype(np.uint8)
                diff_img = Image.fromarray(binary, "L")
                diff_img = diff_img.resize(
                    (diff_img.width * 2, diff_img.height * 2), Image.Resampling.LANCZOS
                )
                store_transformed(label_suffix, diff_img,
                                  {"method": "channel_difference_threshold", "sigma": sigma,
                                   "upscale": 2,
                                   "channels": diff_name.replace("-difference", "")})

    return artifacts


def generate_grayscale_only(
    store: ArtifactStore,
    source_artifact: Artifact,
    source_path: Path,
    scan_id: str,
    budget: Optional[ResourceBudget] = None,
) -> Dict[str, Artifact]:
    """Minimal transform set: only grayscale."""
    with Image.open(source_path) as raw:
        image = raw.convert("RGBA")
    gray = ImageOps.grayscale(image)
    artifacts: Dict[str, Artifact] = {}

    data = encode_png(gray.convert("RGB"))
    if budget:
        budget.consume_transformed_pixels(gray.width * gray.height)
        budget.consume_artifact(len(data))
    transformation = ArtifactTransformation(
        transformation_id="transform:grayscale",
        type="grayscale",
        parameters={},
        inverse_coordinate_mapping="identity",
        reliability_class="forensic",
        resource_cost_class="low",
    )
    artifacts["grayscale"] = store.store_bytes(
        data,
        artifact_id="artifact:%s:grayscale" % scan_id,
        media_type="image/png",
        created_by="transformation-bank",
        role="grayscale",
        release_eligible=False,
        derived_from=source_artifact.artifact_id,
        transformation=transformation,
        width=gray.width,
        height=gray.height,
        representation_id="repr:grayscale",
    )
    return artifacts
