"""Parser worker entry point.

This module is executed as a separate process (via spawn, not fork) so that
hostile image parsing is isolated from the API, policy engine, and database.

The worker currently:
1. Applies sandbox resource limits.
2. Reads a WorkerRequest from stdin.
3. Performs authoritative Pillow intake parsing, bounds checks, structural
   verification, and a forced pixel decode.
4. Writes a WorkerResponse to stdout.
5. Exits.

Canonical derivatives and optional animated-frame extraction are generated in
this boundary; the control process imports only independently verified files.

The worker has no access to the release-grant database and cannot write
outside its assigned job directory.
"""
from __future__ import annotations

import json
import os
import sys
import time
import hashlib
import io
from pathlib import Path


def _apply_sandbox(deadline_epoch: float, cpu_seconds: int = 60) -> None:
    """Apply resource limits before any parsing begins."""
    from argus_img.workers.sandbox import WorkerSandbox
    wall = max(1.0, deadline_epoch - time.time()) if deadline_epoch > 0 else 90.0
    sandbox = WorkerSandbox(cpu_seconds=min(cpu_seconds, int(wall) + 5))
    sandbox.apply()


def _encode_png(image) -> bytes:
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=False)
    return output.getvalue()


def _encode_jpeg(image) -> bytes:
    output = io.BytesIO()
    image.convert("RGB").save(output, format="JPEG", quality=90, optimize=False)
    return output.getvalue()


def _record_artifact(job_dir: Path, scan_id: str, role: str, data: bytes,
                     width: int, height: int, transformation_type: str,
                     transformation_id: str, frame_index=None) -> dict:
    artifact_dir = job_dir / "parser-artifacts"
    artifact_dir.mkdir(mode=0o700, exist_ok=True)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    extension = ".jpg" if role == "canonical_lossy" else ".png"
    path = artifact_dir / (role + extension)
    path.write_bytes(data)
    return {
        "artifact_id": "artifact:%s:%s" % (scan_id, role),
        "sha256": digest,
        "role": role,
        "media_type": "image/jpeg" if role == "canonical_lossy" else "image/png",
        "size_bytes": len(data),
        "path": str(path),
        "width": width,
        "height": height,
        "frame_index": frame_index,
        "transformation_type": transformation_type,
        "transformation_id": transformation_id,
    }


def _run(request_json: str) -> dict:
    """Execute the parse job and return a response dict."""
    from argus_img.workers.protocol import WorkerRequest

    try:
        request = WorkerRequest.model_validate_json(request_json)
    except Exception as exc:
        return {
            "scan_id": "unknown",
            "success": False,
            "error": "invalid_request: %s" % exc,
        }

    _apply_sandbox(request.deadline_epoch)

    job_dir = Path(request.job_dir).resolve()
    snapshot_path = Path(request.snapshot_path).resolve()

    if not job_dir.is_dir():
        return {"scan_id": request.scan_id, "success": False, "error": "job_dir_missing"}
    if not snapshot_path.is_file() or snapshot_path.is_symlink():
        return {"scan_id": request.scan_id, "success": False, "error": "snapshot_missing_or_symlink"}

    artifacts = []
    decode_errors = []
    warnings = []
    frames_extracted = 0
    thumbnails_extracted = 0
    transforms_generated = 0

    try:
        from PIL import Image, ImageOps
        from argus_img.core.hashing import sha256_file
        from argus_img.intake.format_policy import is_allowed_format
        from argus_img.intake.mime import detect_magic

        detected_mime, format_name = detect_magic(snapshot_path)
        if not is_allowed_format(format_name):
            raise ValueError("unsupported or active input format: %s" % format_name)
        if snapshot_path.stat().st_size > request.max_input_bytes:
            raise ValueError("input exceeds maximum byte limit")
        with Image.open(str(snapshot_path)) as img:
            width, height = img.size
            frames = getattr(img, "n_frames", 1)
            if width <= 0 or height <= 0:
                raise ValueError("image dimensions are invalid")
            if width > request.max_width or height > request.max_height:
                raise ValueError("image dimensions exceed configured limit")
            if width * height > request.max_pixels_per_frame:
                raise ValueError("image pixel count exceeds configured limit")
            if frames > request.max_frames:
                raise ValueError("image frame count exceeds configured limit")
            total_pixels = 0
            for frame_index in range(frames):
                img.seek(frame_index)
                frame_width, frame_height = img.size
                if frame_width > request.max_width or frame_height > request.max_height:
                    raise ValueError("frame dimensions exceed configured limit")
                pixels = frame_width * frame_height
                if pixels > request.max_pixels_per_frame:
                    raise ValueError("frame pixel count exceeds configured limit")
                total_pixels += pixels
                if total_pixels > request.max_total_decoded_pixels:
                    raise ValueError("total decoded pixels exceed configured limit")
            img.verify()
        with Image.open(str(snapshot_path)) as img:
            img.seek(0)
            img.load()
        if max(width / height, height / width) > 200:
            raise ValueError("image aspect ratio exceeds configured limit")
        file_size = snapshot_path.stat().st_size
        metadata_fields = {
            "width": width, "height": height, "frames": frames,
            "detected_mime": detected_mime, "format": format_name,
            "size_bytes": file_size, "sha256": sha256_file(snapshot_path),
        }
        # Reconstruct metadata-free canonical derivatives in the isolated
        # process. The control process imports only verified files from here.
        with Image.open(str(snapshot_path)) as source:
            source.seek(0)
            first_frame = ImageOps.exif_transpose(source.copy())
        if first_frame.mode not in {"RGB", "RGBA"}:
            first_frame = first_frame.convert("RGBA" if "A" in first_frame.getbands() else "RGB")
        rgb = first_frame.convert("RGB")
        background_white = Image.new("RGBA", first_frame.size, (255, 255, 255, 255))
        background_black = Image.new("RGBA", first_frame.size, (0, 0, 0, 255))
        flattened_white = Image.alpha_composite(background_white, first_frame.convert("RGBA")).convert("RGB")
        flattened_black = Image.alpha_composite(background_black, first_frame.convert("RGBA")).convert("RGB")
        transformed_pixels = 0
        for image in (first_frame, rgb, flattened_white, flattened_black):
            transformed_pixels += image.width * image.height
        if transformed_pixels > request.max_transformed_pixels:
            raise ValueError("transformed pixel budget exceeded")
        artifacts.extend([
            _record_artifact(job_dir, request.scan_id, "canonical_lossy", _encode_jpeg(rgb), rgb.width, rgb.height,
                             "canonical_lossy_jpeg", "transform:canonical-lossy"),
            _record_artifact(job_dir, request.scan_id, "canonical_lossless", _encode_png(first_frame), first_frame.width, first_frame.height,
                             "canonical_lossless_png", "transform:canonical-lossless"),
            _record_artifact(job_dir, request.scan_id, "flattened_white", _encode_png(flattened_white), flattened_white.width, flattened_white.height,
                             "alpha_flatten", "transform:flattened-white"),
            _record_artifact(job_dir, request.scan_id, "flattened_black", _encode_png(flattened_black), flattened_black.width, flattened_black.height,
                             "alpha_flatten", "transform:flattened-black"),
        ])
        if request.extract_frames and frames > 1:
            with Image.open(str(snapshot_path)) as source:
                for frame_index in range(frames):
                    source.seek(frame_index)
                    frame = ImageOps.exif_transpose(source.copy()).convert("RGBA")
                    frame_data = _encode_png(frame)
                    if len(artifacts) >= request.max_artifacts:
                        raise ValueError("artifact count limit exceeded")
                    artifacts.append(_record_artifact(
                        job_dir, request.scan_id, "frame-%03d" % frame_index,
                        frame_data, frame.width, frame.height, "frame_extract",
                        "transform:frame-%03d" % frame_index, frame_index,
                    ))
                    transformed_pixels += frame.width * frame.height
                    if transformed_pixels > request.max_transformed_pixels:
                        raise ValueError("transformed pixel budget exceeded")
        if len(artifacts) > request.max_artifacts:
            raise ValueError("artifact count limit exceeded")
        if any(record["size_bytes"] > request.max_artifact_bytes for record in artifacts):
            raise ValueError("derived artifact byte limit exceeded")
        frames_extracted = max(0, frames - 1) if request.extract_frames else 0
        transforms_generated = 4
    except Exception as exc:
        decode_errors.append("pillow_decode_error: %s" % exc)
        # Return partial result — control decides how to proceed
        return {
            "scan_id": request.scan_id,
            "success": False,
            "error": "pillow_decode_failed",
            "metadata_fields": {"format": "UNKNOWN", "detected_mime": "application/octet-stream"},
            "artifacts": artifacts,
            "decode_errors": decode_errors,
            "warnings": warnings,
            "frames_extracted": frames_extracted,
            "thumbnails_extracted": thumbnails_extracted,
            "transforms_generated": transforms_generated,
        }

    # Worker writes artifacts only to job_dir.
    # (In a full implementation each decoding step would write here.)
    # This stub records that the decode succeeded.

    return {
        "scan_id": request.scan_id,
        "success": True,
        "artifacts": artifacts,
        "metadata_fields": metadata_fields,
        "text_items": [],
        "frames_extracted": frames_extracted,
        "thumbnails_extracted": thumbnails_extracted,
        "transforms_generated": transforms_generated,
        "decode_errors": decode_errors,
        "warnings": warnings,
    }


def main() -> None:
    """Worker entry point: read request from stdin, write response to stdout."""
    try:
        request_json = sys.stdin.read()
        response = _run(request_json)
        sys.stdout.write(json.dumps(response))
        sys.stdout.flush()
    except Exception as exc:
        # Last-resort fallback: write a failure response so the control process
        # gets a structured error rather than an empty/partial stdout.
        try:
            sys.stdout.write(json.dumps({"scan_id": "unknown", "success": False, "error": str(exc)}))
            sys.stdout.flush()
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
