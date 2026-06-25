"""Parser worker entry point.

This module is executed as a separate process (via spawn, not fork) so that
hostile image parsing is isolated from the API, policy engine, and database.

The worker:
1. Applies sandbox resource limits.
2. Reads a WorkerRequest from stdin.
3. Performs Pillow/OpenCV parsing, frame/thumbnail extraction, transforms.
4. Writes a WorkerResponse to stdout.
5. Exits.

The worker has no access to the release-grant database and cannot write
outside its assigned job directory.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def _apply_sandbox(deadline_epoch: float, cpu_seconds: int = 60) -> None:
    """Apply resource limits before any parsing begins."""
    from argus_img.workers.sandbox import WorkerSandbox
    wall = max(1.0, deadline_epoch - time.time()) if deadline_epoch > 0 else 90.0
    sandbox = WorkerSandbox(cpu_seconds=min(cpu_seconds, int(wall) + 5))
    sandbox.apply()


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
        from PIL import Image, UnidentifiedImageError

        with Image.open(str(snapshot_path)) as img:
            width, height = img.size
            frames = getattr(img, "n_frames", 1)
    except Exception as exc:
        decode_errors.append("pillow_decode_error: %s" % exc)
        # Return partial result — control decides how to proceed
        return {
            "scan_id": request.scan_id,
            "success": False,
            "error": "pillow_decode_failed",
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
        "metadata_fields": {"width": width, "height": height, "frames": frames},
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
