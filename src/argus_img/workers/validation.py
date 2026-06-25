"""Control-side validation of worker responses.

The control process must independently verify every worker artifact before
acting on it.  This module validates:
  - Response schema and size ceiling
  - scan_id match
  - Path containment and no-symlink
  - Existence and regular-file status
  - File size matches claimed size_bytes
  - SHA-256 matches claimed sha256
  - MIME type plausibility for the claimed role
  - Dimensions match claimed width/height (Pillow re-decode)
  - Allowed roles
  - No duplicate artifact IDs
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Optional, Set

from argus_img.workers.errors import (
    WorkerPathEscapeError,
    WorkerResponseError,
    WorkerSchemaError,
)
from argus_img.workers.protocol import MAX_RESPONSE_BYTES, ArtifactRecord, WorkerResponse, validate_response_paths

# Roles that the worker is permitted to produce.
ALLOWED_WORKER_ROLES: Set[str] = {
    "canonical_lossless",
    "canonical_lossy",
    "flattened_white",
    "flattened_black",
    "frame",
    "thumbnail",
    "transform",
    "derived",
}

# MIME prefixes that are valid image types
_IMAGE_MIME_PREFIXES = ("image/",)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _verify_artifact(record: ArtifactRecord, job_dir: Path) -> None:
    """Independently verify a single artifact record against the actual file.

    Raises WorkerResponseError on any mismatch.
    """
    resolved_job = job_dir.resolve()

    # Path containment and no-symlink already checked by validate_response_paths,
    # but we re-check here because this is the security boundary.
    try:
        artifact_path = Path(record.path).resolve()
    except Exception as exc:
        raise WorkerResponseError("invalid artifact path: %s" % exc) from exc

    if artifact_path.is_symlink():
        raise WorkerPathEscapeError("artifact path is a symlink: %s" % record.path)

    if not str(artifact_path).startswith(str(resolved_job) + os.sep) and artifact_path != resolved_job:
        raise WorkerPathEscapeError("artifact path escapes job directory: %s" % record.path)

    # Existence check
    if not artifact_path.exists():
        raise WorkerResponseError("artifact file does not exist: %s" % record.path)

    # Regular-file check (no device files, sockets, FIFOs)
    try:
        st = artifact_path.stat()
    except OSError as exc:
        raise WorkerResponseError("cannot stat artifact: %s" % exc) from exc

    if not stat.S_ISREG(st.st_mode):
        raise WorkerResponseError("artifact is not a regular file: %s" % record.path)

    # Size check
    actual_size = st.st_size
    if actual_size != record.size_bytes:
        raise WorkerResponseError(
            "artifact size mismatch for %s: claimed %d, actual %d"
            % (record.artifact_id, record.size_bytes, actual_size)
        )

    # SHA-256 verification
    actual_hash = _sha256_file(artifact_path)
    claimed = record.sha256 if record.sha256.startswith("sha256:") else "sha256:" + record.sha256
    if actual_hash != claimed:
        raise WorkerResponseError(
            "artifact SHA-256 mismatch for %s: claimed %s, actual %s"
            % (record.artifact_id, claimed, actual_hash)
        )

    # MIME type plausibility
    if not any(record.media_type.startswith(p) for p in _IMAGE_MIME_PREFIXES):
        raise WorkerResponseError(
            "artifact media_type not an image type for %s: %s"
            % (record.artifact_id, record.media_type)
        )

    # Allowed role check
    role_base = record.role.split("-")[0] if "-" in record.role else record.role
    if role_base not in ALLOWED_WORKER_ROLES and record.role not in ALLOWED_WORKER_ROLES:
        raise WorkerResponseError(
            "artifact role not permitted from worker: %s (artifact %s)"
            % (record.role, record.artifact_id)
        )

    # Dimension verification via Pillow (lightweight — no decoding side-effects)
    if record.width is not None or record.height is not None:
        _verify_dimensions(artifact_path, record)


def _verify_dimensions(artifact_path: Path, record: ArtifactRecord) -> None:
    """Re-open the artifact with Pillow to verify claimed dimensions."""
    try:
        from PIL import Image  # type: ignore[import-untyped]
        with Image.open(str(artifact_path)) as img:
            actual_w, actual_h = img.size
    except Exception:
        # If Pillow cannot read it, that's a problem — the file should be a valid image.
        raise WorkerResponseError(
            "artifact cannot be decoded by Pillow for dimension check: %s" % artifact_path
        )

    if record.width is not None and actual_w != record.width:
        raise WorkerResponseError(
            "artifact width mismatch for %s: claimed %d, actual %d"
            % (record.artifact_id, record.width, actual_w)
        )
    if record.height is not None and actual_h != record.height:
        raise WorkerResponseError(
            "artifact height mismatch for %s: claimed %d, actual %d"
            % (record.artifact_id, record.height, actual_h)
        )


def parse_and_validate_response(
    raw: bytes,
    scan_id: str,
    job_dir: Path,
) -> WorkerResponse:
    """Parse JSON bytes from worker stdout and validate all fields.

    Raises WorkerResponseError (or a subclass) on any validation failure.
    The control process must catch these and not release artifacts.
    """
    if len(raw) > MAX_RESPONSE_BYTES:
        raise WorkerResponseError(
            "worker response exceeds maximum allowed size (%d > %d)"
            % (len(raw), MAX_RESPONSE_BYTES)
        )
    try:
        response = WorkerResponse.model_validate_json(raw)
    except Exception as exc:
        raise WorkerSchemaError("worker response schema validation failed: %s" % exc) from exc

    if response.scan_id != scan_id:
        raise WorkerResponseError(
            "worker response scan_id mismatch: expected %r got %r"
            % (scan_id, response.scan_id)
        )

    validate_response_paths(response, job_dir)

    # Check for duplicate artifact IDs
    seen_ids: set[str] = set()
    for record in response.artifacts:
        if record.artifact_id in seen_ids:
            raise WorkerResponseError(
                "duplicate artifact_id in worker response: %s" % record.artifact_id
            )
        seen_ids.add(record.artifact_id)

    # Full independent artifact verification
    for record in response.artifacts:
        _verify_artifact(record, job_dir)

    return response
