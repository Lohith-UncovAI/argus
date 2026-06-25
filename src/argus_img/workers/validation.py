"""Control-side validation of worker responses.

The control process must validate every field of the worker response before
acting on it.  This module provides the validation logic used by the launcher.
"""
from __future__ import annotations

import os
from pathlib import Path

from argus_img.workers.errors import (
    WorkerPathEscapeError,
    WorkerResponseError,
    WorkerSchemaError,
)
from argus_img.workers.protocol import MAX_RESPONSE_BYTES, WorkerResponse, validate_response_paths


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
    seen_ids = set()
    for record in response.artifacts:
        if record.artifact_id in seen_ids:
            raise WorkerResponseError(
                "duplicate artifact_id in worker response: %s" % record.artifact_id
            )
        seen_ids.add(record.artifact_id)

    return response
