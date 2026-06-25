"""Typed request/response protocol between control process and parser worker.

All inter-process communication uses JSON-serialised Pydantic models.  The
control process validates every field before acting on the response.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class WorkerRequest(BaseModel):
    """Serialised instruction sent to the parser worker via stdin."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    job_dir: str
    snapshot_path: str
    mode: str = "fast"
    use_profile: str = "AGENT_WITH_TOOLS"
    max_pixels_per_frame: int = 50_000_000
    max_total_decoded_pixels: int = 150_000_000
    max_transformed_pixels: int = 300_000_000
    max_frames: int = 30
    max_artifacts: int = 200
    max_artifact_bytes: int = 250_000_000
    max_text_bytes: int = 2_000_000
    deadline_epoch: float = 0.0


class ArtifactRecord(BaseModel):
    """A single artifact produced by the worker."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    sha256: str
    role: str
    media_type: str
    size_bytes: int
    path: str
    width: Optional[int] = None
    height: Optional[int] = None
    frame_index: Optional[int] = None
    transformation_type: Optional[str] = None
    transformation_id: Optional[str] = None


class WorkerResponse(BaseModel):
    """Serialised results returned by the parser worker via stdout."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    success: bool
    error: Optional[str] = None
    artifacts: List[ArtifactRecord] = Field(default_factory=list)
    # Structured metadata extracted in-worker; control validates before use
    metadata_fields: Dict[str, Any] = Field(default_factory=dict)
    # OCR and QR text items (raw; re-validated by control before policy)
    text_items: List[Dict[str, Any]] = Field(default_factory=list)
    frames_extracted: int = 0
    thumbnails_extracted: int = 0
    transforms_generated: int = 0
    decode_errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB ceiling on IPC response


def validate_response_paths(response: WorkerResponse, job_dir: Path) -> None:
    """Raise WorkerPathEscapeError if any artifact path escapes job_dir."""
    from argus_img.workers.errors import WorkerPathEscapeError

    resolved_job = job_dir.resolve()
    for record in response.artifacts:
        try:
            artifact_path = Path(record.path).resolve()
        except Exception as exc:
            raise WorkerPathEscapeError("invalid artifact path: %s" % exc) from exc
        if artifact_path.is_symlink():
            raise WorkerPathEscapeError("artifact path is a symlink: %s" % record.path)
        if not str(artifact_path).startswith(str(resolved_job) + "/") and artifact_path != resolved_job:
            raise WorkerPathEscapeError(
                "artifact path escapes job directory: %s" % record.path
            )
