"""Worker error types."""
from __future__ import annotations


class WorkerError(Exception):
    """Base class for worker-related errors."""


class WorkerCrashError(WorkerError):
    """Worker process terminated abnormally."""


class WorkerTimeoutError(WorkerError):
    """Worker process exceeded the allowed wall-clock time."""


class WorkerResponseError(WorkerError):
    """Worker returned a malformed, oversized, or untrusted response."""


class WorkerPathEscapeError(WorkerResponseError):
    """Worker response referenced a path outside the allowed job directory."""


class WorkerSchemaError(WorkerResponseError):
    """Worker response failed schema validation."""
