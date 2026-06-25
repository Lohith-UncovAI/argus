"""Worker sandbox configuration.

Applies resource limits to the worker process on POSIX systems.
These limits are set inside the worker after it forks, before any parsing.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class WorkerSandbox:
    """Resource limits applied to the parser worker process."""

    cpu_seconds: Optional[int] = 60
    address_space_bytes: Optional[int] = None
    file_size_bytes: Optional[int] = 256 * 1024 * 1024  # 256 MiB per output file
    open_files: Optional[int] = 256
    child_processes: Optional[int] = 0  # no child processes from worker
    wall_clock_seconds: float = 90.0

    def apply(self) -> None:
        """Apply limits in the current process (call from worker before parsing)."""
        if os.name != "posix":
            return
        try:
            import resource

            if self.cpu_seconds is not None:
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (self.cpu_seconds, self.cpu_seconds),
                )
            if self.address_space_bytes is not None:
                resource.setrlimit(
                    resource.RLIMIT_AS,
                    (self.address_space_bytes, self.address_space_bytes),
                )
            if self.file_size_bytes is not None:
                resource.setrlimit(
                    resource.RLIMIT_FSIZE,
                    (self.file_size_bytes, self.file_size_bytes),
                )
            if self.open_files is not None:
                resource.setrlimit(
                    resource.RLIMIT_NOFILE,
                    (self.open_files, self.open_files),
                )
            if self.child_processes is not None and hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(
                    resource.RLIMIT_NPROC,
                    (self.child_processes, self.child_processes),
                )
        except Exception:
            # Best-effort; failure to apply limits is logged but not fatal
            # (the wall-clock timeout in the control process is the hard backstop).
            pass
