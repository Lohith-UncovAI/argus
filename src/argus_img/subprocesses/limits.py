DEFAULT_MAX_OUTPUT_BYTES = 1_000_000
DEFAULT_TIMEOUT_SECONDS = 30


from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ToolResourceLimits:
    cpu_seconds: Optional[int] = None
    address_space_bytes: Optional[int] = None
    file_size_bytes: Optional[int] = None
    open_files: Optional[int] = 64
