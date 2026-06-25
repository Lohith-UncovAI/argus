from __future__ import annotations

import time

from argus_img.core.exceptions import ResourceLimitExceeded
from argus_img.core.limits import Limits


class ResourceBudget:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.deadline = time.monotonic() + limits.full_scan_timeout_seconds
        self.total_decoded_pixels = 0
        self.transformed_pixels = 0
        self.artifact_count = 0
        self.artifact_bytes = 0
        self.text_bytes = 0

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise ResourceLimitExceeded("full scan timeout exceeded")

    def consume_decoded_pixels(self, pixels: int) -> None:
        self.check_time()
        self.total_decoded_pixels += pixels
        if self.total_decoded_pixels > self.limits.max_total_decoded_pixels:
            raise ResourceLimitExceeded("decoded pixel budget exceeded")

    def consume_transformed_pixels(self, pixels: int) -> None:
        self.check_time()
        self.transformed_pixels += pixels
        if self.transformed_pixels > self.limits.max_transformed_pixels:
            raise ResourceLimitExceeded("transformed pixel budget exceeded")

    def consume_artifact(self, size_bytes: int) -> None:
        self.check_time()
        self.artifact_count += 1
        self.artifact_bytes += size_bytes
        if self.artifact_count > self.limits.max_artifacts:
            raise ResourceLimitExceeded("artifact count budget exceeded")
        if self.artifact_bytes > self.limits.max_artifact_bytes:
            raise ResourceLimitExceeded("artifact byte budget exceeded")

    def consume_text(self, text: str) -> None:
        self.check_time()
        self.text_bytes += len(text.encode("utf-8", errors="replace"))
        if self.text_bytes > self.limits.max_text_bytes:
            raise ResourceLimitExceeded("text byte budget exceeded")
