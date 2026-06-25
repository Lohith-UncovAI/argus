from __future__ import annotations

import time
from typing import Callable, Optional

from argus_img.core.exceptions import ResourceLimitExceeded
from argus_img.core.limits import Limits


class BudgetReservation:
    """A reserved slice of a resource budget.

    Usage::

        reservation = budget.reserve_transformed_pixels(predicted_pixels)
        try:
            do_expensive_operation()
            reservation.commit(actual_pixels)
        except Exception:
            reservation.rollback()
            raise
    """

    def __init__(
        self,
        reserved: int,
        commit_fn: Callable[[int, int], None],
        rollback_fn: Callable[[int], None],
    ) -> None:
        self._reserved = reserved
        self._commit_fn = commit_fn
        self._rollback_fn = rollback_fn
        self._done = False

    def commit(self, actual: Optional[int] = None) -> None:
        """Confirm the operation completed; reconcile actual vs reserved usage."""
        if self._done:
            return
        self._done = True
        self._commit_fn(self._reserved, actual if actual is not None else self._reserved)

    def rollback(self) -> None:
        """Release the reservation without consuming budget."""
        if self._done:
            return
        self._done = True
        self._rollback_fn(self._reserved)

    def __enter__(self) -> "BudgetReservation":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


class ResourceBudget:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.deadline = time.monotonic() + limits.full_scan_timeout_seconds
        self.total_decoded_pixels = 0
        self.transformed_pixels = 0
        self.artifact_count = 0
        self.artifact_bytes = 0
        self.text_bytes = 0
        self.extracted_object_count = 0
        self.extracted_object_bytes = 0
        self.ipc_response_bytes = 0
        # Pending reservations: tracks how much is reserved but not committed
        self._reserved_transformed_pixels = 0
        self._reserved_decoded_pixels = 0
        self._reserved_artifact_count = 0
        self._reserved_artifact_bytes = 0

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

    # ------------------------------------------------------------------
    # Reservation API: reserve before allocation, commit/rollback after.
    # ------------------------------------------------------------------

    def reserve_transformed_pixels(self, predicted_pixels: int) -> BudgetReservation:
        """Reserve transformed pixel budget before performing an image operation.

        If the reservation would exceed the limit, raises ResourceLimitExceeded
        immediately — before the expensive operation is attempted.
        """
        self.check_time()
        if (
            self.transformed_pixels
            + self._reserved_transformed_pixels
            + predicted_pixels
            > self.limits.max_transformed_pixels
        ):
            raise ResourceLimitExceeded(
                "transformed pixel budget would be exceeded by this operation"
            )
        self._reserved_transformed_pixels += predicted_pixels

        def _commit(reserved: int, actual: int) -> None:
            self._reserved_transformed_pixels = max(
                0, self._reserved_transformed_pixels - reserved
            )
            self.consume_transformed_pixels(actual)

        def _rollback(reserved: int) -> None:
            self._reserved_transformed_pixels = max(
                0, self._reserved_transformed_pixels - reserved
            )

        return BudgetReservation(predicted_pixels, _commit, _rollback)

    def reserve_decoded_pixels(self, predicted_pixels: int) -> BudgetReservation:
        """Reserve decoded pixel budget before decoding a frame."""
        self.check_time()
        if (
            self.total_decoded_pixels
            + self._reserved_decoded_pixels
            + predicted_pixels
            > self.limits.max_total_decoded_pixels
        ):
            raise ResourceLimitExceeded(
                "decoded pixel budget would be exceeded by this operation"
            )
        self._reserved_decoded_pixels += predicted_pixels

        def _commit(reserved: int, actual: int) -> None:
            self._reserved_decoded_pixels = max(
                0, self._reserved_decoded_pixels - reserved
            )
            self.consume_decoded_pixels(actual)

        def _rollback(reserved: int) -> None:
            self._reserved_decoded_pixels = max(
                0, self._reserved_decoded_pixels - reserved
            )

        return BudgetReservation(predicted_pixels, _commit, _rollback)

    def reserve_artifact(self, predicted_bytes: int) -> BudgetReservation:
        """Reserve artifact budget before writing an artifact."""
        self.check_time()
        if (
            self.artifact_count + self._reserved_artifact_count + 1
            > self.limits.max_artifacts
        ):
            raise ResourceLimitExceeded(
                "artifact count budget would be exceeded by this operation"
            )
        if (
            self.artifact_bytes
            + self._reserved_artifact_bytes
            + predicted_bytes
            > self.limits.max_artifact_bytes
        ):
            raise ResourceLimitExceeded(
                "artifact byte budget would be exceeded by this operation"
            )
        self._reserved_artifact_count += 1
        self._reserved_artifact_bytes += predicted_bytes

        def _commit(reserved: int, actual: int) -> None:
            self._reserved_artifact_count = max(0, self._reserved_artifact_count - 1)
            self._reserved_artifact_bytes = max(
                0, self._reserved_artifact_bytes - reserved
            )
            self.consume_artifact(actual)

        def _rollback(reserved: int) -> None:
            self._reserved_artifact_count = max(0, self._reserved_artifact_count - 1)
            self._reserved_artifact_bytes = max(
                0, self._reserved_artifact_bytes - reserved
            )

        return BudgetReservation(predicted_bytes, _commit, _rollback)
