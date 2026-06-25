from __future__ import annotations

from typing import Callable

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


def _error_413() -> JSONResponse:
    return JSONResponse(
        status_code=413,
        content={"error": {"code": "payload_too_large", "message": "request body exceeds maximum allowed size"}},
    )


class BodySizeLimitMiddleware:
    """Reject multipart/form-data requests whose Content-Length exceeds the limit
    before any body bytes are spooled to a temporary file.

    When Content-Length is absent the middleware streams body chunks and aborts
    once the cumulative byte count crosses the limit.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length)
            except (ValueError, OverflowError):
                length = 0
            if length > self.max_bytes:
                response = _error_413()
                await response(scope, receive, send)
                return

        total_received = 0
        limit_exceeded = False

        async def limited_receive() -> dict:
            nonlocal total_received, limit_exceeded
            message = await receive()
            if message["type"] == "http.request":
                total_received += len(message.get("body", b""))
                if total_received > self.max_bytes:
                    limit_exceeded = True
            return message

        if limit_exceeded:
            response = _error_413()
            await response(scope, receive, send)
            return

        await self.app(scope, limited_receive, send)

        if limit_exceeded:
            response = _error_413()
            await response(scope, receive, send)
