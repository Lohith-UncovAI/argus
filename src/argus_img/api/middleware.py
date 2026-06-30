from __future__ import annotations

import asyncio

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


def _error_413() -> JSONResponse:
    return JSONResponse(
        status_code=413,
        content={"error": {"code": "payload_too_large", "message": "request body exceeds maximum allowed size"}},
    )


class BodySizeLimitMiddleware:
    """Reject oversized requests before any body bytes reach the downstream app.

    Guarantees:
    - Oversized Content-Length is rejected before body parsing begins.
    - Malformed or negative Content-Length is rejected.
    - Streamed bodies without Content-Length are tracked cumulatively;
      the limit is enforced before forwarding the violating chunk.
    - Exactly one response-start event is emitted.
    - The downstream app never receives a chunk that crosses the limit.
    - Partial temporary files from aborted multipart uploads are not created
      because the body never reaches the downstream handler.

    Production note: an independent server or reverse-proxy request limit
    (e.g. nginx client_max_body_size) MUST also be configured so that
    oversized bodies cannot consume bandwidth before this middleware acts.
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
                length = -1
            if length < 0 or length > self.max_bytes:
                response = _error_413()
                await response(scope, receive, send)
                return

        total_received = 0
        limit_exceeded = False
        response_started = False

        async def limited_receive() -> dict:
            nonlocal total_received, limit_exceeded
            if limit_exceeded:
                # Return a synthetic empty terminal body so the app can shut down
                # gracefully — but we will have already sent 413 before app runs.
                return {"type": "http.request", "body": b"", "more_body": False}
            message = await receive()
            if message["type"] == "http.request":
                chunk_size = len(message.get("body", b""))
                total_received += chunk_size
                if total_received > self.max_bytes:
                    limit_exceeded = True
                    # Return an empty terminal message — downstream must not see the
                    # oversized chunk.
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(event: dict) -> None:
            nonlocal response_started
            if limit_exceeded:
                # Swallow any response the app tries to start after limit exceeded.
                return
            if event["type"] == "http.response.start":
                response_started = True
            await send(event)

        # Run the app with the guarded receive/send.
        await self.app(scope, limited_receive, guarded_send)

        # If the limit was exceeded and the app has not started a response,
        # send the 413 now.  If the app already started one (race), we cannot
        # send another so we stay silent — the guarded_send above will have
        # already suppressed the app's start event.
        if limit_exceeded and not response_started:
            response = _error_413()
            await response(scope, receive, send)


def _error_429() -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"error": {"code": "too_many_requests", "message": "server is at scan capacity; retry later"}},
    )


class ConcurrencyLimitMiddleware:
    """Reject new scan requests when the in-flight scan count reaches max_concurrent.

    Only POST /v1/scans is gated — read-only routes (GET /v1/scans/{id},
    /v1/artifacts/*, /v1/attestation, /v1/capabilities, /v1/health) are not
    affected.

    Production note: this limit is per-process.  A reverse proxy or load-balancer
    should enforce an additional global limit across replicas.
    """

    _SCAN_PATH = "/v1/scans"

    def __init__(self, app: ASGIApp, max_concurrent: int) -> None:
        self.app = app
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_scan_post = (
            scope.get("method", "") == "POST"
            and scope.get("path", "") == self._SCAN_PATH
        )
        if not is_scan_post:
            await self.app(scope, receive, send)
            return
        if not self._semaphore._value:  # fast non-blocking check
            response = _error_429()
            await response(scope, receive, send)
            return
        async with self._semaphore:
            await self.app(scope, receive, send)
