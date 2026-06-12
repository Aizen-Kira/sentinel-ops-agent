"""MCP SSE Authentication Middleware (FEATURE-013)."""

import logging
import os
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)

class SSEAuthMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Awaitable[Any]], send: Callable[..., Awaitable[Any]]) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Basic routing check (assuming FastMCP uses /sse or similar)
        # We'll enforce it globally for simplicity or specifically for SSE.
        path = scope.get("path", "")

        # Enforce on all HTTP endpoints (or just /sse)
        headers = dict(scope.get("headers", []))

        # headers are bytes in ASGI
        api_key_bytes = headers.get(b"x-api-key", b"")
        api_key = api_key_bytes.decode("utf-8") if api_key_bytes else None

        expected_key = os.environ.get("SENTINELMCP_API_KEY")

        if not expected_key:
            # If no key is configured on server, deny by default to fail closed
            await self._respond(send, 401, "Unauthorized: Server missing SENTINELMCP_API_KEY configuration")
            return

        if not api_key:
            await self._respond(send, 401, "Unauthorized: Missing X-API-Key header")
            return

        if api_key != expected_key:
            await self._respond(send, 403, "Forbidden: Invalid X-API-Key")
            return

        # Valid key, continue normally
        await self.app(scope, receive, send)

    async def _respond(self, send: Callable[..., Awaitable[Any]], status: int, message: str) -> None:
        response_body = f'{{"error": "{message}"}}'.encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(response_body)).encode("utf-8")),
            ]
        })
        await send({
            "type": "http.response.body",
            "body": response_body,
        })
