"""Tests for SSE Authentication Middleware."""

import os
from unittest.mock import ANY, AsyncMock, patch

import pytest

from mcp_server.auth import SSEAuthMiddleware


@pytest.fixture
def middleware() -> SSEAuthMiddleware:
    mock_app = AsyncMock()
    return SSEAuthMiddleware(app=mock_app)

@pytest.mark.asyncio
async def test_auth_missing_header(middleware: SSEAuthMiddleware) -> None:
    scope = {"type": "http", "path": "/sse", "headers": []}
    receive = AsyncMock()
    send = AsyncMock()

    with patch.dict(os.environ, {"SENTINELMCP_API_KEY": "secret123"}):
        await middleware(scope, receive, send)

    send.assert_any_call({
        "type": "http.response.start",
        "status": 401,
        "headers": ANY
    })

@pytest.mark.asyncio
async def test_auth_invalid_header(middleware: SSEAuthMiddleware) -> None:
    scope = {"type": "http", "path": "/sse", "headers": [(b"x-api-key", b"badkey")]}
    receive = AsyncMock()
    send = AsyncMock()

    with patch.dict(os.environ, {"SENTINELMCP_API_KEY": "secret123"}):
        await middleware(scope, receive, send)

    send.assert_any_call({
        "type": "http.response.start",
        "status": 403,
        "headers": ANY
    })

@pytest.mark.asyncio
async def test_auth_valid_header(middleware: SSEAuthMiddleware) -> None:
    scope = {"type": "http", "path": "/sse", "headers": [(b"x-api-key", b"secret123")]}
    receive = AsyncMock()
    send = AsyncMock()

    with patch.dict(os.environ, {"SENTINELMCP_API_KEY": "secret123"}):
        await middleware(scope, receive, send)

    middleware.app.assert_called_once_with(scope, receive, send)
