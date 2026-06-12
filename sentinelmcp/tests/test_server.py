"""Tests for mcp_server/server.py — dispatch_tool routing."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcp_server.server import dispatch_tool


class TestDispatchTool:
    def test_known_tool_dispatched(self) -> None:
        mock_fn = MagicMock(return_value=[{"result": "ok"}])
        with patch.dict("mcp_server.server._TOOL_REGISTRY", {"mock_tool": mock_fn}):
            result = dispatch_tool("mock_tool", {"param": "value"})
        mock_fn.assert_called_once_with(param="value")
        assert result == [{"result": "ok"}]

    def test_unknown_tool_raises_key_error(self) -> None:
        with pytest.raises(KeyError, match="Unknown tool"):
            dispatch_tool("nonexistent_tool", {})

    def test_all_16_tools_registered(self) -> None:
        from mcp_server.server import _TOOL_REGISTRY
        expected = {
            "mftdump", "pecmd", "amcacheparser", "reglookup", "fls", "evtxdump",
            "vol3_pslist", "vol3_netscan", "vol3_malfind", "vol3_cmdline",
            "tshark_conversations", "tshark_dns", "tshark_http",
            "correlate_disk_memory", "timeline_gaps",
        }
        assert expected.issubset(set(_TOOL_REGISTRY.keys()))
