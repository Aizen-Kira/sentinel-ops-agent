"""FastMCP server — registers all 16 tools and provides dispatch_tool().

Tools are imported from the four tool modules. dispatch_tool() is the
internal routing function called by agent.loop.call_mcp_tools().
"""
from __future__ import annotations

import logging
from typing import Any

try:
    from fastmcp import FastMCP
    _mcp: FastMCP | None = FastMCP("sentinelmcp")
except ImportError:  # allow import without fastmcp installed (test environments)
    _mcp = None

from mcp_server.auth import SSEAuthMiddleware
from mcp_server.tools import cloud, container, correlate, disk, memory, network, timeline, yara

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool registry — maps tool name → callable
# ---------------------------------------------------------------------------

_TOOL_REGISTRY: dict[str, Any] = {
    # Disk tools
    "mftdump": disk.mftdump,
    "pecmd": disk.pecmd,
    "amcacheparser": disk.amcacheparser,
    "shimcache": disk.shimcache,
    "reglookup": disk.reglookup,
    "fls": disk.fls,
    "evtxdump": disk.evtxdump,
    # Memory tools
    "vol3_pslist": memory.vol3_pslist,
    "vol3_netscan": memory.vol3_netscan,
    "vol3_malfind": memory.vol3_malfind,
    "vol3_cmdline": memory.vol3_cmdline,
    # Network tools
    "tshark_conversations": network.tshark_conversations,
    "tshark_dns": network.tshark_dns,
    "tshark_http": network.tshark_http,
    # Correlation tools
    "correlate_disk_memory": correlate.correlate_disk_memory,
    "timeline_gaps": correlate.timeline_gaps,
    "build_super_timeline": timeline.build_super_timeline,
    "yara_scan": yara.yara_scan,
    # V1.1.0 — Cloud Forensics
    "parse_cloudtrail": cloud.parse_cloudtrail,
    "parse_iam_events": cloud.parse_iam_events,
    "parse_guardduty": cloud.parse_guardduty,
    "parse_entra_signin_logs": cloud.parse_entra_signin_logs,
    "parse_azure_activity_logs": cloud.parse_azure_activity_logs,
    "parse_gcp_audit_logs": cloud.parse_gcp_audit_logs,
    # V1.1.0 — Container Forensics
    "parse_docker_logs": container.parse_docker_logs,
    "parse_container_metadata": container.parse_container_metadata,
    "parse_image_history": container.parse_image_history,
    "parse_k8s_audit_logs": container.parse_k8s_audit_logs,
}


def dispatch_tool(tool_name: str, params: dict[str, Any]) -> list[dict[str, Any]] | dict[str, Any]:
    """Route a tool call by name.  Raises KeyError for unknown tools."""
    fn = _TOOL_REGISTRY.get(tool_name)
    if fn is None:
        raise KeyError(f"Unknown tool: '{tool_name}'. Available: {sorted(_TOOL_REGISTRY)}")
    logger.debug("Dispatching tool: %s params=%s", tool_name, list(params.keys()))
    return fn(**params)  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# FastMCP tool registrations (used when running the MCP server standalone)
# ---------------------------------------------------------------------------

if _mcp is not None:
    @_mcp.tool()
    def mftdump(image_path: str) -> list[dict[str, Any]]:
        return disk.mftdump(image_path=image_path)

    @_mcp.tool()
    def pecmd(image_path: str) -> list[dict[str, Any]]:
        return disk.pecmd(image_path=image_path)

    @_mcp.tool()
    def amcacheparser(image_path: str) -> list[dict[str, Any]]:
        return disk.amcacheparser(image_path=image_path)

    @_mcp.tool()
    def shimcache(image_path: str) -> list[dict[str, Any]]:
        return disk.shimcache(image_path=image_path)

    @_mcp.tool()
    def reglookup(image_path: str, key: str = "") -> list[dict[str, Any]]:
        return disk.reglookup(image_path=image_path, key=key)

    @_mcp.tool()
    def fls(image_path: str, directory: str = "/") -> list[dict[str, Any]]:
        return disk.fls(image_path=image_path, directory=directory)

    @_mcp.tool()
    def evtxdump(image_path: str, channel: str = "Security") -> list[dict[str, Any]]:
        return disk.evtxdump(image_path=image_path, channel=channel)

    @_mcp.tool()
    def vol3_pslist(memory_path: str) -> list[dict[str, Any]]:
        return memory.vol3_pslist(memory_path=memory_path)

    @_mcp.tool()
    def vol3_netscan(memory_path: str) -> list[dict[str, Any]]:
        return memory.vol3_netscan(memory_path=memory_path)

    @_mcp.tool()
    def vol3_malfind(memory_path: str) -> list[dict[str, Any]]:
        return memory.vol3_malfind(memory_path=memory_path)

    @_mcp.tool()
    def vol3_cmdline(memory_path: str) -> list[dict[str, Any]]:
        return memory.vol3_cmdline(memory_path=memory_path)

    @_mcp.tool()
    def tshark_conversations(pcap_path: str) -> list[dict[str, Any]]:
        return network.tshark_conversations(pcap_path=pcap_path)

    @_mcp.tool()
    def tshark_dns(pcap_path: str) -> list[dict[str, Any]]:
        return network.tshark_dns(pcap_path=pcap_path)

    @_mcp.tool()
    def tshark_http(pcap_path: str) -> list[dict[str, Any]]:
        return network.tshark_http(pcap_path=pcap_path)

    @_mcp.tool()
    def correlate_disk_memory(image_path: str, memory_path: str) -> list[dict[str, Any]]:
        return correlate.correlate_disk_memory(image_path=image_path, memory_path=memory_path)

    @_mcp.tool()
    def timeline_gaps(image_path: str, memory_path: str = "", pcap_path: str = "") -> list[dict[str, Any]]:
        return correlate.timeline_gaps(image_path=image_path, memory_path=memory_path, pcap_path=pcap_path)

    @_mcp.tool()
    def build_super_timeline(
        disk_events: list[dict[str, Any]] | None = None,
        memory_events: list[dict[str, Any]] | None = None,
        network_events: list[dict[str, Any]] | None = None,
        evtx_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return timeline.build_super_timeline(
            disk_events=disk_events,
            memory_events=memory_events,
            network_events=network_events,
            evtx_events=evtx_events
        )

    @_mcp.tool()
    def yara_scan(target_path: str, rules_path: str) -> list[dict[str, Any]]:
        return yara.yara_scan(target_path=target_path, rules_path=rules_path)


def run_server() -> None:
    """Start the MCP server (SSE mode)."""
    if _mcp is None:
        raise RuntimeError("fastmcp is not installed. Install it with: pip install fastmcp")

    # Wrap the underlying ASGI app with our authentication middleware
    if hasattr(_mcp, "_app"):
        _mcp._app = SSEAuthMiddleware(_mcp._app)
    elif hasattr(_mcp, "app"):
        _mcp.app = SSEAuthMiddleware(_mcp.app)

    _mcp.run()


if __name__ == "__main__":
    run_server()
