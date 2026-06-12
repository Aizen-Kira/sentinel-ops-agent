"""Network forensics tools — BUG-001: all paths validated via validate_path().

Wraps tshark CLI. No shell=True. All subprocess args are lists.
"""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from mcp_server.parsers.network_parsers import (
    parse_conversations,
    parse_dns,
    parse_http,
)
from shared.security import validate_path

logger = logging.getLogger(__name__)

_PCAP_ROOTS: list[Path] = [Path(os.environ.get("SENTINELMCP_PCAP_ROOT", "/evidence"))]


def set_pcap_roots(roots: list[Path]) -> None:
    global _PCAP_ROOTS
    _PCAP_ROOTS = roots


def _validate(pcap_path: str) -> Path:
    return validate_path(pcap_path, _PCAP_ROOTS)


def _tshark(pcap: Path, args: list[str]) -> str:
    cmd = ["tshark", "-r", str(pcap)] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, shell=False)
    if result.returncode != 0:
        logger.warning("tshark exited %d: %s", result.returncode, result.stderr[:200])
    return result.stdout


def tshark_conversations(pcap_path: str) -> list[dict[str, Any]]:
    """Extract TCP/UDP conversation statistics."""
    validated = _validate(pcap_path)
    raw = _tshark(validated, ["-q", "-z", "conv,tcp"])
    entries = parse_conversations(raw)
    return [
        {
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "src_port": e.src_port,
            "dst_port": e.dst_port,
            "proto": e.proto,
            "bytes_sent": e.bytes_sent,
            "bytes_recv": e.bytes_recv,
            "packets": e.packets,
            "start_time": e.start_time,
            "end_time": e.end_time,
        }
        for e in entries
    ]


def tshark_dns(pcap_path: str) -> list[dict[str, Any]]:
    """Extract DNS queries and responses."""
    validated = _validate(pcap_path)
    raw = _tshark(
        validated,
        ["-Y", "dns", "-T", "fields",
         "-e", "frame.time_epoch",
         "-e", "ip.src",
         "-e", "dns.qry.name",
         "-e", "dns.qry.type",
         "-e", "dns.a"],
    )
    entries = parse_dns(raw)
    return [
        {
            "src_ip": e.src_ip,
            "query_name": e.query_name,
            "query_type": e.query_type,
            "response_ips": e.response_ips,
            "timestamp": e.timestamp,
        }
        for e in entries
    ]


def tshark_http(pcap_path: str) -> list[dict[str, Any]]:
    """Extract HTTP request metadata."""
    validated = _validate(pcap_path)
    raw = _tshark(
        validated,
        ["-Y", "http.request", "-T", "fields",
         "-e", "frame.time_epoch",
         "-e", "ip.src",
         "-e", "ip.dst",
         "-e", "http.request.method",
         "-e", "http.host",
         "-e", "http.request.uri",
         "-e", "http.user_agent"],
    )
    entries = parse_http(raw)
    return [
        {
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "method": e.method,
            "host": e.host,
            "uri": e.uri,
            "user_agent": e.user_agent,
            "timestamp": e.timestamp,
        }
        for e in entries
    ]
