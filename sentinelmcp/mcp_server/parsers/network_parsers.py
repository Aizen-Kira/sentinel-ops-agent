"""Network artifact parsers — parse tshark CLI output into typed dataclasses."""
from __future__ import annotations

import logging

from shared.models import DnsQuery, HttpRequest, NetworkConversation

logger = logging.getLogger(__name__)


def parse_conversations(raw: str) -> list[NetworkConversation]:
    """Parse tshark conv,tcp statistics output.

    Sample line:
      192.168.1.1:1234  <->  10.0.0.1:443     100     5000     120     8000    200
    """
    entries: list[NetworkConversation] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or "<->" not in line:
            continue
        try:
            left, right = line.split("<->")
            src_parts = left.strip().rsplit(":", 1)
            dst_parts = right.strip().split()
            dst_addr_port = dst_parts[0].rsplit(":", 1)
            src_ip = src_parts[0].strip()
            src_port = int(src_parts[1]) if len(src_parts) > 1 and src_parts[1].isdigit() else 0
            dst_ip = dst_addr_port[0].strip()
            dst_port = int(dst_addr_port[1]) if len(dst_addr_port) > 1 and dst_addr_port[1].isdigit() else 0
            pkts = int(dst_parts[1]) if len(dst_parts) > 1 and dst_parts[1].isdigit() else 0
            bytes_sent = int(dst_parts[2]) if len(dst_parts) > 2 and dst_parts[2].isdigit() else 0
            bytes_recv = int(dst_parts[4]) if len(dst_parts) > 4 and dst_parts[4].isdigit() else 0
            entries.append(NetworkConversation(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto="tcp",
                packets=pkts,
                bytes_sent=bytes_sent,
                bytes_recv=bytes_recv,
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed conversation line: %s (%s)", line[:80], exc)
    return entries


def parse_dns(raw: str) -> list[DnsQuery]:
    """Parse tshark DNS fields output (tab-separated)."""
    entries: list[DnsQuery] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            response_ips = [ip.strip() for ip in parts[4].split(",") if ip.strip()] if len(parts) > 4 else []
            entries.append(DnsQuery(
                src_ip=parts[1].strip(),
                query_name=parts[2].strip(),
                query_type=parts[3].strip() if len(parts) > 3 else "A",
                response_ips=response_ips,
                timestamp=parts[0].strip() or None,
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed DNS line: %s (%s)", line[:80], exc)
    return entries


def parse_http(raw: str) -> list[HttpRequest]:
    """Parse tshark HTTP fields output (tab-separated)."""
    entries: list[HttpRequest] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            entries.append(HttpRequest(
                src_ip=parts[1].strip(),
                dst_ip=parts[2].strip(),
                method=parts[3].strip(),
                host=parts[4].strip(),
                uri=parts[5].strip() if len(parts) > 5 else "/",
                user_agent=parts[6].strip() if len(parts) > 6 else "",
                timestamp=parts[0].strip() or None,
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed HTTP line: %s (%s)", line[:80], exc)
    return entries
