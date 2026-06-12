"""Tests for mcp_server/parsers/network_parsers.py."""
from __future__ import annotations

from mcp_server.parsers.network_parsers import parse_conversations, parse_dns, parse_http


class TestParseConversations:
    def test_valid_line(self) -> None:
        raw = "192.168.1.1:1234  <->  10.0.0.1:443     100     5000     120     8000    200\n"
        entries = parse_conversations(raw)
        assert len(entries) == 1
        assert entries[0].src_ip == "192.168.1.1"
        assert entries[0].dst_port == 443

    def test_header_skipped(self) -> None:
        raw = "===========================================================\n192.168.1.1:80 <-> 10.0.0.1:9999 10 100 10 100 20\n"
        entries = parse_conversations(raw)
        assert len(entries) == 1

    def test_empty_raw(self) -> None:
        assert parse_conversations("") == []


class TestParseDns:
    def test_valid_line(self) -> None:
        raw = "1672531200.0\t192.168.1.1\tevil.com\tA\t10.0.0.1\n"
        entries = parse_dns(raw)
        assert len(entries) == 1
        assert entries[0].query_name == "evil.com"
        assert entries[0].response_ips == ["10.0.0.1"]

    def test_multiple_response_ips(self) -> None:
        raw = "1672531200.0\t1.1.1.1\tmulti.com\tA\t10.0.0.1, 10.0.0.2\n"
        entries = parse_dns(raw)
        assert len(entries[0].response_ips) == 2

    def test_empty_raw(self) -> None:
        assert parse_dns("") == []


class TestParseHttp:
    def test_valid_line(self) -> None:
        raw = "1672531200.0\t192.168.1.1\t10.0.0.1\tGET\tevil.com\t/payload.exe\tpython/3.11\n"
        entries = parse_http(raw)
        assert len(entries) == 1
        assert entries[0].method == "GET"
        assert entries[0].host == "evil.com"
        assert entries[0].user_agent == "python/3.11"

    def test_empty_raw(self) -> None:
        assert parse_http("") == []

    def test_short_line_skipped(self) -> None:
        raw = "1672531200.0\t192.168.1.1\n"
        entries = parse_http(raw)
        assert entries == []
