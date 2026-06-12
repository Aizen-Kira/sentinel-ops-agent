"""Tests for mcp_server/parsers/memory_parsers.py."""
from __future__ import annotations

from mcp_server.parsers.memory_parsers import (
    parse_cmdline,
    parse_malfind,
    parse_netscan,
    parse_pslist,
)


class TestParsePslist:
    def test_valid_line(self) -> None:
        raw = "4\t0\tSystem\t2023-01-01 00:00:00\t\n1234\t4\tmimikatz.exe\t2023-01-01 01:00:00\t\n"
        entries = parse_pslist(raw)
        assert any(e.name == "mimikatz.exe" for e in entries)

    def test_header_skipped(self) -> None:
        raw = "PID\tPPID\tImageFileName\tCreateTime\tExitTime\n4\t0\tSystem\t\t\n"
        entries = parse_pslist(raw)
        assert len(entries) == 1

    def test_empty_raw(self) -> None:
        assert parse_pslist("") == []

    def test_malformed_line_skipped(self) -> None:
        raw = "bad\n4\t0\tSystem\t\t\n"
        entries = parse_pslist(raw)
        assert len(entries) == 1


class TestParseNetscan:
    def test_valid_line(self) -> None:
        raw = "0xffff\tTCPv4\t192.168.1.1\t445\t10.0.0.1\t5555\tESTABLISHED\t1234\n"
        entries = parse_netscan(raw)
        assert len(entries) == 1
        assert entries[0].proto == "TCPv4"
        assert entries[0].remote_addr == "10.0.0.1"

    def test_header_skipped(self) -> None:
        raw = "Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\n"
        entries = parse_netscan(raw)
        assert entries == []


class TestParseMalfind:
    def test_empty_raw(self) -> None:
        assert parse_malfind("") == []

    def test_block_parsed(self) -> None:
        raw = (
            "Process: svchost.exe Pid: 1234\n"
            "Start: 0x400000 End: 0x410000 Tag: VadS\n"
            "0x400000  4d 5a 90 00  MZ..\n"
            "0x400000 JMP 0x401000\n"
        )
        entries = parse_malfind(raw)
        assert len(entries) == 1
        assert entries[0].pid == 1234
        assert entries[0].process_name == "svchost.exe"


class TestParseCmdline:
    def test_valid_line(self) -> None:
        raw = "1234\tmimikatz.exe\tsekurlsa::logonpasswords\n"
        entries = parse_cmdline(raw)
        assert len(entries) == 1
        assert entries[0].cmd == "sekurlsa::logonpasswords"

    def test_empty_raw(self) -> None:
        assert parse_cmdline("") == []
