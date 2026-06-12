"""Tests for mcp_server/parsers/disk_parsers.py."""
from __future__ import annotations

from mcp_server.parsers.disk_parsers import (
    parse_amcache,
    parse_evtx,
    parse_fls,
    parse_mft,
    parse_pecmd,
    parse_reglookup,
)


class TestParseMft:
    def test_valid_line(self) -> None:
        raw = "1|C:\\Windows\\notepad.exe|12345|2023-01-01|2023-01-02|A\n"
        entries = parse_mft(raw)
        assert len(entries) == 1
        assert entries[0].path == "C:\\Windows\\notepad.exe"
        assert entries[0].size == 12345
        assert not entries[0].deleted

    def test_deleted_flag(self) -> None:
        raw = "2|C:\\bad.exe|0|2023-01-01|2023-01-02|D\n"
        entries = parse_mft(raw)
        assert entries[0].deleted

    def test_empty_raw(self) -> None:
        assert parse_mft("") == []

    def test_comment_lines_skipped(self) -> None:
        raw = "# comment\n1|file.exe|100|2023-01-01|2023-01-01|A\n"
        entries = parse_mft(raw)
        assert len(entries) == 1

    def test_malformed_line_skipped(self) -> None:
        raw = "bad_line\n1|good.exe|100|2023-01-01|2023-01-01|A\n"
        entries = parse_mft(raw)
        assert len(entries) == 1


class TestParsePecmd:
    def test_csv_header_skipped(self) -> None:
        raw = "Executable,RunCount,LastRun\nnotepad.exe,5,2023-01-01\n"
        entries = parse_pecmd(raw)
        assert len(entries) == 1
        assert entries[0].executable == "notepad.exe"
        assert entries[0].run_count == 5

    def test_empty_raw(self) -> None:
        assert parse_pecmd("") == []


class TestParseAmcache:
    def test_valid_csv(self) -> None:
        raw = "Name,Path,SHA1,FileID,LastModified\nevil.exe,C:\\evil.exe,abc123,{001},2023-01-01\n"
        entries = parse_amcache(raw)
        assert len(entries) == 1
        assert entries[0].sha1 == "abc123"

    def test_empty_raw(self) -> None:
        assert parse_amcache("") == []


class TestParseReglookup:
    def test_valid_line(self) -> None:
        raw = "HKLM\\Run|evil|REG_SZ|C:\\evil.exe|2023-01-01\n"
        entries = parse_reglookup(raw)
        assert len(entries) == 1
        assert entries[0].value_data == "C:\\evil.exe"

    def test_comment_skipped(self) -> None:
        raw = "# comment\nHKLM\\Run|k|REG_SZ|v|2023-01-01\n"
        entries = parse_reglookup(raw)
        assert len(entries) == 1


class TestParseFls:
    def test_regular_file(self) -> None:
        raw = "r/r 1234:    C:\\Users\\user\\file.txt\n"
        entries = parse_fls(raw)
        assert len(entries) == 1
        assert not entries[0].deleted

    def test_deleted_file(self) -> None:
        raw = "r/r * 1234:    C:\\deleted.txt\n"
        entries = parse_fls(raw)
        assert entries[0].deleted


class TestParseEvtx:
    def test_valid_line(self) -> None:
        raw = "4624\tSecurity\t2023-01-01T00:00:00\tMS-Windows-Security\tInformation\tLogon\n"
        entries = parse_evtx(raw)
        assert len(entries) == 1
        assert entries[0].event_id == 4624
        assert entries[0].channel == "Security"

    def test_empty_raw(self) -> None:
        assert parse_evtx("") == []


class TestParseShimcache:
    def test_valid_csv(self) -> None:
        raw = "Path,LastModified,ExecFlag\nC:\\evil.exe,2023-01-01,True\n"
        from mcp_server.parsers.disk_parsers import parse_shimcache
        entries = parse_shimcache(raw)
        assert len(entries) == 1
        assert entries[0].exec_flag is True

    def test_empty_raw(self) -> None:
        from mcp_server.parsers.disk_parsers import parse_shimcache
        assert parse_shimcache("") == []
