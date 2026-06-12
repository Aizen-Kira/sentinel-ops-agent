"""Tests for mcp_server/tools/correlate.py — BUG-001 + BUG-002."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server.tools.correlate as corr_mod
from mcp_server.tools.correlate import _parse_ts, _utcnow_naive


@pytest.fixture(autouse=True)
def set_roots(tmp_path: Path) -> None:
    corr_mod.set_roots(
        disk_roots=[tmp_path],
        memory_roots=[tmp_path],
        pcap_roots=[tmp_path],
    )


def _make_file(tmp_path: Path, name: str) -> str:
    p = tmp_path / name
    p.touch()
    return str(p)


class TestParseTsBug002:
    """BUG-002: _parse_ts must always return tz-naïve datetimes."""

    def test_naive_iso_returned_as_is(self) -> None:
        dt = _parse_ts("2023-01-01T12:00:00")
        assert dt is not None
        assert dt.tzinfo is None

    def test_tz_aware_stripped(self) -> None:
        dt = _parse_ts("2023-01-01T12:00:00+05:30")
        assert dt is not None
        assert dt.tzinfo is None

    def test_utc_z_stripped(self) -> None:
        dt = _parse_ts("2023-01-01T12:00:00+00:00")
        assert dt is not None
        assert dt.tzinfo is None

    def test_invalid_returns_none(self) -> None:
        assert _parse_ts("not-a-date") is None

    def test_empty_returns_none(self) -> None:
        assert _parse_ts("") is None

    def test_naive_and_aware_comparable(self) -> None:
        """Key BUG-002 scenario: naïve and aware datetimes must not be mixed."""
        dt1 = _parse_ts("2023-01-01T00:00:00+00:00")
        dt2 = _parse_ts("2023-01-01T01:00:00")
        assert dt1 is not None and dt2 is not None
        # This must not raise TypeError:
        diff = dt2 - dt1
        assert diff.total_seconds() == 3600.0


class TestUtcnowNaive:
    def test_returns_naive_datetime(self) -> None:
        now = _utcnow_naive()
        assert now.tzinfo is None

    def test_comparable_with_parse_ts(self) -> None:
        now = _utcnow_naive()
        ts = _parse_ts("2020-01-01T00:00:00+00:00")
        assert ts is not None
        # Must not raise TypeError:
        assert now > ts


class TestTimelineGapsBug001:
    def test_invalid_disk_path_raises(self) -> None:
        with pytest.raises(PermissionError):
            corr_mod.timeline_gaps(image_path="/outside/disk.E01")

    def test_valid_paths_no_crash(self, tmp_path: Path) -> None:
        disk = _make_file(tmp_path, "disk.E01")
        mem = _make_file(tmp_path, "mem.dmp")
        import subprocess as stdlib_subprocess
        from unittest.mock import MagicMock
        mock_result = MagicMock()
        mock_result.stdout = ""
        with patch.object(stdlib_subprocess, "run", return_value=mock_result):
            result = corr_mod.timeline_gaps(image_path=disk, memory_path=mem)
        assert isinstance(result, list)


class TestCorrelateDiskMemoryBug001:
    def test_invalid_disk_path_raises(self, tmp_path: Path) -> None:
        mem = _make_file(tmp_path, "mem.dmp")
        with pytest.raises(PermissionError):
            corr_mod.correlate_disk_memory("/outside/disk.E01", mem)

    def test_invalid_memory_path_raises(self, tmp_path: Path) -> None:
        disk = _make_file(tmp_path, "disk.E01")
        with pytest.raises(PermissionError):
            corr_mod.correlate_disk_memory(disk, "/outside/mem.dmp")
