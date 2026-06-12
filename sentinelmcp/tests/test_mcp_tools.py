"""Tests for mcp_server tools — patch _run/_vol3/_tshark to avoid real CLI calls."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import mcp_server.tools.disk as disk_mod
import mcp_server.tools.memory as mem_mod
import mcp_server.tools.network as net_mod


@pytest.fixture(autouse=True)
def set_roots(tmp_path: Path) -> None:
    """Allow tmp_path as root for all tool validation."""
    disk_mod.set_disk_roots([tmp_path])
    mem_mod.set_memory_roots([tmp_path])
    net_mod.set_pcap_roots([tmp_path])


def _make_file(tmp_path: Path, name: str) -> str:
    p = tmp_path / name
    p.touch()
    return str(p)


# ---------------------------------------------------------------------------
# Disk tool tests
# ---------------------------------------------------------------------------

class TestMftdump:
    def test_returns_list(self, tmp_path: Path) -> None:
        path = _make_file(tmp_path, "disk.E01")
        mft_output = "1|C:\\Windows\\system32\\notepad.exe|12345|2023-01-01|2023-01-02|A\n"
        with patch.object(disk_mod, "_run", return_value=mft_output):
            result = disk_mod.mftdump(path)
        assert isinstance(result, list)
        assert result[0]["path"] == "C:\\Windows\\system32\\notepad.exe"

    def test_invalid_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PermissionError):
            disk_mod.mftdump("/etc/passwd")


class TestEvtxdump:
    def test_returns_list(self, tmp_path: Path) -> None:
        path = _make_file(tmp_path, "disk.E01")
        evtx_output = "4624\tSecurity\t2023-01-01T00:00:00\tMicrosoft-Security\tInformation\tLogon success\n"
        with patch.object(disk_mod, "_run", return_value=evtx_output):
            result = disk_mod.evtxdump(path)
        assert isinstance(result, list)
        assert result[0]["event_id"] == 4624

    def test_invalid_path_raises(self) -> None:
        with pytest.raises(PermissionError):
            disk_mod.evtxdump("/outside/path")


class TestReglookup:
    def test_returns_list(self, tmp_path: Path) -> None:
        path = _make_file(tmp_path, "disk.E01")
        reg_output = "HKLM\\Run|malware|REG_SZ|C:\\evil.exe|2023-01-01\n"
        with patch.object(disk_mod, "_run", return_value=reg_output):
            result = disk_mod.reglookup(path, key=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        assert isinstance(result, list)
        assert result[0]["value_data"] == "C:\\evil.exe"


# ---------------------------------------------------------------------------
# Memory tool tests
# ---------------------------------------------------------------------------

class TestVol3Pslist:
    def test_returns_list(self, tmp_path: Path) -> None:
        path = _make_file(tmp_path, "mem.dmp")
        pslist_output = "4\t0\tSystem\t2023-01-01 00:00:00\t\n1234\t4\tmimikatz.exe\t2023-01-01 01:00:00\t\n"
        with patch.object(mem_mod, "_vol3", return_value=pslist_output):
            result = mem_mod.vol3_pslist(path)
        assert isinstance(result, list)
        names = [r["name"] for r in result]
        assert "mimikatz.exe" in names

    def test_invalid_path_raises(self) -> None:
        with pytest.raises(PermissionError):
            mem_mod.vol3_pslist("/bad/path/mem.dmp")


class TestVol3Malfind:
    def test_returns_list(self, tmp_path: Path) -> None:
        path = _make_file(tmp_path, "mem.dmp")
        with patch.object(mem_mod, "_vol3", return_value=""):
            result = mem_mod.vol3_malfind(path)
        assert isinstance(result, list)

    def test_invalid_path_raises(self) -> None:
        with pytest.raises(PermissionError):
            mem_mod.vol3_malfind("/etc/shadow")


class TestVol3Cmdline:
    def test_returns_list(self, tmp_path: Path) -> None:
        path = _make_file(tmp_path, "mem.dmp")
        cmdline_output = "1234\tmimikatz.exe\tsekurlsa::logonpasswords\n"
        with patch.object(mem_mod, "_vol3", return_value=cmdline_output):
            result = mem_mod.vol3_cmdline(path)
        assert isinstance(result, list)
        assert result[0]["cmd"] == "sekurlsa::logonpasswords"


# ---------------------------------------------------------------------------
# Network tool tests
# ---------------------------------------------------------------------------

class TestTsharkConversations:
    def test_returns_list(self, tmp_path: Path) -> None:
        path = _make_file(tmp_path, "cap.pcap")
        with patch.object(net_mod, "_tshark", return_value=""):
            result = net_mod.tshark_conversations(path)
        assert isinstance(result, list)

    def test_invalid_path_raises(self) -> None:
        with pytest.raises(PermissionError):
            net_mod.tshark_conversations("/bad.pcap")


class TestTsharkDns:
    def test_returns_list(self, tmp_path: Path) -> None:
        path = _make_file(tmp_path, "cap.pcap")
        dns_output = "1672531200.0\t192.168.1.1\tevil.com\tA\t10.0.0.1\n"
        with patch.object(net_mod, "_tshark", return_value=dns_output):
            result = net_mod.tshark_dns(path)
        assert isinstance(result, list)
        assert result[0]["query_name"] == "evil.com"


class TestTsharkHttp:
    def test_returns_list(self, tmp_path: Path) -> None:
        path = _make_file(tmp_path, "cap.pcap")
        http_output = "1672531200.0\t192.168.1.1\t10.0.0.1\tGET\tevil.com\t/payload.exe\tpython-requests\n"
        with patch.object(net_mod, "_tshark", return_value=http_output):
            result = net_mod.tshark_http(path)
        assert isinstance(result, list)
        assert result[0]["method"] == "GET"
        assert result[0]["host"] == "evil.com"


class TestShimcache:
    def test_returns_list(self, tmp_path: Path) -> None:
        p = tmp_path / "disk.E01"
        p.touch()
        from unittest.mock import patch

        import mcp_server.tools.disk as disk_mod
        shim_output = "Path,LastModified,ExecFlag\nC:\\evil.exe,2023-01-01,True\n"
        with patch.object(disk_mod, "_run", return_value=shim_output):
            result = disk_mod.shimcache(str(p))
        assert isinstance(result, list)
        assert result[0]["exec_flag"] is True

    def test_invalid_path_raises(self) -> None:
        import pytest

        import mcp_server.tools.disk as disk_mod
        with pytest.raises(PermissionError):
            disk_mod.shimcache("/outside/path")
