
def append_to_file(path, content):
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n" + content)

# 1. test_disk_parsers.py
append_to_file("tests/test_disk_parsers.py", """
class TestParseShimcache:
    def test_valid_csv(self) -> None:
        raw = "Path,LastModified,ExecFlag\\nC:\\\\evil.exe,2023-01-01,True\\n"
        from mcp_server.parsers.disk_parsers import parse_shimcache
        entries = parse_shimcache(raw)
        assert len(entries) == 1
        assert entries[0].exec_flag is True

    def test_empty_raw(self) -> None:
        from mcp_server.parsers.disk_parsers import parse_shimcache
        assert parse_shimcache("") == []
""")

# 2. test_mcp_tools.py
append_to_file("tests/test_mcp_tools.py", """
class TestShimcache:
    def test_returns_list(self, tmp_path) -> None:
        p = tmp_path / "disk.E01"
        p.touch()
        from unittest.mock import patch
        import mcp_server.tools.disk as disk_mod
        shim_output = "Path,LastModified,ExecFlag\\nC:\\\\evil.exe,2023-01-01,True\\n"
        with patch.object(disk_mod, "_run", return_value=shim_output):
            result = disk_mod.shimcache(str(p))
        assert isinstance(result, list)
        assert result[0]["exec_flag"] is True

    def test_invalid_path_raises(self) -> None:
        import pytest
        import mcp_server.tools.disk as disk_mod
        with pytest.raises(PermissionError):
            disk_mod.shimcache("/outside/path")
""")

# 3. test_reporter.py
append_to_file("tests/test_reporter.py", """
    def test_ttp_ids_rendered_and_escaped(self) -> None:
        from shared.models import Finding, FindingStatus
        from agent.reporter import generate_report
        f = Finding(
            title="TTP Finding",
            ttp_ids=["T1003", "<script>alert(1)</script>"],
            status=FindingStatus.CONFIRMED,
        )
        # Using a dummy result
        from shared.models import TriageResult
        res = TriageResult(findings=[f], gaps=[], iterations=[], case_id="case1")
        from shared.models import Case
        report = generate_report(res, Case(id="case1"))
        assert "T1003" in report
        assert "<script>" not in report
        assert "&lt;script&gt;" in report
""")
