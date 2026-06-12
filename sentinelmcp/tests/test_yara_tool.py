"""Tests for YARA scanning tool."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yara

from mcp_server.tools.yara import yara_scan


def test_yara_scan_valid_paths_and_matches(tmp_path: Path) -> None:
    target_file = tmp_path / "target.exe"
    rules_file = tmp_path / "rules.yar"
    target_file.write_text("dummy")
    rules_file.write_text("dummy")

    mock_match = MagicMock()
    mock_match.rule = "EvilMalware"
    mock_match.namespace = "default"
    mock_match.tags = ["malware"]
    mock_match.meta = {"author": "Test"}
    mock_match.strings = [(10, "$a", b"evil")]

    mock_rules = MagicMock()
    mock_rules.match.return_value = [mock_match]

    with patch("mcp_server.tools.yara.validate_path", side_effect=[target_file, rules_file]), \
         patch("mcp_server.tools.yara.yara.compile", return_value=mock_rules):
        results = yara_scan(str(target_file), str(rules_file))

    assert len(results) == 1
    assert results[0]["rule"] == "EvilMalware"
    assert results[0]["tags"] == ["malware"]
    assert results[0]["meta"] == {"author": "Test"}
    assert results[0]["strings"] == [(10, "$a", b"evil")]


def test_yara_scan_invalid_target_path(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.yar"
    rules_file.write_text("dummy")

    with patch("mcp_server.tools.yara.validate_path", side_effect=PermissionError("Access Denied")):
        with pytest.raises(PermissionError):
            yara_scan("/outside/target.exe", str(rules_file))


def test_yara_scan_compile_error(tmp_path: Path) -> None:
    target_file = tmp_path / "target.exe"
    rules_file = tmp_path / "rules.yar"
    target_file.write_text("dummy")
    rules_file.write_text("dummy")

    with patch("mcp_server.tools.yara.validate_path", side_effect=[target_file, rules_file]), \
         patch("mcp_server.tools.yara.yara.compile", side_effect=yara.SyntaxError("Syntax Error")):
        with pytest.raises(ValueError, match="YARA syntax error"):
            yara_scan(str(target_file), str(rules_file))
