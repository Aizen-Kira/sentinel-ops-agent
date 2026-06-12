"""Tests for shared/security.py — validate_path() (BUG-001)."""
from __future__ import annotations

from pathlib import Path

import pytest

from shared.security import validate_path


class TestValidatePath:
    def test_valid_path_under_root(self, tmp_path: Path) -> None:
        target = tmp_path / "evidence" / "disk.E01"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()
        result = validate_path(str(target), [tmp_path])
        assert result == target.resolve()

    def test_path_outside_root_raises_permission_error(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside" / "secret.txt"
        outside.parent.mkdir(parents=True, exist_ok=True)
        outside.touch()
        with pytest.raises(PermissionError):
            validate_path(str(outside), [allowed])

    def test_empty_path_raises_value_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            validate_path("", [tmp_path])

    def test_whitespace_path_raises_value_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            validate_path("   ", [tmp_path])

    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        traversal = str(allowed / ".." / ".." / "etc" / "passwd")
        with pytest.raises(PermissionError):
            validate_path(traversal, [allowed])

    def test_multiple_roots_first_match_wins(self, tmp_path: Path) -> None:
        root_a = tmp_path / "a"
        root_b = tmp_path / "b"
        root_a.mkdir()
        root_b.mkdir()
        target = root_b / "file.txt"
        target.touch()
        result = validate_path(str(target), [root_a, root_b])
        assert result == target.resolve()

    def test_returns_resolved_path(self, tmp_path: Path) -> None:
        subdir = tmp_path / "sub"
        subdir.mkdir()
        target = subdir / "file.bin"
        target.touch()
        result = validate_path(str(target), [tmp_path])
        assert result.is_absolute()
