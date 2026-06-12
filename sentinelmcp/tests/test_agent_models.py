"""Tests for agent/models.py — compatibility shim (BUG-007)."""
from __future__ import annotations


class TestAgentModelsShim:
    def test_no_star_import(self) -> None:
        """BUG-007: agent.models must use explicit imports, not star imports."""
        import ast
        import inspect

        import agent.models as mod

        source = inspect.getsource(mod)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.ImportFrom, ast.Import)):
                if isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        assert alias.name != "*", "Star import found in agent.models!"

    def test_all_canonical_types_importable(self) -> None:
        from agent.models import (
            Case,
            Finding,
            FindingStatus,
            Gap,
            IterationLog,
            TriageResult,
        )
        assert Case is not None
        assert Finding is not None
        assert FindingStatus is not None
        assert Gap is not None
        assert IterationLog is not None
        assert TriageResult is not None

    def test_finding_from_shim_is_same_as_shared(self) -> None:
        from agent.models import Finding as AgentFinding
        from shared.models import Finding as SharedFinding
        assert AgentFinding is SharedFinding

    def test_all_defined_in_dunder_all(self) -> None:
        import agent.models as mod
        assert hasattr(mod, "__all__")
        assert "Finding" in mod.__all__
        assert "Case" in mod.__all__
