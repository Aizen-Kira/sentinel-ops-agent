"""Path validation utilities — BUG-001 fix.

All external file paths received from MCP tool parameters MUST be validated
through validate_path() before any filesystem access.
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def validate_path(path: str, allowed_roots: list[Path]) -> Path:
    """Resolve *path* and assert it falls under one of *allowed_roots*.

    Args:
        path: Raw path string received from external input (MCP param).
        allowed_roots: Absolute directory paths that are permitted.

    Returns:
        The resolved :class:`pathlib.Path`.

    Raises:
        ValueError: If *path* is empty.
        PermissionError: If the resolved path is outside every allowed root.
    """
    if not path or not path.strip():
        raise ValueError("Path must be a non-empty string.")

    resolved = Path(path).resolve()

    for root in allowed_roots:
        root_resolved = root.resolve()
        try:
            resolved.relative_to(root_resolved)
            logger.debug("Path validated: %s under root %s", resolved, root_resolved)
            return resolved
        except ValueError:
            continue

    # Never log the raw path at INFO+ — only at DEBUG.
    logger.debug("Path validation failed — not under any allowed root.")
    raise PermissionError(
        f"Access denied: path is not within any of the "
        f"{len(allowed_roots)} allowed root(s)."
    )
