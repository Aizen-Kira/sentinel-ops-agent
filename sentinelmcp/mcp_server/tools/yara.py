"""YARA scanning tool (FEATURE-010)."""

import os
from pathlib import Path
from typing import Any

import yara

from shared.security import validate_path

_YARA_ROOTS: list[Path] = [Path(os.environ.get("SENTINELMCP_YARA_ROOT", "/evidence"))]

def yara_scan(target_path: str, rules_path: str) -> list[dict[str, Any]]:
    """Scan a target file or memory image using provided YARA rules.

    Args:
        target_path: Path to the file to scan (memory dump, executable, etc.)
        rules_path: Path to the YARA rule file

    Returns:
        List of dictionaries containing matched YARA rule details.
    """
    valid_target = validate_path(target_path, _YARA_ROOTS)
    valid_rules = validate_path(rules_path, _YARA_ROOTS)

    # Compile the rules
    try:
        rules = yara.compile(filepath=str(valid_rules))
    except yara.SyntaxError as e:
        raise ValueError(f"YARA syntax error in {rules_path}: {e}") from e
    except yara.Error as e:
        raise RuntimeError(f"YARA compilation error: {e}") from e

    # Perform the scan
    try:
        matches = rules.match(filepath=str(valid_target))
    except yara.Error as e:
        raise RuntimeError(f"YARA matching error on {target_path}: {e}") from e

    results = []
    for match in matches:
        results.append({
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": match.tags,
            "meta": match.meta,
            "strings": match.strings,
        })

    return results
