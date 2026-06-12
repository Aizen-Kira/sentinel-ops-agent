"""Memory forensics tools — BUG-001: all paths validated via validate_path().

Wraps Volatility 3 (vol3) CLI. No shell=True. All subprocess args are lists.
"""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from mcp_server.parsers.memory_parsers import (
    parse_cmdline,
    parse_malfind,
    parse_netscan,
    parse_pslist,
)
from shared.security import validate_path

logger = logging.getLogger(__name__)

_MEMORY_ROOTS: list[Path] = [Path(os.environ.get("SENTINELMCP_MEMORY_ROOT", "/evidence"))]


def set_memory_roots(roots: list[Path]) -> None:
    global _MEMORY_ROOTS
    _MEMORY_ROOTS = roots


def _validate(memory_path: str) -> Path:
    return validate_path(memory_path, _MEMORY_ROOTS)


def _vol3(plugin: str, memory_path: Path, extra: list[str] | None = None) -> str:
    cmd = ["vol3", "-f", str(memory_path), plugin] + (extra or [])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, shell=False)
    if result.returncode != 0:
        logger.warning("vol3 %s exited %d: %s", plugin, result.returncode, result.stderr[:200])
    return result.stdout


def vol3_pslist(memory_path: str) -> list[dict[str, Any]]:
    """List processes from a memory dump."""
    validated = _validate(memory_path)
    raw = _vol3("windows.pslist.PsList", validated)
    entries = parse_pslist(raw)
    return [
        {
            "pid": e.pid,
            "ppid": e.ppid,
            "name": e.name,
            "create_time": e.create_time,
            "exit_time": e.exit_time,
        }
        for e in entries
    ]


def vol3_netscan(memory_path: str) -> list[dict[str, Any]]:
    """Scan network connections from a memory dump."""
    validated = _validate(memory_path)
    raw = _vol3("windows.netstat.NetStat", validated)
    entries = parse_netscan(raw)
    return [
        {
            "proto": e.proto,
            "local_addr": e.local_addr,
            "local_port": e.local_port,
            "remote_addr": e.remote_addr,
            "remote_port": e.remote_port,
            "state": e.state,
            "pid": e.pid,
        }
        for e in entries
    ]


def vol3_malfind(memory_path: str) -> list[dict[str, Any]]:
    """Find suspicious memory regions via malfind heuristic."""
    validated = _validate(memory_path)
    raw = _vol3("windows.malfind.Malfind", validated)
    entries = parse_malfind(raw)
    return [
        {
            "pid": e.pid,
            "process_name": e.process_name,
            "start": e.start,
            "end": e.end,
            "tag": e.tag,
            "hex_dump": e.hex_dump,
            "disassembly": e.disassembly,
        }
        for e in entries
    ]


def vol3_cmdline(memory_path: str) -> list[dict[str, Any]]:
    """Extract process command lines from a memory dump."""
    validated = _validate(memory_path)
    raw = _vol3("windows.cmdline.CmdLine", validated)
    entries = parse_cmdline(raw)
    return [
        {
            "pid": e.pid,
            "name": e.name,
            "cmd": e.cmd,
        }
        for e in entries
    ]


# get_handles is a dead function per the spec — kept as stub, not registered.
def get_handles(memory_path: str, pid: int) -> list[dict[str, Any]]:  # pragma: no cover
    """STUB: not registered as MCP tool (dead code per architecture spec)."""
    logger.warning("get_handles is not an active MCP tool.")
    return []
