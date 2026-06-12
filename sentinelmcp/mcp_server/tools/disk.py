"""Disk forensics tools — BUG-001: all paths validated via validate_path().

Each tool:
  1. Validates image_path against ALLOWED_ROOTS (set via set_disk_roots()).
  2. Mounts / reads the image using the appropriate CLI tool.
  3. Parses output through mcp_server/parsers/disk_parsers.py.
  4. Returns list[dict] — never raw dataclasses.

No shell=True. All subprocess args are explicit lists.
"""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from mcp_server.parsers.disk_parsers import (
    parse_amcache,
    parse_evtx,
    parse_fls,
    parse_mft,
    parse_pecmd,
    parse_reglookup,
    parse_shimcache,
)
from shared.security import validate_path

logger = logging.getLogger(__name__)

# Allowed root directories for disk images.
# Override in production by calling set_disk_roots() at startup.
_DISK_ROOTS: list[Path] = [Path(os.environ.get("SENTINELMCP_DISK_ROOT", "/evidence"))]


def set_disk_roots(roots: list[Path]) -> None:
    """Configure the allowed root paths for disk image access."""
    global _DISK_ROOTS
    _DISK_ROOTS = roots


def _validate(image_path: str) -> Path:
    return validate_path(image_path, _DISK_ROOTS)


def _run(cmd: list[str], timeout: int = 120) -> str:
    """Run a subprocess command, never with shell=True."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,  # explicit — never shell=True
    )
    if result.returncode != 0:
        logger.warning("Command %s exited %d: %s", cmd[0], result.returncode, result.stderr[:200])
    return result.stdout


# ---------------------------------------------------------------------------
# Tool functions — each returns list[dict]
# ---------------------------------------------------------------------------


def mftdump(image_path: str) -> list[dict[str, Any]]:
    """Dump MFT entries from a disk image."""
    validated = _validate(image_path)
    raw = _run(["mftdump", "-f", str(validated)])
    entries = parse_mft(raw)
    return [
        {
            "path": e.path,
            "size": e.size,
            "modified": e.modified,
            "created": e.created,
            "deleted": e.deleted,
            "inode": e.inode,
        }
        for e in entries
    ]


def pecmd(image_path: str) -> list[dict[str, Any]]:
    """Parse Windows Prefetch files from a disk image."""
    validated = _validate(image_path)
    raw = _run(["PECmd.exe", "-d", str(validated), "--csv", "-"])
    entries = parse_pecmd(raw)
    return [
        {
            "executable": e.executable,
            "run_count": e.run_count,
            "last_run": e.last_run,
            "volumes": e.volumes,
        }
        for e in entries
    ]


def amcacheparser(image_path: str) -> list[dict[str, Any]]:
    """Parse Amcache.hve from a disk image."""
    validated = _validate(image_path)
    raw = _run(["AmcacheParser.exe", "-f", str(validated), "--csv", "-"])
    entries = parse_amcache(raw)
    return [
        {
            "name": e.name,
            "path": e.path,
            "sha1": e.sha1,
            "file_id": e.file_id,
            "last_modified": e.last_modified,
        }
        for e in entries
    ]


def reglookup(image_path: str, key: str = "") -> list[dict[str, Any]]:
    """Look up registry keys from a disk image."""
    validated = _validate(image_path)
    cmd = ["reglookup", str(validated)]
    if key:
        cmd += ["-p", key]
    raw = _run(cmd)
    entries = parse_reglookup(raw)
    return [
        {
            "key": e.key,
            "value_name": e.value_name,
            "value_type": e.value_type,
            "value_data": e.value_data,
            "last_written": e.last_written,
        }
        for e in entries
    ]


def fls(image_path: str, directory: str = "/") -> list[dict[str, Any]]:
    """List files in a directory of a disk image using The Sleuth Kit fls."""
    validated = _validate(image_path)
    raw = _run(["fls", "-r", "-p", str(validated)])
    entries = parse_fls(raw)
    return [
        {
            "path": e.path,
            "size": e.size,
            "modified": e.modified,
            "deleted": e.deleted,
        }
        for e in entries
    ]


def evtxdump(image_path: str, channel: str = "Security") -> list[dict[str, Any]]:
    """Dump Windows event log entries from a disk image."""
    validated = _validate(image_path)
    raw = _run(["evtxdump", "--channel", channel, str(validated)])
    entries = parse_evtx(raw)
    return [
        {
            "event_id": e.event_id,
            "channel": e.channel,
            "timestamp": e.timestamp,
            "provider": e.provider,
            "level": e.level,
            "message": e.message,
            "data": e.data,
        }
        for e in entries
    ]


def shimcache(image_path: str) -> list[dict[str, Any]]:
    """Parse AppCompatCache (shimcache) from a disk image."""
    validated = _validate(image_path)
    raw = _run(["AppCompatCacheParser.exe", "-f", str(validated), "--csv", "-"])
    entries = parse_shimcache(raw)
    return [
        {
            "path": e.path,
            "last_modified": e.last_modified,
            "exec_flag": e.exec_flag,
        }
        for e in entries
    ]


