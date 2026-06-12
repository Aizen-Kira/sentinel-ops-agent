"""Disk artifact parsers — parse raw CLI output into typed dataclasses.

These parsers are called ONLY by mcp_server/tools/disk.py. They must never
be imported by agent.loop or agent.evaluator.
"""
from __future__ import annotations

import logging

from shared.models import (
    AmcacheEntry,
    EventLogEntry,
    FileEntry,
    PrefetchEntry,
    RegistryEntry,
    ShimcacheEntry,
)

logger = logging.getLogger(__name__)


def parse_mft(raw: str) -> list[FileEntry]:
    """Parse mftdump text output into FileEntry list.

    Expected format (one entry per line):
        <inode>|<path>|<size>|<created>|<modified>|<D/A>
    """
    entries: list[FileEntry] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 4:
            continue
        try:
            inode = int(parts[0]) if parts[0].isdigit() else None
            path = parts[1] if len(parts) > 1 else ""
            size = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
            created = parts[3] if len(parts) > 3 else None
            modified = parts[4] if len(parts) > 4 else None
            deleted = len(parts) > 5 and parts[5].upper() == "D"
            entries.append(FileEntry(
                path=path,
                size=size,
                modified=modified or None,
                created=created or None,
                deleted=deleted,
                inode=inode,
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed MFT line: %s (%s)", line[:80], exc)
    return entries


def parse_pecmd(raw: str) -> list[PrefetchEntry]:
    """Parse PECmd CSV output into PrefetchEntry list."""
    entries: list[PrefetchEntry] = []
    lines = raw.splitlines()
    if not lines:
        return entries
    # Skip header row
    for line in lines[1:]:
        parts = line.split(",")
        if len(parts) < 3:
            continue
        try:
            entries.append(PrefetchEntry(
                executable=parts[0].strip().strip('"'),
                run_count=int(parts[1].strip()) if parts[1].strip().isdigit() else 0,
                last_run=parts[2].strip().strip('"') or None,
                volumes=[v.strip().strip('"') for v in parts[3:] if v.strip()],
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed PECmd line: %s (%s)", line[:80], exc)
    return entries


def parse_amcache(raw: str) -> list[AmcacheEntry]:
    """Parse AmcacheParser CSV output into AmcacheEntry list."""
    entries: list[AmcacheEntry] = []
    lines = raw.splitlines()
    for line in lines[1:]:
        parts = line.split(",")
        if len(parts) < 2:
            continue
        try:
            entries.append(AmcacheEntry(
                name=parts[0].strip().strip('"'),
                path=parts[1].strip().strip('"'),
                sha1=parts[2].strip().strip('"') if len(parts) > 2 else None,
                file_id=parts[3].strip().strip('"') if len(parts) > 3 else None,
                last_modified=parts[4].strip().strip('"') if len(parts) > 4 else None,
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed Amcache line: %s (%s)", line[:80], exc)
    return entries


def parse_reglookup(raw: str) -> list[RegistryEntry]:
    """Parse reglookup output into RegistryEntry list.

    Expected format: KEY|VALUE_NAME|TYPE|DATA|LAST_WRITTEN
    """
    entries: list[RegistryEntry] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 4:
            continue
        try:
            entries.append(RegistryEntry(
                key=parts[0],
                value_name=parts[1],
                value_type=parts[2],
                value_data=parts[3],
                last_written=parts[4] if len(parts) > 4 else None,
            ))
        except IndexError as exc:
            logger.debug("Skipping malformed reglookup line: %s (%s)", line[:80], exc)
    return entries


def parse_fls(raw: str) -> list[FileEntry]:
    """Parse TSK fls -r output into FileEntry list.

    TSK fls output format:
        r/r <inode>:    <path>
        d/d <inode>:    <path>
    """
    entries: list[FileEntry] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        deleted = line.startswith("r/r * ") or line.startswith("d/d * ")
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        path = parts[2].strip()
        entries.append(FileEntry(path=path, size=0, deleted=deleted))
    return entries


def parse_evtx(raw: str) -> list[EventLogEntry]:
    """Parse evtxdump text output into EventLogEntry list.

    Expected format (tab-separated):
        EVENT_ID\\tCHANNEL\\tTIMESTAMP\\tPROVIDER\\tLEVEL\\tMESSAGE
    """
    entries: list[EventLogEntry] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            entries.append(EventLogEntry(
                event_id=int(parts[0]) if parts[0].isdigit() else 0,
                channel=parts[1],
                timestamp=parts[2],
                provider=parts[3],
                level=parts[4],
                message=parts[5] if len(parts) > 5 else "",
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed evtx line: %s (%s)", line[:80], exc)
    return entries


def parse_shimcache(raw: str) -> list[ShimcacheEntry]:
    """Parse output from AppCompatCacheParser."""
    entries: list[ShimcacheEntry] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("Path,") or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 3:
            entries.append(ShimcacheEntry(
                path=parts[0].strip().strip('"'),
                last_modified=parts[1].strip().strip('"') or None,
                exec_flag=parts[2].strip().strip('"').lower() == "true" if len(parts) > 2 else None,
            ))
    return entries
