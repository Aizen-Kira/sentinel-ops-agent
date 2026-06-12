"""Memory artifact parsers — parse Volatility 3 CLI output into typed dataclasses."""
from __future__ import annotations

import logging

from shared.models import MalfindRegion, NetworkConnection, ProcessEntry

logger = logging.getLogger(__name__)


def parse_pslist(raw: str) -> list[ProcessEntry]:
    """Parse vol3 windows.pslist output.

    Header: PID  PPID  ImageFileName  CreateTime  ExitTime
    """
    entries: list[ProcessEntry] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("PID") or line.startswith("*") or line.startswith("Volatility"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            entries.append(ProcessEntry(
                pid=int(parts[0]),
                ppid=int(parts[1]),
                name=parts[2],
                create_time=parts[3] if len(parts) > 3 else None,
                exit_time=parts[4] if len(parts) > 4 else None,
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed pslist line: %s (%s)", line[:80], exc)
    return entries


def parse_netscan(raw: str) -> list[NetworkConnection]:
    """Parse vol3 windows.netstat output.

    Header: Offset  Proto  LocalAddr  LocalPort  ForeignAddr  ForeignPort  State  PID
    """
    entries: list[NetworkConnection] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("Offset") or line.startswith("Volatility"):
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            entries.append(NetworkConnection(
                proto=parts[1],
                local_addr=parts[2],
                local_port=int(parts[3]) if parts[3].isdigit() else 0,
                remote_addr=parts[4],
                remote_port=int(parts[5]) if parts[5].isdigit() else 0,
                state=parts[6],
                pid=int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else None,
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed netscan line: %s (%s)", line[:80], exc)
    return entries


def parse_malfind(raw: str) -> list[MalfindRegion]:
    """Parse vol3 windows.malfind output (block-structured)."""
    entries: list[MalfindRegion] = []
    current: dict[str, str] = {}
    hex_lines: list[str] = []
    disasm_lines: list[str] = []
    in_hex = False
    in_disasm = False

    def _flush() -> None:
        if current.get("pid"):
            entries.append(MalfindRegion(
                pid=int(current.get("pid", "0")),
                process_name=current.get("name", ""),
                start=current.get("start", ""),
                end=current.get("end", ""),
                tag=current.get("tag", ""),
                hex_dump="\n".join(hex_lines),
                disassembly="\n".join(disasm_lines),
            ))
        current.clear()
        hex_lines.clear()
        disasm_lines.clear()

    for line in raw.splitlines():
        if line.startswith("Process:"):
            _flush()
            in_hex = False
            in_disasm = False
            parts = line.split()
            try:
                current["name"] = parts[1]
                current["pid"] = parts[3]
            except IndexError:
                pass
        elif "Start VPN" in line or "Start:" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p in ("Start:", "Start") and i + 1 < len(parts):
                    current["start"] = parts[i + 1]
                if p in ("End:", "End") and i + 1 < len(parts):
                    current["end"] = parts[i + 1]
                if p in ("Tag:", "Tag") and i + 1 < len(parts):
                    current["tag"] = parts[i + 1]
        elif line.startswith("0x"):
            in_hex = True
            in_disasm = False
            hex_lines.append(line)
        elif in_hex and line.strip():
            in_disasm = True
            in_hex = False
            disasm_lines.append(line)
        elif in_disasm and line.strip():
            disasm_lines.append(line)

    _flush()
    return entries


def parse_cmdline(raw: str) -> list[ProcessEntry]:
    """Parse vol3 windows.cmdline output.

    Format: PID  Process  Args
    """
    entries: list[ProcessEntry] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("PID") or line.startswith("Volatility"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            entries.append(ProcessEntry(
                pid=int(parts[0]),
                ppid=0,
                name=parts[1],
                cmd=parts[2] if len(parts) > 2 else None,
            ))
        except (ValueError, IndexError) as exc:
            logger.debug("Skipping malformed cmdline line: %s (%s)", line[:80], exc)
    return entries
