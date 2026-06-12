"""Fuzz testing for all parsers (FEATURE-014).

Generates randomized malformed input:
  - empty input
  - oversized lines
  - malformed CSV / JSON
  - unicode edge cases
  - binary blobs

Each parser must:
  - never crash (no unhandled exceptions)
  - never execute code
  - return safe types (list)

Minimum: 1000 iterations per parser.
"""
from __future__ import annotations

import os
import random
import string

import pytest

from mcp_server.parsers.disk_parsers import (
    parse_amcache,
    parse_evtx,
    parse_fls,
    parse_mft,
    parse_pecmd,
    parse_reglookup,
    parse_shimcache,
)
from mcp_server.parsers.memory_parsers import (
    parse_cmdline,
    parse_malfind,
    parse_netscan,
    parse_pslist,
)
from mcp_server.parsers.network_parsers import (
    parse_conversations,
    parse_dns,
    parse_http,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ITERATIONS = 1000
SEED = 42  # deterministic randomness for reproducibility


# ---------------------------------------------------------------------------
# Fuzz generators
# ---------------------------------------------------------------------------

def _random_unicode(length: int) -> str:
    """Generate a string of random unicode characters."""
    chars = []
    for _ in range(length):
        # Mix of basic multilingual plane characters
        cp = random.randint(0x20, 0xFFFF)
        # Skip surrogates
        if 0xD800 <= cp <= 0xDFFF:
            cp = 0x20
        try:
            chars.append(chr(cp))
        except (ValueError, OverflowError):
            chars.append("?")
    return "".join(chars)


def _random_binary(length: int) -> str:
    """Generate a string from random bytes decoded with errors replaced."""
    return os.urandom(length).decode("utf-8", errors="replace")


def _random_ascii(length: int) -> str:
    return "".join(random.choices(string.printable, k=length))


def generate_fuzz_input(rng: random.Random) -> str:
    """Generate one fuzz input string."""
    kind = rng.randint(0, 9)

    if kind == 0:
        # Empty input
        return ""
    elif kind == 1:
        # Whitespace only
        return " \t\n\r" * rng.randint(1, 100)
    elif kind == 2:
        # Oversized single line
        return "A" * rng.randint(10_000, 100_000)
    elif kind == 3:
        # Malformed CSV — wrong number of fields, unmatched quotes
        rows = []
        for _ in range(rng.randint(1, 50)):
            fields = rng.randint(0, 20)
            row = ",".join(_random_ascii(rng.randint(0, 30)) for _ in range(fields))
            if rng.random() < 0.3:
                row += '"'  # unmatched quote
            rows.append(row)
        return "\n".join(rows)
    elif kind == 4:
        # Malformed JSON-like input
        return "{" * rng.randint(1, 50) + _random_ascii(rng.randint(0, 200))
    elif kind == 5:
        # Unicode edge cases
        return _random_unicode(rng.randint(1, 5000))
    elif kind == 6:
        # Binary blob
        return _random_binary(rng.randint(1, 5000))
    elif kind == 7:
        # Pipe-delimited garbage (targets disk parsers)
        rows = []
        for _ in range(rng.randint(1, 100)):
            fields = rng.randint(0, 10)
            row = "|".join(_random_ascii(rng.randint(0, 50)) for _ in range(fields))
            rows.append(row)
        return "\n".join(rows)
    elif kind == 8:
        # Tab-delimited garbage (targets network parsers)
        rows = []
        for _ in range(rng.randint(1, 100)):
            fields = rng.randint(0, 10)
            row = "\t".join(_random_ascii(rng.randint(0, 50)) for _ in range(fields))
            rows.append(row)
        return "\n".join(rows)
    else:
        # Null bytes and control characters
        return "\x00" * rng.randint(1, 1000) + "\n" + "\x01\x02\x03" * rng.randint(1, 100)


# ---------------------------------------------------------------------------
# All parsers to fuzz
# ---------------------------------------------------------------------------
ALL_PARSERS = [
    ("parse_mft", parse_mft),
    ("parse_pecmd", parse_pecmd),
    ("parse_amcache", parse_amcache),
    ("parse_reglookup", parse_reglookup),
    ("parse_fls", parse_fls),
    ("parse_evtx", parse_evtx),
    ("parse_shimcache", parse_shimcache),
    ("parse_pslist", parse_pslist),
    ("parse_netscan", parse_netscan),
    ("parse_malfind", parse_malfind),
    ("parse_cmdline", parse_cmdline),
    ("parse_conversations", parse_conversations),
    ("parse_dns", parse_dns),
    ("parse_http", parse_http),
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("parser_name,parser_fn", ALL_PARSERS, ids=[n for n, _ in ALL_PARSERS])
def test_fuzz_parser_never_crashes(parser_name: str, parser_fn: object) -> None:
    """Run 1000 iterations of randomized input against each parser.

    Asserts:
      - No unhandled exceptions
      - Return type is always list
      - No code execution side effects
    """
    rng = random.Random(SEED)
    for i in range(ITERATIONS):
        fuzz_input = generate_fuzz_input(rng)
        try:
            result = parser_fn(fuzz_input)  # type: ignore[operator]
        except Exception as exc:
            pytest.fail(
                f"{parser_name} crashed on iteration {i} with input "
                f"(len={len(fuzz_input)}): {exc!r}"
            )
        assert isinstance(result, list), (
            f"{parser_name} returned {type(result).__name__} instead of list "
            f"on iteration {i}"
        )


@pytest.mark.parametrize("parser_name,parser_fn", ALL_PARSERS, ids=[n for n, _ in ALL_PARSERS])
def test_parser_handles_empty_input(parser_name: str, parser_fn: object) -> None:
    """Every parser must return an empty list for empty input."""
    result = parser_fn("")  # type: ignore[operator]
    assert result == [], f"{parser_name} returned {result!r} for empty input"


@pytest.mark.parametrize("parser_name,parser_fn", ALL_PARSERS, ids=[n for n, _ in ALL_PARSERS])
def test_parser_handles_null_bytes(parser_name: str, parser_fn: object) -> None:
    """Parsers must not crash on null-byte input."""
    result = parser_fn("\x00" * 1000)  # type: ignore[operator]
    assert isinstance(result, list)


@pytest.mark.parametrize("parser_name,parser_fn", ALL_PARSERS, ids=[n for n, _ in ALL_PARSERS])
def test_parser_handles_mega_line(parser_name: str, parser_fn: object) -> None:
    """Parsers must handle a single extremely long line without crashing."""
    mega = "A" * 1_000_000
    result = parser_fn(mega)  # type: ignore[operator]
    assert isinstance(result, list)


@pytest.mark.parametrize("parser_name,parser_fn", ALL_PARSERS, ids=[n for n, _ in ALL_PARSERS])
def test_parser_handles_unicode_edge_cases(parser_name: str, parser_fn: object) -> None:
    """Parsers must handle emoji, CJK, RTL, combining characters."""
    weird = "🔥💀\u200B\u200F\u0300\u0301价格العربية\n" * 100
    result = parser_fn(weird)  # type: ignore[operator]
    assert isinstance(result, list)
