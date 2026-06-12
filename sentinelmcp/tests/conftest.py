"""Shared pytest fixtures."""
from __future__ import annotations

import pytest

from shared.models import Case, Finding, FindingStatus


@pytest.fixture()
def sample_case() -> Case:
    return Case(
        id="test-case-001",
        disk_path="/evidence/disk.E01",
        memory_path="/evidence/mem.dmp",
        pcap_path="/evidence/capture.pcap",
        description="Test case for unit tests",
    )


@pytest.fixture()
def confirmed_finding() -> Finding:
    return Finding(
        id="f-001",
        title="Confirmed Malware Execution",
        description="mimikatz.exe observed in process list",
        status=FindingStatus.CONFIRMED,
        severity="critical",
        source_tools=["vol3_pslist"],
        evidence=["PID 1234: mimikatz.exe"],
        ioc_type="hash",
        ioc_value="mimikatz.exe",
    )


@pytest.fixture()
def inferred_finding() -> Finding:
    return Finding(
        id="f-002",
        title="Possible Lateral Movement",
        description="PsExec observed connecting to internal host",
        status=FindingStatus.INFERRED,
        severity="high",
        source_tools=["tshark_conversations"],
        evidence=["Connection to 192.168.10.50:445"],
        ioc_type="ip",
        ioc_value="192.168.10.50",
    )
