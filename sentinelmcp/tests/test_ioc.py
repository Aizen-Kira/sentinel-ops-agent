"""Tests for IOC extraction."""

from shared.ioc import extract_iocs


def test_extract_valid_indicators() -> None:
    text = "Found evil.com and 192.168.1.1. Hash: a" * 8 + " and e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. Contact badguy@evil.com or visit https://evil.com/payload"
    iocs = extract_iocs(text)
    types = {i.type: i.value for i in iocs}

    assert types.get("domain") == "evil.com"
    assert types.get("ipv4") == "192.168.1.1"
    assert types.get("sha256") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert types.get("email") == "badguy@evil.com"
    assert types.get("url") == "https://evil.com/payload"


def test_extract_malformed_indicators_ignored() -> None:
    text = "Bad IP 999.999.999.999"
    iocs = extract_iocs(text)
    assert not any(i.type == "ipv4" and i.value == "999.999.999.999" for i in iocs)


def test_duplicate_suppression() -> None:
    text = "IP 1.1.1.1 and again 1.1.1.1"
    iocs = extract_iocs(text)
    ipv4s = [i for i in iocs if i.type == "ipv4"]
    assert len(ipv4s) == 1
    assert ipv4s[0].value == "1.1.1.1"


def test_normalization() -> None:
    text = "HASH: E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 and DOMAIN: EviL.CoM"
    iocs = extract_iocs(text)
    assert any(i.type == "sha256" and i.value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" for i in iocs)
    assert any(i.type == "domain" and i.value == "evil.com" for i in iocs)
