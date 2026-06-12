"""IOC Extraction Framework (FEATURE-011)."""

import re

from shared.models import IOC

# Pre-compiled regex patterns
_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6_RE = re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.IGNORECASE)
_DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b', re.IGNORECASE)
_URL_RE = re.compile(r'\b(?:https?|ftp|smb)://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', re.IGNORECASE)
_MD5_RE = re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE)
_SHA1_RE = re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE)
_SHA256_RE = re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE)
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE)


def extract_iocs(text: str) -> list[IOC]:
    """Extract IOCs from text deterministically using regex."""
    if not text:
        return []

    iocs = []
    seen = set()

    def add_match(match: str, ioc_type: str, confidence: float) -> None:
        # Normalize
        val = match.strip()
        if ioc_type in ("md5", "sha1", "sha256"):
            val = val.lower()
        elif ioc_type in ("domain", "email", "url"):
            val = val.lower()

        # Basic invalid IP filtering
        if ioc_type == "ipv4":
            parts = val.split(".")
            if len(parts) == 4 and any(int(p) > 255 for p in parts):
                return

        key = (ioc_type, val)
        if key not in seen:
            seen.add(key)
            iocs.append(IOC(
                type=ioc_type,
                value=val,
                source_tool="extracted",
                confidence=confidence
            ))

    for m in _URL_RE.finditer(text):
        add_match(m.group(), "url", 0.9)
    for m in _EMAIL_RE.finditer(text):
        add_match(m.group(), "email", 0.9)
    for m in _IPV4_RE.finditer(text):
        add_match(m.group(), "ipv4", 0.8)
    for m in _IPV6_RE.finditer(text):
        add_match(m.group(), "ipv6", 0.8)
    for m in _SHA256_RE.finditer(text):
        add_match(m.group(), "sha256", 1.0)
    for m in _SHA1_RE.finditer(text):
        add_match(m.group(), "sha1", 1.0)
    for m in _MD5_RE.finditer(text):
        add_match(m.group(), "md5", 1.0)

    # Domains last, avoiding overlap with URLs/Emails if possible (simplified logic)
    for m in _DOMAIN_RE.finditer(text):
        val = m.group()
        # skip if purely numeric (handled by ipv4) or matches url/email closely
        if re.match(r'^[\d\.]+$', val):
            continue
        add_match(val, "domain", 0.7)

    return iocs
