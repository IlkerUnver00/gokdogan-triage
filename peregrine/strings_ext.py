"""String extraction and classification.

Extracts printable ASCII and UTF-16LE strings with file offsets, then
classifies the interesting ones (IOCs, persistence artifacts, suspicious
commands) with regexes. Uncategorized strings are counted but not kept,
so reports stay small even for multi-megabyte samples.
"""

from __future__ import annotations

import re

from .models import StringHit

ASCII_PATTERN = rb"[\x20-\x7e]{%d,}"
WIDE_PATTERN = rb"(?:[\x20-\x7e]\x00){%d,}"

# Order matters: first match wins.
CLASSIFIERS: list[tuple[str, re.Pattern[str]]] = [
    ("url", re.compile(r"^(?:https?|ftp)://[^\s\"']{4,}", re.I)),
    ("ipv4", re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$")),
    ("email", re.compile(r"^[\w.+-]+@[\w-]+\.[\w.]{2,}$")),
    ("pdb", re.compile(r"\.pdb$", re.I)),
    (
        "registry",
        re.compile(r"(?:HKEY_|HKLM|HKCU|SOFTWARE\\Microsoft\\Windows\\CurrentVersion)", re.I),
    ),
    (
        "user_agent",
        re.compile(r"^Mozilla/\d|^User-Agent", re.I),
    ),
    (
        "command",
        re.compile(
            r"(?:cmd(?:\.exe)?\s*/c|powershell|"
            r"-enc(?:odedcommand)?\b|rundll32|regsvr32|mshta|wscript|cscript|"
            r"schtasks|sc\s+(?:create|config)|net\s+user|whoami|"
            r"vssadmin\s+delete|bcdedit|wevtutil\s+cl|certutil.*-decode|bitsadmin)",
            re.I,
        ),
    ),
    (
        "path",
        re.compile(r"^(?:[a-z]:\\|\\\\|%[a-z]+%\\)[^\s\"']{3,}", re.I),
    ),
    (
        "domain",
        re.compile(
            r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"(?:com|net|org|info|biz|ru|cn|top|xyz|io|onion)$",
            re.I,
        ),
    ),
]

# Strings that are near-certain noise even when a classifier matches.
_NOISE = re.compile(
    r"\b(?:microsoft|windows|schemas|w3|openssl|digicert|verisign|"
    r"globalsign|sectigo|symantec|thawte|godaddy|usertrust|comodo)\.(?:com|org|net)\b",
    re.I,
)


def extract_strings(
    data: bytes, min_length: int = 6
) -> tuple[list[tuple[str, int, str]], int]:
    """Return ([(text, offset, encoding), ...], total_string_count)."""
    found: list[tuple[str, int, str]] = []
    ascii_re = re.compile(ASCII_PATTERN % min_length)
    wide_re = re.compile(WIDE_PATTERN % min_length)

    total = 0
    for match in ascii_re.finditer(data):
        found.append((match.group().decode("ascii"), match.start(), "ascii"))
        total += 1
    for match in wide_re.finditer(data):
        text = match.group().decode("utf-16le", errors="replace")
        found.append((text, match.start(), "utf-16le"))
        total += 1
    return found, total


def classify(text: str) -> str | None:
    """Return the category for a string, or None if uninteresting."""
    stripped = text.strip()
    if _NOISE.search(stripped):
        return None
    for category, pattern in CLASSIFIERS:
        if pattern.search(stripped):
            if category == "ipv4" and not _valid_ipv4(stripped):
                continue
            return category
    return None


def _valid_ipv4(text: str) -> bool:
    host = text.split(":")[0]
    octets = host.split(".")
    if len(octets) != 4:
        return False
    try:
        values = [int(o) for o in octets]
    except ValueError:
        return False
    if any(v > 255 for v in values):
        return False
    # Version-number lookalikes: 0.0.0.0, 1.0.0.1, 6.1.7601.x etc.
    if values[0] in (0, 1, 2, 3, 4, 5, 6, 10) and values[1] == 0:
        return False
    return True


def analyze_strings(
    data: bytes, min_length: int = 6, max_per_category: int = 40
) -> tuple[list[StringHit], dict[str, int]]:
    """Extract + classify. Returns (hits, stats)."""
    raw, total = extract_strings(data, min_length)
    hits: list[StringHit] = []
    stats: dict[str, int] = {"total_strings": total}
    seen: set[tuple[str, str]] = set()

    for text, offset, encoding in raw:
        category = classify(text)
        if category is None:
            continue
        stats[category] = stats.get(category, 0) + 1
        key = (category, text)
        if key in seen:
            continue
        seen.add(key)
        if sum(1 for h in hits if h.category == category) < max_per_category:
            hits.append(
                StringHit(category=category, value=text[:300], offset=offset, encoding=encoding)
            )
    return hits, stats
