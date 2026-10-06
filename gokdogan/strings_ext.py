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

# Building blocks for the command patterns. A tool name may carry ".exe" and a
# closing quote; the flag that makes an invocation suspicious must sit near
# the name. Every gap is bounded: extracted strings can be megabytes long, and
# an unbounded ".*" after a name that repeats thousands of times turns
# classification quadratic.
_EXE = r"(?:\.exe)?\"?"
_GAP = r"[^\r\n]{0,160}?"
_USER_DIR = (r"(?:\\(?:appdata|temp|programdata|users\\public)\\|"
             r"%(?:temp|tmp|appdata|localappdata|programdata|public)%)")
_PS = r"\b(?:powershell|pwsh)" + _EXE + r"\s" + _GAP

# Each alternative was priced against 2,888 benign binaries before it went in
# (scripts/benign_sweep.py): "cmd /c|/k" matches 11 of them (Git's launchers,
# forfiles), every other alternative at most 1.
_COMMAND_PATTERNS = (
    r"\bcmd" + _EXE + r"\s*/[ck]\s",
    # PowerShell accepts any unambiguous prefix of a parameter name.
    _PS + r"-e(?:c|nc?\w*)?\s+(?:[A-Za-z0-9+/]{4,}|%l?s|\{\d\})",
    _PS + r"-w(?:in\w*)?\s+(?:hidden|1)\b",
    _PS + r"-(?:ep|ex\w*)\s+(?:bypass|unrestricted)\b",
    _PS + r"-nop(?:rofile)?\b",
    r"\biex\s*[(\$]|invoke-expression\s*[(\$]|\.download(?:string|file|data)\s*\(|"
    r"new-object\s+(?:system\.)?net\.webclient|start-bitstransfer\s",
    r"(?:^|\s)-e(?:c|nc\w*)\s+[A-Za-z0-9+/]{16,}|^-e(?:c|nc|ncodedcommand)$",
    r"\b(?:add|set)-mppreference\s" + _GAP + r"-(?:exclusion\w*|disable\w*)",
    r"\bmshta" + _EXE + r"\s+[^\r\n]{0,16}(?:https?:|javascript:|vbscript:|about:)",
    r"\brundll32" + _EXE + r"\s" + _GAP + r"(?:javascript:|" + _USER_DIR + ")",
    r"\bregsvr32" + _EXE + r"\s" + _GAP + r"(?:[/-]i:|" + _USER_DIR + ")",
    r"\b[wc]script" + _EXE + r"\s" + _GAP + r"(?://e:(?:jscript|vbscript)|//b\b|" + _USER_DIR + ")",
    r"\bcertutil" + _EXE + r"\s" + _GAP + r"[-/](?:decode(?:hex)?|urlcache)\b",
    r"\bbitsadmin" + _EXE + r"\s" + _GAP + r"/(?:transfer|addfile|setnotifycmdline)\b",
    r"\bschtasks" + _EXE + r"\s" + _GAP + r"/create\b",
    r"\bsc" + _EXE + r"\s+(?:\\\\\S+\s+)?(?:create|config)\s",
    r"\bnet1?" + _EXE + r"\s+user\s" + _GAP + r"/add\b",
    r"\bnet1?" + _EXE + r"\s+localgroup\s+administrators\s" + _GAP + r"/add\b",
    r"\bwhoami" + _EXE + r"\s+/(?:all|priv|groups)\b",
    # Destroying backups and logs (also read by the anti-recovery capability).
    r"\bvssadmin" + _EXE + r"\s+(?:delete\s+shadows|resize\s+shadowstorage)",
    r"\bwmic" + _EXE + r"\s" + _GAP + r"shadowcopy\s[^\r\n]{0,40}?delete|win32_shadowcopy" + _GAP + r"delete",
    # bcdedit only to turn recovery or integrity checks off, boot into safe
    # mode or delete an entry: "/set hypervisorlaunchtype" and "/set nx" are
    # what installers do.
    r"\bbcdedit" + _EXE + r"\s" + _GAP + r"(?:[/-]set\s+(?:\{[^}\r\n]{1,40}\}\s+)?(?:recoveryenabled|"
    r"bootstatuspolicy|safeboot|testsigning|nointegritychecks|loadoptions)\b|[/-]delete(?:value)?\b)",
    r"\bwbadmin" + _EXE + r"\s+delete\s+(?:catalog|systemstatebackup|backup)",
    r"\bwevtutil" + _EXE + r"\s+(?:cl|clear-log)\b",
)

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
        # Suspicious *invocations*: how a living-off-the-land binary is called,
        # not the fact that its name appears (see "lolbin" below).
        "command",
        re.compile("|".join(f"(?:{p})" for p in _COMMAND_PATTERNS), re.I),
    ),
    (
        # A LOLBin merely named: Windows components mention rundll32 and
        # regsvr32 all the time. Shown to the analyst, not scored.
        "lolbin",
        re.compile(
            r"\b(?:rundll32|regsvr32|mshta|wscript|cscript|powershell|pwsh|schtasks|whoami|"
            r"bitsadmin|certutil|bcdedit|wmic|vssadmin|wbadmin|wevtutil)(?:\.exe)?\b",
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
