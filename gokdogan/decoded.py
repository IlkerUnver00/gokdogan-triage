"""FLOSS-lite: recovery of encoded / obfuscated strings.

Malware routinely hides its IOCs from a plain ``strings`` pass by encoding
them — most commonly a single-byte XOR, ADD, or bit-rotation, or a Base64
blob. Full FLOSS emulates code to recover stack strings; this lite version
skips emulation and instead does a fast, precise brute force:

  1. Take a small set of high-value plaintext *anchors* ("http://", ".exe",
     "cmd", "HKEY_", "This program cannot be run", ...).
  2. For every candidate key (XOR/ADD 1..255, ROL 1..7) encode each anchor
     and search the raw bytes for it. A hit means "this key is live" — and
     because the anchors are 5+ bytes, coincidental hits are astronomically
     unlikely, so there are almost no false keys.
  3. Only for those live keys, decode the whole image (via a C-speed
     ``bytes.translate`` table) and extract + classify the strings.

Plus a Base64 pass that decodes long base64 runs and keeps the ones that
resolve to an IOC, a command, or an embedded PE.

The result is high-signal by construction: a benign file almost never
contains an XOR-encoded URL, so anything recovered here is worth a look.
"""

from __future__ import annotations

import base64
import re

from .models import DecodedString
from .strings_ext import _NOISE, classify

# Plaintext markers that betray an encoded IOC / command / executable.
# Kept >= 6 bytes so a coincidental encoded match is astronomically unlikely
# (short markers like ".dll" would produce phantom keys on clean binaries).
_ANCHORS: tuple[bytes, ...] = (
    b"http://", b"https://", b"ftp://",
    b"cmd.exe", b"powershell", b"rundll32", b"regsvr32", b"schtasks",
    b"vssadmin", b"HKEY_CURRENT", b"HKEY_LOCAL", b"SOFTWARE\\",
    b"CurrentVersion", b"Mozilla/", b"User-Agent",
    b"This program cannot be run",
)

_MAX_LIVE_KEYS = 24

# ADD/XOR use keys 1..255; ROL uses bit counts 1..7. Key 0 / rot 0 == plaintext.
_BYTE_KEYS = range(1, 256)
_ROL_KEYS = range(1, 8)

_BASE64_RE = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
# >= 32 hex chars (16 bytes). Runs of 32+ *ASCII* hex digits in a binary are
# strings, not incidental bytes, so this stays low-noise.
_HEX_RE = re.compile(rb"(?:[0-9a-fA-F]{2}){16,}")
_MAX_RESULTS = 80


def _rol8(byte: int, count: int) -> int:
    count &= 7
    return ((byte << count) | (byte >> (8 - count))) & 0xFF


def _xor_table(key: int) -> bytes:
    return bytes(i ^ key for i in range(256))


def _add_decode_table(key: int) -> bytes:
    # encoded = (plain + key) & 0xff  ->  plain = (encoded - key) & 0xff
    return bytes((i - key) & 0xFF for i in range(256))


def _rol_decode_table(count: int) -> bytes:
    # encoded = rol(plain, count)  ->  plain = rol(encoded, 8 - count)
    return bytes(_rol8(i, 8 - count) for i in range(256))


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for c in data if 32 <= c < 127 or c in (9, 10, 13))
    return good / len(data)


def _adjacent_xor(data: bytes) -> bytes:
    """Byte-wise data[i] ^ data[i-1] — key-invariant under single-byte XOR.

    Computed at C speed via a single big-integer XOR of the buffer against
    itself shifted by one byte.
    """
    if len(data) < 2:
        return b""
    high = int.from_bytes(data[:-1], "big")
    low = int.from_bytes(data[1:], "big")
    return (high ^ low).to_bytes(len(data) - 1, "big")


def _adjacent_add(data: bytes) -> bytes:
    """Byte-wise (data[i] - data[i-1]) mod 256 — key-invariant under +key."""
    return bytes((data[i + 1] - data[i]) & 0xFF for i in range(len(data) - 1))


def _find_matches(haystack_adj: bytes, needle_adj: bytes):
    """Yield every start offset where needle_adj occurs in haystack_adj."""
    start = 0
    while True:
        idx = haystack_adj.find(needle_adj, start)
        if idx == -1:
            return
        yield idx
        start = idx + 1


def _find_live_keys(data: bytes) -> list[tuple[str, int]]:
    """Return (method, key) pairs whose encoded anchor appears in the data.

    XOR and ADD keys are found in one pass each via the adjacency transform
    (no 255-key loop); ROL is a cheap 7-count brute since rotation has no
    linear adjacency invariant.
    """
    if len(data) < 8:
        return []

    live: set[tuple[str, int]] = set()
    adj_xor = _adjacent_xor(data)
    adj_add = _adjacent_add(data)

    for anchor in _ANCHORS:
        if len(anchor) < 2:
            continue
        for idx in _find_matches(adj_xor, _adjacent_xor(anchor)):
            live.add(("xor", data[idx] ^ anchor[0]))
            if len(live) >= _MAX_LIVE_KEYS:
                break
        for idx in _find_matches(adj_add, _adjacent_add(anchor)):
            live.add(("add", (data[idx] - anchor[0]) & 0xFF))
            if len(live) >= _MAX_LIVE_KEYS:
                break

    for count in _ROL_KEYS:
        if any(bytes(_rol8(b, count) for b in a) in data for a in _ANCHORS):
            live.add(("rol", count))

    live.discard(("xor", 0))
    live.discard(("add", 0))
    return sorted(live)


def _decode(data: bytes, method: str, key: int) -> bytes:
    if method == "xor":
        return data.translate(_xor_table(key))
    if method == "add":
        return data.translate(_add_decode_table(key))
    return data.translate(_rol_decode_table(key))


def _label(method: str, key: int) -> str:
    return f"{method}-0x{key:02x}" if method != "rol" else f"rol-{key}"


# Printable bytes map to "p", everything else to "n", so run bounds are two
# C-speed find() calls instead of a Python loop over the run.
_RUN_MASK = bytes(0x70 if 0x20 <= b < 0x7F else 0x6E for b in range(256))
# Anchors whose category must start where the anchor starts (a URL, a user
# agent): the text after one is read as a single short token.
_PREFIX_ANCHORS = (b"http://", b"https://", b"ftp://", b"Mozilla/", b"User-Agent")
_TOKEN_MAX = 300
# Command and registry patterns match anywhere in a run, so if the whole run
# did not classify, only a noise domain elsewhere in it can have hidden one.
# Such a run is re-read in overlapping windows around the anchors.
_WINDOW, _STRIDE = 512, 256
# Hostile input can hold millions of anchors; past this much classified text
# per call the rest of the buffer is skipped, so triage always finishes.
_CLASSIFY_BUDGET = 8_000_000


def _printable_run(mask: bytes, idx: int) -> tuple[int, int]:
    """Bounds of the printable-ASCII run containing position ``idx``."""
    end = mask.find(b"n", idx)
    return mask.rfind(b"n", 0, idx) + 1, len(mask) if end == -1 else end


class _Budget:
    """Characters of text left to classify in one recover_encoded_strings call."""

    def __init__(self, chars: int) -> None:
        self.chars = chars

    def classify(self, text: str) -> str | None:
        self.chars -= len(text)
        return classify(text)


def _harvest(decoded: bytes, method: str, key: int, min_len: int,
             seen: set[str], out: list[DecodedString], budget: _Budget) -> None:
    """Pull classified strings out of a decoded buffer, anchored at each hit.

    We locate each anchor inside the decoded stream and take the printable
    run around it. Classification is tried on the whole run first, then on
    the text at the anchor — so an encoded ``http://...`` still resolves
    even when non-IOC text decoded just before it. A run that holds many
    anchors (hostile input can repeat "powershell" thousands of times) is
    measured and classified once, not once per anchor.
    """
    label = _label(method, key)
    mask = decoded.translate(_RUN_MASK)
    run_category: dict[tuple[int, int], str | None] = {}
    run_noisy: dict[tuple[int, int], bool] = {}
    window_category: dict[str, str | None] = {}
    emitted: set[tuple[int, int]] = set()
    for anchor in _ANCHORS:
        pos = 0
        bounds = (0, 0)
        last_window = -_WINDOW
        while budget.chars > 0:
            idx = decoded.find(anchor, pos)
            if idx == -1:
                break
            pos = idx + 1
            if not bounds[0] <= idx < bounds[1]:
                bounds = _printable_run(mask, idx)
                last_window = -_WINDOW
            start, end = bounds
            if end - start < min_len:
                continue
            if bounds not in run_category:
                run = decoded[start:end].decode("latin-1")
                run_category[bounds] = budget.classify(run)
                run_noisy[bounds] = bool(_NOISE.search(run))
            category = run_category[bounds]
            if category is not None:
                if bounds in emitted:
                    continue
                emitted.add(bounds)
                value = decoded[start:end].decode("latin-1")
            elif anchor in _PREFIX_ANCHORS:
                value = decoded[idx:min(end, idx + _TOKEN_MAX)].decode("latin-1").split(" ")[0]
                category = budget.classify(value)
            elif run_noisy[bounds] and idx >= last_window + _STRIDE:
                last_window = idx
                value = decoded[idx:min(end, idx + _WINDOW)].decode("latin-1")
                if value not in window_category:
                    window_category[value] = budget.classify(value)
                category = window_category[value]
            else:
                continue
            if category is None or value in seen:
                continue
            seen.add(value)
            out.append(DecodedString(value=value[:300], encoding=label, category=category, offset=idx))
            if len(out) >= _MAX_RESULTS:
                return


def _consider_blob(decoded: bytes, encoding: str, offset: int,
                   seen: set[str], out: list[DecodedString]) -> None:
    """Keep a decoded base64/hex blob only if it's an IOC/command or a PE."""
    if len(decoded) < 4:
        return
    if decoded[:2] == b"MZ":
        value = f"<embedded PE, {len(decoded)} bytes>"
        if value not in seen:
            seen.add(value)
            out.append(DecodedString(value=value, encoding=encoding,
                                     category="embedded-pe", offset=offset))
        return
    if _printable_ratio(decoded) < 0.8:
        return
    text = decoded.decode("latin-1", errors="replace")
    category = classify(text)
    if category is None or text in seen:
        return
    seen.add(text)
    out.append(DecodedString(value=text[:300], encoding=encoding,
                             category=category, offset=offset))


def _harvest_base64(data: bytes, seen: set[str], out: list[DecodedString]) -> None:
    for match in _BASE64_RE.finditer(data):
        if len(out) >= _MAX_RESULTS:
            return
        try:
            decoded = base64.b64decode(match.group(), validate=True)
        except Exception:
            continue
        _consider_blob(decoded, "base64", match.start(), seen, out)


def _harvest_hex(data: bytes, seen: set[str], out: list[DecodedString]) -> None:
    for match in _HEX_RE.finditer(data):
        if len(out) >= _MAX_RESULTS:
            return
        try:
            decoded = bytes.fromhex(match.group().decode("ascii"))
        except ValueError:
            continue
        _consider_blob(decoded, "hex", match.start(), seen, out)


def recover_encoded_strings(data: bytes, min_len: int = 5) -> list[DecodedString]:
    """Recover XOR/ADD/ROL-, Base64- and hex-encoded strings of interest."""
    out: list[DecodedString] = []
    seen: set[str] = set()
    budget = _Budget(_CLASSIFY_BUDGET)

    for method, key in _find_live_keys(data):
        if len(out) >= _MAX_RESULTS or budget.chars <= 0:
            break
        decoded = _decode(data, method, key)
        _harvest(decoded, method, key, min_len, seen, out, budget)

    _harvest_base64(data, seen, out)
    _harvest_hex(data, seen, out)
    return out
