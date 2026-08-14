"""Rich header parsing and hashing.

The Rich header is an undocumented block MSVC's linker inserts between the
DOS stub and the PE header. It records the toolchain — a list of
``@comp.id`` entries, one per contributing tool (linker, C/C++ compiler,
assembler, resource compiler), each carrying a product id, a build number
and how many object files that tool produced.

Two triage signals come out of it:

  * **rich_hash** — MD5 of the decoded header. Far more specific than
    imphash: it fingerprints the exact build environment, so samples
    compiled on the same actor's machine cluster together even when their
    imports differ.
  * **checksum validity** — the header stores a checksum derived from the
    DOS header and the comp.id entries. A mismatch means the header was
    copied from another binary or forged (a deliberate anti-clustering /
    false-flag move), which is itself suspicious.

Non-MSVC binaries (MinGW, Go, Delphi, packed stubs) usually have no Rich
header at all; that is normal and simply yields ``None``.
"""

from __future__ import annotations

import hashlib

from .models import RichEntry, RichHeader

# Compact map of common product ids to a human label. The build number is
# the precise version discriminator; this just gives the tool family so a
# reader isn't staring at bare integers. Unknown ids fall back to "prodid N".
_PRODID_NAMES: dict[int, str] = {
    0x00: "unmarked / padding",
    0x01: "import object",
    0x02: "linker 5.10",
    0x06: "cvtomf 5.10",
    0x0A: "linker 6.00",
    0x0F: "cvtomf 7.00",
    0x5D: "linker 7.00 (VS2002)",
    0x5E: "export 7.00",
    0x5F: "import 7.00",
    0x60: "C/C++ 13.00 (VS2002)",
    0x6D: "C/C++ 13.10 (VS2003)",
    0x83: "C/C++ 14.00 (VS2005)",
    0x91: "linker 8.00 (VS2005)",
    0x9A: "C/C++ 15.00 (VS2008)",
    0x9B: "linker 9.00 (VS2008)",
    0xAA: "C/C++ 16.00 (VS2010)",
    0xAB: "linker 10.00 (VS2010)",
    0xC9: "C/C++ 17.00 (VS2012)",
    0xCA: "linker 11.00 (VS2012)",
    0xDB: "C/C++ 18.00 (VS2013)",
    0xDC: "linker 12.00 (VS2013)",
    0xE0: "C/C++ 19.00 (VS2015)",
    0xE1: "linker 14.00 (VS2015)",
}


def _prodid_name(prod_id: int) -> str:
    return _PRODID_NAMES.get(prod_id, f"prodid 0x{prod_id:02x}")


def _rotl32(value: int, bits: int) -> int:
    bits &= 31
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def _compute_checksum(data: bytes, rich_offset: int, entries: list[tuple[int, int]]) -> int:
    """Recompute the Rich header checksum (a.k.a. the XOR key).

    Sum of the DOS header bytes (with e_lfanew zeroed) each rotated left by
    its offset, plus each comp_id rotated left by its use count, seeded with
    the header's own file offset. Matches MSVC's linker exactly.
    """
    checksum = rich_offset
    for i in range(rich_offset):
        if 0x3C <= i <= 0x3F:  # e_lfanew is not covered by the checksum
            continue
        checksum = (checksum + _rotl32(data[i], i)) & 0xFFFFFFFF
    for comp_id, count in entries:
        checksum = (checksum + _rotl32(comp_id, count)) & 0xFFFFFFFF
    return checksum


def parse_rich_header(pe, data: bytes) -> RichHeader | None:
    """Return a RichHeader for the sample, or None if there isn't one."""
    try:
        rich = pe.parse_rich_header()
    except Exception:  # pragma: no cover - defensive against odd headers
        rich = None
    if not rich:
        return None

    clear = rich.get("clear_data") or b""
    values = rich.get("values") or []
    if not clear or len(values) < 2:
        return None

    pairs = [(values[i], values[i + 1]) for i in range(0, len(values) - 1, 2)]
    entries = [
        RichEntry(
            prod_id=comp_id >> 16,
            build=comp_id & 0xFFFF,
            count=count,
            tool=_prodid_name(comp_id >> 16),
        )
        for comp_id, count in pairs
    ]

    stored = rich.get("checksum")
    checksum_valid: bool | None = None
    raw = rich.get("raw_data")
    if stored is not None and raw:
        offset = bytes(data).find(bytes(raw))
        if offset != -1:
            checksum_valid = _compute_checksum(bytes(data), offset, pairs) == stored

    return RichHeader(
        hash=hashlib.md5(clear).hexdigest(),
        xor_key=f"0x{stored:08x}" if stored is not None else "-",
        entries=entries,
        checksum_valid=checksum_valid,
    )
