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

# @comp.id product ids -> Microsoft's internal tool name. Ids 0x00-0xB4 are
# irregular and listed in order; from VS2010 SP1 (0xB5) on, every toolset
# release repeats one fixed 18-entry block, so those are generated. Names
# follow the prodid enum documented by public Rich-header research. The build
# number stays the precise version discriminator; this names the tool.
_EARLY = """
Unknown Import0 Linker510 Cvtomf510 Linker600 Cvtomf600 Cvtres500 Utc11_Basic
Utc11_C Utc12_Basic Utc12_C Utc12_CPP AliasObj60 VisualBasic60 Masm613 Masm710
Linker511 Cvtomf511 Masm614 Linker512 Cvtomf512 Utc12_C_Std Utc12_CPP_Std
Utc12_C_Book Utc12_CPP_Book Implib700 Cvtomf700 Utc13_Basic Utc13_C Utc13_CPP
Linker610 Cvtomf610 Linker601 Cvtomf601 Utc12_1_Basic Utc12_1_C Utc12_1_CPP
Linker620 Cvtomf620 AliasObj70 Linker621 Cvtomf621 Masm615 Utc13_LTCG_C
Utc13_LTCG_CPP Masm620 ILAsm100 Utc12_2_Basic Utc12_2_C Utc12_2_CPP
Utc12_2_C_Std Utc12_2_CPP_Std Utc12_2_C_Book Utc12_2_CPP_Book Implib622
Cvtomf622 Cvtres501 Utc13_C_Std Utc13_CPP_Std Cvtpgd1300 Linker622 Linker700
Export622 Export700 Masm700 Utc13_POGO_I_C Utc13_POGO_I_CPP Utc13_POGO_O_C
Utc13_POGO_O_CPP Cvtres700 Cvtres710p Linker710p Cvtomf710p Export710p Implib710p
Masm710p Utc1310p_C Utc1310p_CPP Utc1310p_C_Std Utc1310p_CPP_Std Utc1310p_LTCG_C
Utc1310p_LTCG_CPP Utc1310p_POGO_I_C Utc1310p_POGO_I_CPP Utc1310p_POGO_O_C
Utc1310p_POGO_O_CPP Linker624 Cvtomf624 Export624 Implib624 Linker710 Cvtomf710
Export710 Implib710 Cvtres710 Utc1310_C Utc1310_CPP Utc1310_C_Std Utc1310_CPP_Std
Utc1310_LTCG_C Utc1310_LTCG_CPP Utc1310_POGO_I_C Utc1310_POGO_I_CPP
Utc1310_POGO_O_C Utc1310_POGO_O_CPP AliasObj710 AliasObj710p Cvtpgd1310
Cvtpgd1310p Utc1400_C Utc1400_CPP Utc1400_C_Std Utc1400_CPP_Std Utc1400_LTCG_C
Utc1400_LTCG_CPP Utc1400_POGO_I_C Utc1400_POGO_I_CPP Utc1400_POGO_O_C
Utc1400_POGO_O_CPP Cvtpgd1400 Linker800 Cvtomf800 Export800 Implib800 Cvtres800
Masm800 AliasObj800 PhoenixPrerelease Utc1400_CVTCIL_C Utc1400_CVTCIL_CPP
Utc1400_LTCG_MSIL Utc1500_C Utc1500_CPP Utc1500_C_Std Utc1500_CPP_Std
Utc1500_CVTCIL_C Utc1500_CVTCIL_CPP Utc1500_LTCG_C Utc1500_LTCG_CPP
Utc1500_LTCG_MSIL Utc1500_POGO_I_C Utc1500_POGO_I_CPP Utc1500_POGO_O_C
Utc1500_POGO_O_CPP Cvtpgd1500 Linker900 Export900 Implib900 Cvtres900 Masm900
AliasObj900 Resource AliasObj1000 Cvtpgd1600 Cvtres1000 Export1000 Implib1000
Linker1000 Masm1000 Phx1600_C Phx1600_CPP Phx1600_CVTCIL_C Phx1600_CVTCIL_CPP
Phx1600_LTCG_C Phx1600_LTCG_CPP Phx1600_LTCG_MSIL Phx1600_POGO_I_C
Phx1600_POGO_I_CPP Phx1600_POGO_O_C Phx1600_POGO_O_CPP Utc1600_C Utc1600_CPP
Utc1600_CVTCIL_C Utc1600_CVTCIL_CPP Utc1600_LTCG_C Utc1600_LTCG_CPP
Utc1600_LTCG_MSIL Utc1600_POGO_I_C Utc1600_POGO_I_CPP Utc1600_POGO_O_C
Utc1600_POGO_O_CPP
""".split()

_BLOCK = (
    "AliasObj{t}", "Cvtpgd{c}", "Cvtres{t}", "Export{t}", "Implib{t}", "Linker{t}",
    "Masm{t}", "Utc{c}_C", "Utc{c}_CPP", "Utc{c}_CVTCIL_C", "Utc{c}_CVTCIL_CPP",
    "Utc{c}_LTCG_C", "Utc{c}_LTCG_CPP", "Utc{c}_LTCG_MSIL", "Utc{c}_POGO_I_C",
    "Utc{c}_POGO_I_CPP", "Utc{c}_POGO_O_C", "Utc{c}_POGO_O_CPP",
)
# (first id, tools version, compiler version) of each block-layout release.
_BLOCK_RELEASES = (
    (0xB5, "1010", "1610"), (0xC7, "1100", "1700"), (0xD9, "1200", "1800"),
    (0xEB, "1210", "1810"), (0xFD, "1400", "1900"),
)
# The enum grows in release order, so an id range dates the toolset.
_ERAS = (
    (0x5A, 0x6C, "VS2003"), (0x6D, 0x82, "VS2005"), (0x83, 0x97, "VS2008"),
    (0x98, 0xC6, "VS2010"), (0xC7, 0xD8, "VS2012"), (0xD9, 0xFC, "VS2013"),
    (0xFD, 0x10E, "VS2015+"),
)


def _build_names() -> dict[int, str]:
    names = dict(enumerate(_EARLY))
    for first, tools, compiler in _BLOCK_RELEASES:
        for offset, pattern in enumerate(_BLOCK):
            names[first + offset] = pattern.format(t=tools, c=compiler)
    return names


_PRODID_NAMES = _build_names()


def _prodid_name(prod_id: int) -> str:
    if prod_id == 0x00:
        return "unmarked / padding"
    if prod_id == 0x01:
        return "import object (Import0)"
    name = _PRODID_NAMES.get(prod_id)
    if name is None:
        return f"prodid 0x{prod_id:02x}"
    for low, high, era in _ERAS:
        if low <= prod_id <= high:
            return f"{name} ({era})"
    return name


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
