from pathlib import Path

import pefile
import pytest

from gokdogan.rich import _prodid_name, _rotl32, parse_rich_header

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
has_notepad = pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")


def test_rotl32_wraps():
    assert _rotl32(0x00000001, 4) == 0x00000010
    assert _rotl32(0x80000000, 1) == 0x00000001   # top bit rotates around
    assert _rotl32(0x12345678, 0) == 0x12345678
    assert _rotl32(0x12345678, 32) == 0x12345678   # bits masked to 0


def test_prodid_name_known_and_fallback():
    assert _prodid_name(0x5A) == "Linker710 (VS2003)"
    assert _prodid_name(0x5D) == "Implib710 (VS2003)"   # an import library, not a linker
    assert _prodid_name(0x1234) == "prodid 0x1234"


def test_prodid_names_match_known_toolchains():
    # Spot checks against the documented prodid enum, including the VS2015+
    # ids every modern MSVC binary carries.
    assert _prodid_name(0x91) == "Linker900 (VS2008)"
    assert _prodid_name(0x93) == "Implib900 (VS2008)"
    assert _prodid_name(0xAB) == "Utc1600_CPP (VS2010)"
    assert _prodid_name(0xD3) == "Utc1700_LTCG_CPP (VS2012)"
    assert _prodid_name(0xE1) == "Utc1800_CPP (VS2013)"
    assert _prodid_name(0xE3) == "Utc1800_CVTCIL_CPP (VS2013)"
    assert _prodid_name(0x102) == "Linker1400 (VS2015+)"
    assert _prodid_name(0x104) == "Utc1900_C (VS2015+)"
    assert _prodid_name(0x105) == "Utc1900_CPP (VS2015+)"
    assert _prodid_name(0x10E) == "Utc1900_POGO_O_CPP (VS2015+)"


def test_prodid_table_is_contiguous():
    from gokdogan.rich import _PRODID_NAMES
    assert sorted(_PRODID_NAMES) == list(range(0x10F))


class _FakePE:
    def __init__(self, rich):
        self._rich = rich

    def parse_rich_header(self):
        return self._rich


def test_none_when_no_rich_header():
    assert parse_rich_header(_FakePE(None), b"") is None


def test_none_when_values_empty():
    fake = _FakePE({"clear_data": b"DanS", "values": [], "checksum": 0, "raw_data": b""})
    assert parse_rich_header(fake, b"") is None


@has_notepad
def test_notepad_rich_header_is_valid():
    pe = pefile.PE(str(NOTEPAD), fast_load=True)
    data = pe.__data__
    header = parse_rich_header(pe, bytes(data))
    assert header is not None
    assert len(header.hash) == 32
    assert header.entries
    assert header.checksum_valid is True
    # every entry decodes to sane fields
    for e in header.entries:
        assert e.prod_id >= 0 and e.count >= 0
        assert e.tool


@has_notepad
def test_rich_hash_is_deterministic():
    pe1 = pefile.PE(str(NOTEPAD), fast_load=True)
    pe2 = pefile.PE(str(NOTEPAD), fast_load=True)
    h1 = parse_rich_header(pe1, bytes(pe1.__data__))
    h2 = parse_rich_header(pe2, bytes(pe2.__data__))
    assert h1.hash == h2.hash


@has_notepad
def test_tampered_dos_stub_invalidates_checksum():
    original = NOTEPAD.read_bytes()
    tampered = bytearray(original)
    # Flip a byte in the DOS stub message region (well before e_lfanew's use,
    # inside the checksum-covered range) — a real header would no longer match.
    tampered[0x50] ^= 0xFF
    pe = pefile.PE(data=bytes(tampered), fast_load=True)
    header = parse_rich_header(pe, bytes(tampered))
    assert header is not None
    assert header.checksum_valid is False
