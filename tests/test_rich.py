from pathlib import Path

import pytest

import pefile

from peregrine import rich
from peregrine.rich import _prodid_name, _rotl32, parse_rich_header

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
has_notepad = pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")


def test_rotl32_wraps():
    assert _rotl32(0x00000001, 4) == 0x00000010
    assert _rotl32(0x80000000, 1) == 0x00000001   # top bit rotates around
    assert _rotl32(0x12345678, 0) == 0x12345678
    assert _rotl32(0x12345678, 32) == 0x12345678   # bits masked to 0


def test_prodid_name_known_and_fallback():
    assert "linker" in _prodid_name(0x5D).lower()
    assert _prodid_name(0x1234) == "prodid 0x1234"


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
