import sys
from pathlib import Path

import pytest

from gokdogan import signature
from gokdogan.signature import verify

KERNEL32 = Path(r"C:\Windows\System32\kernel32.dll")
is_windows = sys.platform == "win32"


def test_status_map_covers_common_codes():
    # the codes an analyst cares about are all mapped
    for code in (0x00000000, 0x800B0100, 0x80096010, 0x800B0101, 0x800B0109, 0x800B010C):
        assert code in signature._TRUST_CODES


def test_non_windows_degrades(monkeypatch):
    monkeypatch.setattr(signature, "_IS_WINDOWS", False)
    info = verify("whatever.exe")
    assert info.status == "unavailable"
    assert info.verified is None


@pytest.mark.skipif(not is_windows or not KERNEL32.exists(),
                    reason="needs Windows + kernel32.dll")
def test_valid_microsoft_binary():
    info = verify(str(KERNEL32))
    assert info.status == "valid"
    assert info.verified is True
    assert info.present is True
    assert "Microsoft" in info.signer          # real leaf publisher, not the intermediate CA


@pytest.mark.skipif(not is_windows, reason="needs Windows")
def test_tampered_binary_detected(tmp_path):
    if not KERNEL32.exists():
        pytest.skip("kernel32.dll not available")
    tampered = tmp_path / "tampered.dll"
    data = bytearray(KERNEL32.read_bytes())
    data[0x400] ^= 0xFF                          # break the signed digest
    tampered.write_bytes(data)
    info = verify(str(tampered))
    assert info.status == "tampered"
    assert info.verified is False


@pytest.mark.skipif(not is_windows, reason="needs Windows")
def test_unsigned_or_catalog_binary(tmp_path):
    # a bare file with no embedded Authenticode -> unsigned
    plain = tmp_path / "plain.exe"
    plain.write_bytes(b"MZ" + b"\x00" * 512)
    info = verify(str(plain))
    assert info.status in ("unsigned", "invalid")
    assert info.present is False or info.status == "invalid"
