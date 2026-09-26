from pathlib import Path

import pefile
import pytest

from gokdogan.capabilities import infer_capabilities
from gokdogan.models import ResourceInfo
from gokdogan.resources import (
    _classify_resource,
    _looks_like_pe,
    resource_anomalies,
    walk_resources,
)

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
has_notepad = pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")


def _fake_pe_bytes() -> bytes:
    """Smallest buffer that satisfies _looks_like_pe: MZ .. e_lfanew .. 'PE\\0\\0'."""
    buf = bytearray(b"MZ" + b"\x00" * 0x3E)   # up to 0x40
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")
    buf += b"PE\x00\x00" + b"\x00" * 16
    return bytes(buf)


def test_looks_like_pe_positive():
    assert _looks_like_pe(_fake_pe_bytes())


def test_looks_like_pe_negatives():
    assert not _looks_like_pe(b"MZ" + b"\x00" * 4)          # too short
    assert not _looks_like_pe(b"not an exe at all........")  # no MZ
    bad = bytearray(_fake_pe_bytes())
    bad[0x40:0x44] = b"XXXX"                                 # MZ but no PE sig
    assert not _looks_like_pe(bytes(bad))


def test_classify_flags_embedded_pe():
    flags = _classify_resource("RT_ICON", _fake_pe_bytes(), entropy=3.0)
    assert any("embedded PE" in f for f in flags)
    # inert declared type + executable content => mismatch called out
    assert any("mismatch" in f for f in flags)


def test_classify_flags_high_entropy():
    flags = _classify_resource("RT_RCDATA", b"\x00", entropy=7.9)
    assert any("high entropy" in f for f in flags)


def test_classify_clean_icon_is_unflagged():
    assert _classify_resource("RT_ICON", b"(\x00\x00\x00 icon data", entropy=4.0) == []


def test_high_entropy_png_icon_is_not_flagged():
    # Modern icons embed compressed PNG (~7.9 bits/byte) — must NOT be
    # mistaken for a packed payload just because entropy is high.
    assert _classify_resource("RT_ICON", b"\x89PNG\r\n\x1a\n" + b"\xff" * 100, entropy=7.93) == []


def test_high_entropy_rcdata_is_flagged():
    flags = _classify_resource("RT_RCDATA", b"\xff" * 4096, entropy=7.9)
    assert any("high entropy" in f for f in flags)


def test_resource_anomalies_surfaces_flags():
    res = [
        ResourceInfo("RT_RCDATA", "101", "9/1", 4096, 7.95, "a" * 64,
                     flags=["embedded PE executable"]),
        ResourceInfo("RT_ICON", "1", "9/1", 500, 3.0, "b" * 64, flags=[]),
    ]
    anomalies = resource_anomalies(res)
    assert len(anomalies) == 1
    assert "embedded PE" in anomalies[0]


def test_embedded_resource_yields_dropper_capability():
    res = [ResourceInfo("RT_RCDATA", "BIN", "9/1", 90000, 7.99, "c" * 64,
                        flags=["embedded PE executable"])]
    caps = infer_capabilities({}, [], res)
    dropper = next((c for c in caps if c.name == "embedded-executable"), None)
    assert dropper is not None
    assert dropper.severity == 3
    assert "T1027.009" in dropper.attack


@has_notepad
def test_walk_notepad_has_resources_and_no_false_embedded_pe():
    pe = pefile.PE(str(NOTEPAD), fast_load=False)
    resources = walk_resources(pe)
    assert len(resources) > 3
    # A stock binary must not be mistaken for a dropper.
    for r in resources:
        assert not any("embedded PE" in f for f in r.flags)
    # entropy and hashes are populated
    assert all(len(r.sha256) == 64 for r in resources)


def _high_entropy(type_name, data):
    return any("high entropy" in f for f in _classify_resource(type_name, data, entropy=7.95))


def test_compressed_media_is_recognised_by_content_not_type():
    # MFC/Office file PNGs under a custom "PNG" type rather than RT_ICON.
    png = bytes.fromhex("89504e470d0a1a0a 0000000d49484452") + bytes(64)
    assert not _high_entropy("PNG", png)
    riff = b"RIFF" + (4 + 64).to_bytes(4, "little") + b"WAVE" + bytes(64)
    assert not _high_entropy("WAVE", riff)
    # an encrypted blob with no known header is still flagged
    assert _high_entropy("PNG", bytes(64))


def test_pasted_media_magic_does_not_hide_an_encrypted_blob():
    blob = bytes(range(256)) * 4
    assert _high_entropy("RT_RCDATA", bytes.fromhex("89504e470d0a1a0a") + blob)  # no IHDR chunk
    assert _high_entropy("RT_RCDATA", b"RIFF" + bytes(4) + b"WAVE" + blob)       # size field wrong
    assert _high_entropy("RT_RCDATA", bytes.fromhex("ffd8ff") + blob)             # no JPEG end marker
    assert _high_entropy("RT_RCDATA", b"ID3" + blob)                              # no ID3 version


def test_compressed_archives_in_resources_stay_flagged():
    # A zipped or gzipped second stage is the dropper shape, not an image.
    for magic in (b"PK\x03\x04", bytes.fromhex("1f8b08"), b"MSCF", bytes.fromhex("377abcaf271c"),
                  b"BZh9", bytes.fromhex("fd377a585a00")):
        assert _high_entropy("RT_RCDATA", magic + bytes(64)), magic


def test_many_high_entropy_resources_are_one_anomaly():
    res = [ResourceInfo("RT_RCDATA", str(i), "9/1", 4096, 7.95, "a" * 64,
                        flags=["high entropy 7.95 (packed/encrypted)"]) for i in range(40)]
    anomalies = resource_anomalies(res)
    assert len(anomalies) == 1
    assert anomalies[0].startswith("40 resources are high-entropy")
    assert "+37 more" in anomalies[0]
