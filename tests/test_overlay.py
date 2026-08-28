from pathlib import Path

import pytest

import pefile

from gokdogan.models import OverlayInfo
from gokdogan.overlay import _type_guess, analyze_overlay, overlay_anomalies

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
has_notepad = pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")


def test_type_guess():
    assert _type_guess(b"PK\x03\x04rest") == "ZIP archive"
    assert _type_guess(b"MZ\x90\x00") == "PE/DOS executable"
    assert _type_guess(b"Rar!\x1a\x07\x00") == "RAR archive"
    assert _type_guess(b"7z\xbc\xaf\x27\x1c") == "7-Zip archive"
    assert _type_guess(b"random bytes here") == "unknown"


def test_anomalies_skip_signature_overlay():
    sig = OverlayInfo(offset=1000, size=2000, pct=5.0, entropy=7.8,
                      type_guess="DER/PKCS certificate", contains_pe=False, is_signature=True)
    assert overlay_anomalies(sig) == []


def test_anomalies_embedded_pe():
    ov = OverlayInfo(offset=1000, size=90000, pct=40.0, entropy=6.4,
                     type_guess="PE/DOS executable", contains_pe=True, is_signature=False)
    notes = overlay_anomalies(ov)
    assert any("embedded executable" in n for n in notes)


def test_anomalies_high_entropy_blob():
    ov = OverlayInfo(offset=1000, size=8000, pct=20.0, entropy=7.9,
                     type_guess="unknown", contains_pe=False, is_signature=False)
    assert any("high-entropy overlay" in n for n in overlay_anomalies(ov))


@has_notepad
def test_analyze_appended_zip_overlay(tmp_path):
    sample = tmp_path / "with_overlay.exe"
    payload = b"PK\x03\x04" + b"\x00" * 5000     # fake ZIP appended as overlay
    sample.write_bytes(NOTEPAD.read_bytes() + payload)
    pe = pefile.PE(str(sample))
    info = analyze_overlay(pe, pe.__data__)
    assert info is not None
    assert info.size >= len(payload)
    # overlay starts at our appended ZIP magic (notepad ships no overlay)
    assert info.type_guess == "ZIP archive"


@has_notepad
def test_analyze_appended_pe_overlay(tmp_path):
    sample = tmp_path / "dropper.exe"
    fake_pe = b"MZ" + b"\x90" * 3000 + b"This program cannot be run in DOS mode"
    sample.write_bytes(NOTEPAD.read_bytes() + fake_pe)
    pe = pefile.PE(str(sample))
    info = analyze_overlay(pe, pe.__data__)
    assert info is not None
    assert info.contains_pe is True
