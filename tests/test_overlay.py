import sys
from pathlib import Path

import pefile
import pytest

from gokdogan.models import OverlayInfo
from gokdogan.overlay import (
    MIN_HIDDEN_BYTES,
    _cert_table_slack,
    _type_guess,
    analyze_overlay,
    cert_table_padding,
    overlay_anomalies,
)

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



_HDR = bytes.fromhex("00020200")    # wRevision 0x0200, wCertificateType PKCS_SIGNED_DATA


def _win_cert(extra=b"", content=0x100, align=True):
    # One WIN_CERTIFICATE entry: 8-byte header + a DER SEQUENCE (+ optional extra bytes).
    body = bytes.fromhex("3082") + content.to_bytes(2, "big") + bytes([0xAA]) * content + extra
    entry = (8 + len(body)).to_bytes(4, "little") + _HDR + body
    return entry + bytes(-len(entry) % 8) if align else entry


def test_cert_table_slack_clean_signature():
    assert _cert_table_slack(_win_cert()) == 0


def test_cert_table_slack_counts_hidden_payload():
    assert _cert_table_slack(_win_cert(extra=bytes([0x5A]) * 4096)) == 4096


def test_cert_table_slack_counts_non_zero_alignment_bytes():
    # A 268-byte entry needs 4 alignment bytes; they must be zeros.
    assert _cert_table_slack(_win_cert(align=False) + b"AAAA") == 4


def test_padding_is_reported_even_when_overlay_is_the_signature():
    ov = OverlayInfo(offset=1000, size=14000, pct=10.0, entropy=7.9, type_guess="unknown",
                     contains_pe=False, is_signature=True, cert_padding=4096)
    notes = overlay_anomalies(ov)
    assert len(notes) == 1 and "CVE-2013-3900" in notes[0]


def test_real_signed_binary_has_no_cert_padding():
    pe = pefile.PE(sys.executable, fast_load=True)
    try:
        if not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:
            pytest.skip("interpreter binary carries no embedded signature")
        assert cert_table_padding(pe, bytes(pe.__data__)) == 0
    finally:
        pe.close()


def _entry(body, revision=0x0200, cert_type=0x0002):
    head = ((8 + len(body)).to_bytes(4, "little") + revision.to_bytes(2, "little")
            + cert_type.to_bytes(2, "little"))
    entry = head + body
    return entry + bytes(-len(entry) % 8)


_DER = bytes.fromhex("3082") + (0x100).to_bytes(2, "big") + bytes([0xAA]) * 0x100
_BER = bytes.fromhex("3080" "0402AAAA" "0000")   # indefinite SEQUENCE { OCTET STRING } EOC
_PAYLOAD = bytes([0x5A]) * 4096


def test_cert_table_slack_indefinite_length_blob_alone_is_clean():
    assert _cert_table_slack(_entry(_BER)) == 0


def test_cert_table_slack_counts_payload_after_indefinite_length_end():
    # Rewriting the header to 30 80 must not hide what follows the real end.
    assert _cert_table_slack(_entry(_BER + _PAYLOAD)) == 4096


def test_cert_table_slack_counts_every_entry_after_the_signature():
    table = _entry(_DER)
    assert _cert_table_slack(table + _entry(_PAYLOAD)) == 4096
    # a DER-looking wrapper does not make a second entry part of the signature
    assert _cert_table_slack(table + _entry(_DER + _PAYLOAD)) == len(_DER) + 4096
    assert _cert_table_slack(table + _entry(_PAYLOAD, 0x0100, 0x0001)) == 4096


def test_cert_table_slack_counts_an_unparseable_signature_body():
    body = bytes([0x30, 0x85]) + bytes([0x5A]) * 64    # length form no walker accepts
    assert _cert_table_slack(_entry(body)) == len(body)


def test_cert_table_slack_ignores_zero_fill():
    assert _cert_table_slack(_entry(_DER + bytes(64))) == 0


def test_stray_tail_bytes_stay_below_the_reporting_threshold():
    stray = _cert_table_slack(_entry(_DER + bytes([0x5C])))
    assert 0 < stray < MIN_HIDDEN_BYTES
    ov = OverlayInfo(offset=1000, size=400, pct=1.0, entropy=6.0, type_guess="unknown",
                     contains_pe=False, is_signature=True, cert_padding=stray)
    assert overlay_anomalies(ov) == []
