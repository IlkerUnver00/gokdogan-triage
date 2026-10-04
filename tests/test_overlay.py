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


@pytest.mark.skipif(sys.platform != "win32", reason="the interpreter is a PE file only on Windows")
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


# --- the payload: the overlay without its certificate table -----------------

class _FakePE:
    """Just what analyze_overlay asks of a parsed PE: where the overlay starts
    and the certificate table's data directory. No PE image is built."""

    def __init__(self, overlay_offset, table_offset=0, table_size=0):
        from types import SimpleNamespace
        dirs = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(16)]
        dirs[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]] = SimpleNamespace(
            VirtualAddress=table_offset, Size=table_size)
        self.OPTIONAL_HEADER = SimpleNamespace(DATA_DIRECTORY=dirs)
        self._offset = overlay_offset

    def get_overlay_data_start_offset(self):
        return self._offset


IMAGE = b"I" * 4096


def _noise(n: int) -> bytes:
    import hashlib
    out = b""
    while len(out) < n:
        out += hashlib.sha256(len(out).to_bytes(8, "little")).digest()
    return out[:n]


def _der(n: int) -> bytes:
    """A well-formed signature blob of n bytes (its contents are noise)."""
    return bytes.fromhex("3082") + n.to_bytes(2, "big") + _noise(n)


def _signed(before: bytes, table: bytes, after: bytes = b""):
    data = IMAGE + before + table + after
    return _FakePE(len(IMAGE), len(IMAGE) + len(before), len(table)), data


def test_a_few_bytes_beside_the_signature_are_not_a_payload():
    # Signed files with alignment slack before the table once read as a
    # 7.9-entropy "high-entropy overlay": the table itself was measured.
    info = analyze_overlay(*_signed(b"\x00" * 24, _entry(_der(15000))))
    assert info.payload_size == 24 and not info.is_signature and info.entropy < 7.2
    assert overlay_anomalies(info) == []
    exact = analyze_overlay(*_signed(b"", _entry(_der(15000))))
    assert exact.is_signature and exact.payload_size == 0


def test_a_payload_beside_the_table_is_still_judged():
    after = analyze_overlay(*_signed(b"", _entry(_der(4000)), _noise(300000)))
    assert after.payload_size == 300000 and after.entropy > 7.9
    assert overlay_anomalies(after) == ["high-entropy overlay (300000 bytes, entropy 8.00)"]
    zipped = analyze_overlay(*_signed(b"\x00" * 3, _entry(_der(4000)), b"PK\x03\x04" + _noise(5000)))
    assert zipped.type_guess == "ZIP archive"           # found after the table, not hidden by slack
    dropped = analyze_overlay(*_signed(b"\x00" * 8, _entry(_der(4000)), b"MZ" + b"\x00" * 5000))
    assert dropped.contains_pe and not dropped.is_signature


def test_an_executable_hidden_inside_the_table_is_still_reported():
    hidden = _entry(_DER + b"MZ" + b"\x00" * 64 + b"This program cannot be run in DOS mode" + b"\x00" * 900)
    info = analyze_overlay(*_signed(b"", hidden))
    assert info.contains_pe and not info.is_signature
    assert any("embedded executable" in n for n in overlay_anomalies(info))


def test_a_table_that_runs_past_the_end_hides_nothing():
    appended = b"MZ" + b"\x00" * 64 + b"This program cannot be run in DOS mode" + b"\x00" * 2000
    data = IMAGE + appended
    forged = _FakePE(len(IMAGE), len(IMAGE), len(appended) + 100000)
    info = analyze_overlay(forged, data)
    assert info.payload_size == len(appended) and info.contains_pe and not info.is_signature


def test_payloads_under_a_kilobyte_say_nothing_about_type_or_entropy():
    def note(size, **kw):
        return overlay_anomalies(OverlayInfo(offset=1000, size=size + 15000, pct=5.0, contains_pe=False,
                                             is_signature=False, payload_size=size, **kw))
    assert note(1023, entropy=7.9, type_guess="unknown") == []
    assert note(1023, entropy=1.0, type_guess="ZIP archive") == []
    assert note(1024, entropy=7.9, type_guess="unknown") != []
    assert note(1024, entropy=1.0, type_guess="ZIP archive") != []


def test_a_few_forged_bytes_are_not_a_certificate_table():
    # A 2-byte "table" at the start of the overlay used to cut "MZ" off an
    # appended executable; a table must at least open like a WIN_CERTIFICATE.
    appended = b"MZ" + b"\x00" * 3000
    forged = _FakePE(len(IMAGE), len(IMAGE), 2)
    info = analyze_overlay(forged, IMAGE + appended)
    assert info.contains_pe and info.payload_size == len(appended)


def test_alignment_bytes_before_the_table_still_make_it_just_the_signature():
    info = analyze_overlay(*_signed(b"\x00" * 8, _entry(_der(4000))))
    assert info.is_signature and info.type_guess == "unknown" and overlay_anomalies(info) == []


def test_reports_show_the_bytes_outside_the_signature():
    from gokdogan.html_report import _beside_signature
    from gokdogan.models import FileInfo, TriageReport
    from gokdogan.summary import _overlay
    slack = OverlayInfo(offset=1000, size=15096, pct=13.1, entropy=3.1, type_guess="ZIP archive",
                        contains_pe=False, is_signature=False, payload_size=24)
    assert _beside_signature(slack) == ", 24 outside the signature"
    info = FileInfo(path="x", size=1, md5="", sha1="", sha256="", imphash=None, ssdeep=None, tlsh=None,
                    file_type="", compile_timestamp=None, compile_timestamp_anomaly=None, is_dll=True,
                    is_driver=False, is_signed=True, entry_point=0, entry_section=None)
    assert _overlay(TriageReport(file=info, overlay=slack)) == ""            # slack has no type
    zipped = OverlayInfo(offset=1000, size=9000, pct=40.0, entropy=7.9, type_guess="ZIP archive",
                         contains_pe=False, is_signature=False, payload_size=5000)
    assert _overlay(TriageReport(file=info, overlay=zipped)) == "ZIP archive"
