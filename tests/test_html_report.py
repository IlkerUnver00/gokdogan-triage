from pathlib import Path

import pytest

from peregrine.html_report import render_html
from peregrine.models import (
    Capability,
    DecodedString,
    FileInfo,
    ScoreEntry,
    StringHit,
    TriageReport,
    Verdict,
)


def _file_info(**over):
    base = dict(
        path="sample.exe", size=2048, md5="0" * 32, sha1="0" * 40, sha256="a" * 64,
        imphash=None, ssdeep=None, tlsh=None, file_type="PE32 executable (GUI) x86",
        compile_timestamp=None, compile_timestamp_anomaly=None, is_dll=False,
        is_driver=False, is_signed=False, entry_point=0x1000, entry_section=".text",
    )
    base.update(over)
    return FileInfo(**base)


def test_html_is_self_contained_and_has_verdict():
    report = TriageReport(file=_file_info(), score=42, verdict=Verdict.SUSPICIOUS,
                          score_breakdown=[ScoreEntry(15, "packer detected: UPX")])
    html = render_html(report)
    assert "<style>" in html                       # inline CSS, no external deps
    assert "http://" not in html                    # no external fetches
    assert "SUSPICIOUS" in html
    assert "packer detected: UPX" in html           # rationale embedded


def test_html_escapes_malicious_strings():
    # A sample string containing markup must be neutralized in the report.
    payload = '<script>alert(1)</script>'
    report = TriageReport(
        file=_file_info(path=payload),
        strings=[StringHit(category="url", value=payload, offset=0, encoding="ascii")],
        string_stats={"url": 1},
        capabilities=[Capability("network", payload, 2, [payload], attack=[payload])],
        decoded_strings=[DecodedString(payload, "xor-0x5a", "url", 0)],
        verdict=Verdict.SUSPICIOUS, score=30,
    )
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html   # never emitted raw
    assert "&lt;script&gt;" in html                   # escaped instead


def test_html_written_to_file(tmp_path):
    report = TriageReport(file=_file_info(), verdict=Verdict.LIKELY_CLEAN)
    out = tmp_path / "r.html"
    out.write_text(render_html(report), encoding="utf-8")
    text = out.read_text(encoding="utf-8")
    assert "LIKELY CLEAN" in text
    assert text.strip().startswith("<title>")


NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


@pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")
def test_html_renders_real_report():
    from peregrine.engine import triage

    html = render_html(triage(NOTEPAD, use_yara=False))
    assert "notepad.exe" in html
    assert "MITRE ATT&amp;CK" in html or "Capabilities" in html
    # basic structural sanity: title present, reasonable size
    assert html.count("<h2>") >= 3
