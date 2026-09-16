"""Smoke tests for the console renderer — the primary output path."""
import io
from pathlib import Path

import pytest

from gokdogan.engine import triage
from gokdogan.report import render_console, render_json

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
has_notepad = pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")


def _render(report) -> str:
    buf = io.StringIO()
    render_console(report, buf)
    return buf.getvalue()


@has_notepad
def test_render_console_clean_binary():
    out = _render(triage(NOTEPAD, use_yara=False))
    assert "gokdogan triage report" in out
    assert "Verdict" in out
    assert "LIKELY CLEAN" in out or "LIKELY_CLEAN" in out
    for section in ("File", "Sections", "Capabilities"):
        assert section in out


@has_notepad
def test_render_console_rich_malicious_report(tmp_path):
    # a synthetic sample that lights up many sections (never executed)
    data = bytearray(NOTEPAD.read_bytes())
    data += b"\xff" * 8 + bytes(b ^ 0x5A for b in b"http://45.9.1.2/gate.php") + b"\xff" * 8
    data += b"\xff" * 8 + bytes(b ^ 0x5A for b in
                                b"https://discord.com/api/webhooks/1/AbC-def") + b"\xff" * 8
    data += b"\x00VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    data += b"vssadmin delete shadows /all /quiet\x00"
    sample = tmp_path / "evil.exe"
    sample.write_bytes(data)

    report = triage(sample, use_yara=False)
    out = _render(report)
    assert report.verdict.value == "HIGH_RISK"
    # the malicious-signal sections must render
    for section in ("Capabilities", "MITRE ATT&CK", "Extracted config",
                    "Recovered (encoded) strings", "Verdict"):
        assert section in out, f"missing section: {section}"
    assert "anti-recovery" in out  # from the vssadmin command string
    assert "discord.com/api/webhooks" in out


@has_notepad
def test_render_console_survives_cp1254_stream():
    # the _SafeStream fallback must not raise when the stream can't encode the
    # box-drawing / em-dash characters (legacy Windows codepage).
    report = triage(NOTEPAD, use_yara=False)
    # a stream whose encoding cannot represent the box-drawing / em-dash chars
    buf = io.TextIOWrapper(io.BytesIO(), encoding="cp1254", errors="strict")
    render_console(report, buf)   # _SafeStream must transliterate, not raise
    buf.flush()


def test_render_json_is_valid():
    import json
    fake = triage(NOTEPAD, use_yara=False) if NOTEPAD.exists() else None
    if fake is None:
        pytest.skip("notepad.exe not available")
    assert json.loads(render_json(fake))["file"]["sha256"]
