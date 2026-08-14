"""End-to-end tests against real, known-benign Windows binaries."""

import json
from pathlib import Path

import pytest

from peregrine.engine import NotAPEError, triage
from peregrine.report import render_json

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
KERNEL32 = Path(r"C:\Windows\System32\kernel32.dll")

pytestmark = pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")


@pytest.mark.skipif(not KERNEL32.exists(), reason="kernel32.dll not available")
def test_triage_dll_reports_exports_cleanly():
    report = triage(KERNEL32)
    assert report.exports is not None
    assert report.exports.total > 1000
    assert report.exports.dll_name.lower() == "kernel32.dll"
    # a stock system DLL must not trip export-based capabilities
    assert not any(
        c.name in ("reflective-loading", "regsvr32-loadable", "service-dll")
        for c in report.capabilities
    )
    assert report.verdict.value in ("LIKELY_CLEAN", "SUSPICIOUS")


def test_triage_notepad_runs_clean():
    report = triage(NOTEPAD)
    assert report.file.sha256
    assert report.file.imphash
    # ssdeep is a hard dep in the test env; a real binary must hash.
    from peregrine import fuzzy
    if fuzzy.HAVE_SSDEEP:
        assert report.file.ssdeep
    assert len(report.sections) > 2
    assert 0.0 < report.overall_entropy < 8.0
    assert not report.packer.detected
    # notepad is MSVC-built: Rich header present, valid, and hashed.
    assert report.rich is not None
    assert report.rich.checksum_valid is True
    assert len(report.rich.hash) == 32
    # notepad ships resources (icons/version) but is not a dropper.
    assert len(report.resources) > 3
    assert not any(c.name == "embedded-executable" for c in report.capabilities)
    # A clean binary should not yield a flood of phantom "recovered" strings.
    assert len(report.decoded_strings) < 5
    # A stock Microsoft binary must never come out HIGH_RISK.
    assert report.verdict.value in ("LIKELY_CLEAN", "SUSPICIOUS")


def test_json_report_round_trips():
    report = triage(NOTEPAD)
    parsed = json.loads(render_json(report))
    assert parsed["file"]["sha256"] == report.file.sha256
    assert parsed["verdict"] == report.verdict.value
    assert isinstance(parsed["sections"], list)
    assert isinstance(parsed["attack"], list)


def test_attack_summary_is_consistent_with_capabilities():
    report = triage(NOTEPAD)
    summary_ids = {t.id for t in report.attack}
    for cap in report.capabilities:
        for tid in cap.attack:
            assert tid in summary_ids, f"{cap.name} technique {tid} missing from summary"
    # Every summary technique names a real tactic and source.
    for tech in report.attack:
        assert tech.tactic
        assert tech.sources


def test_non_pe_raises(tmp_path):
    bogus = tmp_path / "not_a_pe.exe"
    bogus.write_bytes(b"#!/bin/sh\necho hello\n")
    with pytest.raises(NotAPEError):
        triage(bogus)


def test_yara_disabled_still_reports():
    report = triage(NOTEPAD, use_yara=False)
    assert report.yara == []
    assert report.yara_error is None
