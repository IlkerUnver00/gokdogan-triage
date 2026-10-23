"""Every score breakdown line carries a stable signal ID."""

import ast
import re
import sys
from pathlib import Path

import pytest
from archetypes import ARCHETYPES

from gokdogan.signals import UNKNOWN_ANOMALY, anomaly_signal, timestamp_signal
from gokdogan.verdict import score_report

ROOT = Path(__file__).resolve().parents[1]
_ID = re.compile(r"[a-z]+(\.[A-Za-z0-9_-]+)+")


@pytest.mark.parametrize("note, signal", [
    ("no import table", "anomaly.no-import-table"),
    ("only 3 imported functions (likely resolved at runtime)", "anomaly.few-imports"),
    ("section '.bss': zero raw size (uninitialised data)", "anomaly.section-zero-raw-data"),
    ("section 'UPX0': zero raw size (unpacking target)", "anomaly.section-zero-raw-exec"),
    ("section '.text': W+X", "anomaly.section-wx"),
    ("section '.text': high-entropy executable section", "anomaly.section-high-entropy-code"),
    ("entry point lies outside all sections", "anomaly.entry-outside-sections"),
    ("entry point in last section '.rsrc'", "anomaly.entry-last-section"),
    ("TLS callbacks present (code runs before entry point)", "anomaly.tls-callbacks"),
    ("PE header checksum does not match computed checksum", "anomaly.checksum-mismatch"),
    ("Rich header checksum invalid (toolchain header forged or copied)", "anomaly.rich-checksum"),
    ("Authenticode signature tampered: digest mismatch", "anomaly.signature-tampered"),
    ("resource RT_RCDATA/101: embedded PE executable", "anomaly.resource-embedded-pe"),
    ("resource RT_RCDATA/7: contains an embedded executable (DOS stub found)", "anomaly.resource-embedded-pe"),
    ("resource RT_RCDATA/7: high entropy 7.99 (packed/encrypted)", "anomaly.resource-high-entropy"),
    ("12 resources are high-entropy (packed/encrypted): RT_RCDATA/1, RT_RCDATA/2, +9 more",
     "anomaly.resource-high-entropy"),
    ("2 resources carry an embedded executable: BIN/a, BIN/b", "anomaly.resource-embedded-pe"),
    ("4096 bytes of unauthenticated data in the Authenticode certificate table (CVE-2013-3900)",
     "anomaly.cert-table-padding"),
    ("overlay contains an embedded executable (90112 bytes)", "anomaly.overlay-embedded-pe"),
    ("overlay is a zip (40000 bytes, 30% of file)", "anomaly.overlay-container"),
    ("high-entropy overlay (500000 bytes, entropy 7.98)", "anomaly.overlay-high-entropy"),
    (".NET obfuscator detected: ConfuserEx", "anomaly.dotnet-obfuscator"),
    (".NET metadata unreadable (truncated stream)", "anomaly.dotnet-metadata-unreadable"),
    (".NET metadata has 12 malformed rows", "anomaly.dotnet-metadata-malformed"),
    ("something no stage writes", UNKNOWN_ANOMALY),
])
def test_each_anomaly_note_has_its_signal(note, signal):
    assert anomaly_signal(note) == signal


@pytest.mark.parametrize("note, signal", [
    # Section and resource names are the file's own text: a name cannot pass
    # itself off as a different flag.
    ("section \".bss': zero raw size (unpacking target)\": W+X", "anomaly.section-wx"),
    ("section '.bss': zero raw size (unpacking target)': W+X", "anomaly.section-wx"),
    ("resource RT_RCDATA/x: embedded PE executable: high entropy 7.99 (packed/encrypted)",
     "anomaly.resource-high-entropy"),
    ("resource RT_RCDATA/x: high entropy 7.99 (packed/encrypted): content/type mismatch (declared RT_ICON)",
     UNKNOWN_ANOMALY),
])
def test_a_name_inside_a_note_cannot_choose_its_signal(note, signal):
    assert anomaly_signal(note) == signal


def test_timestamp_notes():
    assert timestamp_signal("compile timestamp is zero (deliberately wiped)") == "timestamp.zero"
    assert timestamp_signal("compile timestamp is in the future") == "timestamp.future"
    assert timestamp_signal("compile timestamp predates the PE era") == "timestamp.predates-pe"


@pytest.mark.parametrize("name", sorted(ARCHETYPES))
def test_every_breakdown_line_of_a_scored_report_has_a_signal(name):
    factory, _verdict = ARCHETYPES[name]
    report = factory()
    score_report(report)
    assert report.score_breakdown
    for entry in report.score_breakdown:
        assert _ID.fullmatch(entry.signal), (entry.signal, entry.reason)
        assert entry.signal != UNKNOWN_ANOMALY, entry.reason


def test_the_scorer_names_the_signal_of_every_entry_it_writes():
    """A new ScoreEntry without an ID would fall back to "" and skew a measurement."""
    tree = ast.parse((ROOT / "gokdogan" / "verdict.py").read_text(encoding="utf-8"))
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "ScoreEntry"]
    assert len(calls) > 15
    for call in calls:
        assert len(call.args) == 3 or any(k.arg == "signal" for k in call.keywords), ast.unparse(call)


def test_sweep_rows_carry_one_signal_per_breakdown_line():
    sys.path.insert(0, str(ROOT / "scripts"))
    from benign_sweep import report_fields

    factory, _verdict = ARCHETYPES["dropper"]
    report = factory()
    score_report(report)
    row = report_fields(report, use_yara=False)
    assert len(row["signals"]) == len(row["breakdown"])
    assert row["signals"] == [e.signal for e in report.score_breakdown]


def test_rows_from_an_engine_without_signals_say_so():
    sys.path.insert(0, str(ROOT / "scripts"))
    from benign_sweep import _signals

    class Old:  # an older engine's entry (--engine): points and reason only
        points, reason = 6, "anomaly: no import table"

    assert _signals([Old()]) is None


def _section(name, *, executable, raw_size=0):
    from gokdogan.loader import FLAG_UNPACK_TARGET
    from gokdogan.models import SectionInfo
    return SectionInfo(name=name, virtual_size=0x10000, raw_size=raw_size, entropy=0.0, md5="0" * 32,
                       is_executable=executable, is_writable=True,
                       flags=[FLAG_UNPACK_TARGET] if raw_size == 0 else [])


def test_an_empty_section_is_told_apart_by_its_flags_not_its_name():
    from gokdogan.loader import section_notes
    notes = section_notes([_section(".bss", executable=True),      # a packer naming its target .bss
                           _section("UPX0", executable=False),     # an empty data section named like UPX
                           _section("BSS", executable=False)])     # Delphi
    assert [anomaly_signal(n) for n in notes] == ["anomaly.section-zero-raw-exec",
                                                  "anomaly.section-zero-raw-data",
                                                  "anomaly.section-zero-raw-data"]


def test_known_packers_and_the_structural_heuristic_are_two_signals():
    from gokdogan.models import SectionInfo
    from gokdogan.packers import detect_packer

    def section(name, entropy, flags):
        return SectionInfo(name=name, virtual_size=4096, raw_size=4096, entropy=entropy, md5="0" * 32,
                           is_executable=True, is_writable=False, flags=flags)

    named = detect_packer([section("UPX0", 7.9, []), section("UPX1", 7.9, [])], import_count=4)
    guessed = detect_packer([section(".krkr", 7.8, ["high-entropy executable section"])], import_count=3)
    assert named.detected and not named.heuristic
    assert guessed.detected and guessed.heuristic
    for packer, signal in ((named, "packing.packer-named"), (guessed, "packing.packer-heuristic")):
        factory, _verdict = ARCHETYPES["packed_loader"]
        report = factory()
        report.packer = packer
        score_report(report)
        assert signal in [e.signal for e in report.score_breakdown]


def test_a_capability_signal_names_the_evidence_behind_it_not_its_severity():
    from gokdogan.capabilities import MANAGED_RULES, infer_capabilities
    from gokdogan.models import StringHit

    def signal_of(caps, name):
        factory, _verdict = ARCHETYPES["stealer"]
        report = factory()
        report.capabilities = caps
        score_report(report)
        return next(e.signal for e in report.score_breakdown if e.reason == f"capability: {name}")

    native = {"ws2_32.dll": ["WSAStartup", "socket", "connect", "send", "recv", "getaddrinfo"]}
    managed = next(r for r in MANAGED_RULES if r.name == "network").apis
    assert signal_of(infer_capabilities(native, []), "network") == "capability.network.imports"
    assert signal_of(infer_capabilities({}, [], managed=set(managed)), "network") == "capability.network.managed"
    assert signal_of(infer_capabilities(native, [], managed=set(managed)), "network") ==         "capability.network.imports+managed"

    run_key = StringHit(category="registry", value=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        offset=0, encoding="ascii")
    registry = {"advapi32.dll": ["RegSetValueExW", "RegCreateKeyExW"]}
    assert signal_of(infer_capabilities(registry, []), "persistence-registry") ==         "capability.persistence-registry.imports"
    assert signal_of(infer_capabilities({}, [run_key]), "persistence-registry") ==         "capability.persistence-registry.strings"
    assert signal_of(infer_capabilities(registry, [run_key]), "persistence-registry") ==         "capability.persistence-registry.imports+strings"
