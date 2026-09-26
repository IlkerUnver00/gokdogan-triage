"""Detection guard: false-positive tuning must not lower malicious verdicts."""

import pytest
from archetypes import ARCHETYPES

from gokdogan.capabilities import infer_capabilities
from gokdogan.models import StringHit, Verdict
from gokdogan.verdict import score_report

_RANK = {Verdict.LIKELY_CLEAN: 0, Verdict.SUSPICIOUS: 1, Verdict.HIGH_RISK: 2}


@pytest.mark.parametrize("name", sorted(ARCHETYPES))
def test_malware_shapes_keep_their_verdict(name):
    factory, floor = ARCHETYPES[name]
    report = factory()
    score_report(report)
    assert _RANK[report.verdict] >= _RANK[floor], f"{name}: {report.verdict.value} {report.score}"


def _caps(*apis):
    return {c.name for c in infer_capabilities({"user32.dll": list(apis)}, [])}


def test_keylogger_imports_still_fire():
    assert "keylogging" in _caps("SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState",
                                 "MapVirtualKeyW")
    assert "keylogging" in _caps("GetAsyncKeyState", "GetKeyboardState")


def test_one_capture_mechanism_plus_key_translation_is_keylogging():
    # Polling or a hook, plus turning key codes into characters.
    assert "keylogging" in _caps("GetAsyncKeyState", "GetKeyState", "MapVirtualKeyW")
    assert "keylogging" in _caps("SetWindowsHookExW", "CallNextHookEx", "ToUnicodeEx")


def test_ordinary_gui_keyboard_use_is_not_keylogging():
    # Checking Ctrl/Shift and translating virtual keys is every GUI's business.
    assert "keylogging" not in _caps("GetKeyState", "MapVirtualKeyW", "MapVirtualKeyA")
    assert "keylogging" not in _caps("GetKeyState", "SetWindowsHookExW")
    assert "keylogging" not in _caps("GetKeyboardState", "ToUnicode")


def test_ansi_and_wide_variants_are_one_function():
    assert "keylogging" not in _caps("SetWindowsHookExA", "SetWindowsHookExW")


def test_anti_recovery_reads_exe_spelled_commands():
    hits = [StringHit("command", "bcdedit.exe /set {current} nx OptIn", 0, "ascii")]
    assert "anti-recovery" in {c.name for c in infer_capabilities({}, hits)}


def test_anti_recovery_keeps_every_command_as_evidence():
    # Reports show the first few; the verdict compares YARA matches with all.
    hits = [StringHit("command", f"wevtutil cl Log{i}", 0, "ascii") for i in range(8)]
    cap = next(c for c in infer_capabilities({}, hits) if c.name == "anti-recovery")
    assert len(cap.evidence) == 8


def test_real_debugger_checks_still_fire():
    assert "anti-debug" in _caps("CheckRemoteDebuggerPresent", "IsDebuggerPresent",
                                 "QueryPerformanceCounter")
    assert "anti-debug" in _caps("NtQueryInformationProcess", "OutputDebugStringW", "GetTickCount")


def test_msvc_runtime_imports_are_not_anti_debug():
    # The set every MSVC-built program links, whatever it does.
    assert "anti-debug" not in _caps("IsDebuggerPresent", "QueryPerformanceCounter",
                                     "GetTickCount64", "OutputDebugStringW")


def test_anti_recovery_reads_quoted_full_path_commands():
    for text in (r'"C:\Windows\System32\vssadmin.exe" delete shadows /for=D: /oldest',
                 r'"C:\Windows\System32\wbadmin.exe" delete catalog',
                 '"wevtutil.exe" cl Application'):
        hits = [StringHit("command", text, 0, "ascii")]
        assert "anti-recovery" in {c.name for c in infer_capabilities({}, hits)}, text
