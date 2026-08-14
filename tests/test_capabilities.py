from peregrine.capabilities import infer_capabilities
from peregrine.models import StringHit


def _names(caps):
    return {c.name for c in caps}


def test_injection_trio_detected():
    imports = {
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    }
    caps = infer_capabilities(imports, [])
    assert "process-injection" in _names(caps)
    injection = next(c for c in caps if c.name == "process-injection")
    assert injection.severity == 3
    assert "WriteProcessMemory" in injection.evidence


def test_single_api_does_not_trigger_multi_hit_rule():
    caps = infer_capabilities({"kernel32.dll": ["VirtualAllocEx"]}, [])
    assert "process-injection" not in _names(caps)


def test_network_needs_two_hits():
    assert "network" not in _names(infer_capabilities({"ws2_32.dll": ["socket"]}, []))
    caps = infer_capabilities({"ws2_32.dll": ["socket", "connect", "send"]}, [])
    assert "network" in _names(caps)


def test_case_insensitive_matching():
    caps = infer_capabilities({"USER32.DLL": ["GetAsyncKeyState", "SetWindowsHookExW"]}, [])
    assert "keylogging" in _names(caps)


def test_run_key_string_upgrades_registry_persistence():
    imports = {"advapi32.dll": ["RegSetValueExW", "RegCreateKeyExW"]}
    hit = StringHit(
        category="registry",
        value=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        offset=0,
        encoding="ascii",
    )
    caps = infer_capabilities(imports, [hit])
    persistence = next(c for c in caps if c.name == "persistence-registry")
    assert persistence.severity == 3


def test_anti_recovery_from_command_strings():
    hit = StringHit(
        category="command",
        value="vssadmin delete shadows /all /quiet",
        offset=0,
        encoding="ascii",
    )
    caps = infer_capabilities({}, [hit])
    assert "anti-recovery" in _names(caps)


def test_benign_imports_stay_quiet():
    imports = {"kernel32.dll": ["GetLastError", "CloseHandle", "Sleep", "lstrlenW"]}
    assert infer_capabilities(imports, []) == []
