from pathlib import Path

import pefile
import pytest

from gokdogan.capabilities import infer_capabilities
from gokdogan.exports import parse_exports
from gokdogan.loader import delay_imported_functions
from gokdogan.models import ExportInfo

KERNEL32 = Path(r"C:\Windows\System32\kernel32.dll")
MMC = Path(r"C:\Windows\System32\mmc.exe")

has_kernel32 = pytest.mark.skipif(not KERNEL32.exists(), reason="kernel32.dll not available")
has_mmc = pytest.mark.skipif(not MMC.exists(), reason="mmc.exe not available")


class _FakeSym:
    def __init__(self, name=None, ordinal=0, forwarder=None):
        self.name = name
        self.ordinal = ordinal
        self.forwarder = forwarder


class _FakeExportDir:
    def __init__(self, name, symbols):
        self.name = name
        self.symbols = symbols


class _FakePE:
    def __init__(self, export_dir):
        if export_dir is not None:
            self.DIRECTORY_ENTRY_EXPORT = export_dir


def test_no_export_directory_returns_none():
    assert parse_exports(_FakePE(None), "x.dll") is None


def test_reflective_loader_export_detected():
    d = _FakeExportDir(b"payload.dll", [
        _FakeSym(name=b"ReflectiveLoader", ordinal=1),
        _FakeSym(name=b"Start", ordinal=2),
    ])
    info = parse_exports(_FakePE(d), "payload.dll")
    assert info.total == 2
    assert info.named == 2
    assert "reflective-loading" in info.suspicious


def test_regsvr32_and_ordinal_counting():
    d = _FakeExportDir(b"evil.dll", [
        _FakeSym(name=b"DllRegisterServer", ordinal=1),
        _FakeSym(name=None, ordinal=2),          # ordinal-only
        _FakeSym(name=None, ordinal=3),
    ])
    info = parse_exports(_FakePE(d), "evil.dll")
    assert info.ordinal_only == 2
    assert info.named == 1
    assert "regsvr32-loadable" in info.suspicious


def test_name_mismatch_flag():
    d = _FakeExportDir(b"realname.dll", [_FakeSym(name=b"Foo", ordinal=1)])
    assert parse_exports(_FakePE(d), "svchost.dll").name_mismatch is True
    assert parse_exports(_FakePE(d), "REALNAME.DLL").name_mismatch is False


def test_forwarder_recorded():
    d = _FakeExportDir(b"a.dll", [
        _FakeSym(name=b"Foo", ordinal=1, forwarder=b"NTDLL.RtlFoo"),
    ])
    info = parse_exports(_FakePE(d), "a.dll")
    assert info.forwarders == ["Foo -> NTDLL.RtlFoo"]


def test_export_capability_from_info():
    info = ExportInfo(dll_name="beacon.dll", total=1, named=1, ordinal_only=0,
                      suspicious=["reflective-loading"])
    caps = infer_capabilities({}, [], None, info)
    refl = next((c for c in caps if c.name == "reflective-loading"), None)
    assert refl is not None
    assert refl.severity == 3
    assert "T1620" in refl.attack


@has_kernel32
def test_kernel32_exports_and_forwarders_real():
    pe = pefile.PE(str(KERNEL32), fast_load=False)
    info = parse_exports(pe, "kernel32.dll")
    assert info is not None
    assert info.dll_name.lower() == "kernel32.dll"
    assert info.total > 1000
    assert info.forwarders            # kernel32 forwards many to ntdll
    assert info.suspicious == []      # a clean system DLL
    assert info.name_mismatch is False


@has_mmc
def test_mmc_has_delay_imports_real():
    pe = pefile.PE(str(MMC), fast_load=False)
    delay = delay_imported_functions(pe)
    assert delay                      # mmc delay-loads several DLLs
    # delay imports are a separate set from normal imports
    assert isinstance(delay, dict)
    assert all(isinstance(v, list) for v in delay.values())
