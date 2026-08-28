import glob
from pathlib import Path

import pefile
import pytest

from gokdogan.dotnet import analyze_dotnet

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


def _find_managed_assembly() -> str | None:
    for pat in (r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\*.dll",
                r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\*.dll"):
        hits = glob.glob(pat)
        if hits:
            return hits[0]
    return None


MANAGED = _find_managed_assembly()


@pytest.mark.skipif(MANAGED is None, reason="no .NET framework assembly available")
def test_detects_managed_assembly():
    pe = pefile.PE(MANAGED)
    info = analyze_dotnet(pe, pe.__data__)
    assert info is not None
    assert info.runtime_version                 # e.g. "2.5"
    assert "IL only" in info.flags


@pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")
def test_native_binary_is_not_dotnet():
    pe = pefile.PE(str(NOTEPAD))
    assert analyze_dotnet(pe, pe.__data__) is None


@pytest.mark.skipif(MANAGED is None, reason="no .NET framework assembly available")
def test_obfuscator_marker_detected():
    pe = pefile.PE(MANAGED)
    doctored = bytes(pe.__data__) + b"\x00ConfuserEx v1.0.0"
    info = analyze_dotnet(pe, doctored)
    assert info is not None
    assert "ConfuserEx" in info.obfuscators
