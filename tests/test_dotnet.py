import glob
from pathlib import Path

import pefile
import pytest

from gokdogan.dotnet import analyze_dotnet
from gokdogan.engine import triage
from gokdogan.loader import (
    build_sections,
    data_directory,
    find_anomalies,
    is_dotnet_stub,
    is_managed,
)

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


def _find_dotnet_stub() -> str | None:
    for pat in ("C:/Windows/Microsoft.NET/Framework64/v4.0.30319/*.dll",
                "C:/Windows/Microsoft.NET/Framework/v4.0.30319/*.dll"):
        for path in glob.glob(pat)[:60]:
            try:
                pe = pefile.PE(path)
            except pefile.PEFormatError:
                continue
            try:
                if is_dotnet_stub(pe):
                    return path
            finally:
                pe.close()
    return None


DOTNET_STUB = _find_dotnet_stub()


@pytest.mark.skipif(DOTNET_STUB is None, reason="no managed assembly with a CLR-only import table")
def test_clr_bootstrap_import_is_not_a_low_import_anomaly():
    pe = pefile.PE(DOTNET_STUB)
    try:
        anomalies = find_anomalies(pe, pe.__data__, build_sections(pe))
    finally:
        pe.close()
    assert not any("likely resolved at runtime" in a for a in anomalies)


@pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")
def test_native_binary_is_not_a_dotnet_stub():
    pe = pefile.PE(str(NOTEPAD))
    try:
        assert not is_dotnet_stub(pe)
    finally:
        pe.close()


def _patched_notepad(nrva=None, cor20=False, bsjb=False) -> bytes:
    """notepad.exe with header edits made in memory (no sample is ever run)."""
    data = bytearray(NOTEPAD.read_bytes())
    pe = pefile.PE(data=bytes(data), fast_load=True)
    try:
        if nrva is not None:
            off = pe.OPTIONAL_HEADER.get_field_absolute_offset("NumberOfRvaAndSizes")
            data[off:off + 4] = nrva.to_bytes(4, "little")
        if cor20:
            rdata = next(s for s in pe.sections if s.Name.rstrip(bytes(1)) == b".rdata")
            rva, raw = rdata.VirtualAddress, rdata.PointerToRawData
            header = ((72).to_bytes(4, "little") + (2).to_bytes(2, "little")
                      + (5).to_bytes(2, "little") + (rva + 72).to_bytes(4, "little")
                      + (16).to_bytes(4, "little") + (1).to_bytes(4, "little"))  # ILONLY
            data[raw:raw + 72] = header + bytes(72 - len(header))
            data[raw + 72:raw + 76] = b"BSJB" if bsjb else b"XXXX"
            com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            at = com.get_file_offset()
            data[at:at + 8] = rva.to_bytes(4, "little") + (72).to_bytes(4, "little")
    finally:
        pe.close()
    return bytes(data)


@pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")
def test_bogus_cor20_header_does_not_make_a_native_file_managed():
    pe = pefile.PE(data=_patched_notepad(cor20=True))
    try:
        assert not is_managed(pe)
        assert not is_dotnet_stub(pe)
    finally:
        pe.close()


@pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")
def test_cor20_with_bsjb_metadata_is_managed():
    pe = pefile.PE(data=_patched_notepad(cor20=True, bsjb=True))
    try:
        assert is_managed(pe)
        assert not is_dotnet_stub(pe)   # far more imports than the CLR bootstrap
    finally:
        pe.close()


@pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")
@pytest.mark.parametrize("nrva", [13, 3])
def test_few_data_directories_do_not_crash_triage(tmp_path, nrva):
    pe = pefile.PE(data=_patched_notepad(nrva=nrva))
    try:
        assert len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) == nrva
        assert data_directory(pe, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR") is None
    finally:
        pe.close()
    sample = tmp_path / "few_dirs.exe"
    sample.write_bytes(_patched_notepad(nrva=nrva))
    assert triage(sample).verdict is not None
