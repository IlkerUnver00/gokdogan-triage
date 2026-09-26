"""The .NET stage: metadata references, P/Invoke, IL call sites and the managed rules."""

import logging
import struct
from pathlib import Path

import pefile
import pytest

from gokdogan.attack import techniques_for
from gokdogan.capabilities import infer_capabilities
from gokdogan.dotnet import _param_kinds, read_references
from gokdogan.engine import triage, triage_bytes
from gokdogan.models import StringHit

SYSTEM_NET = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Net.dll")
NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
needs_net = pytest.mark.skipif(not SYSTEM_NET.exists(), reason=".NET Framework 4 not installed")


def test_signature_reader_finds_byte_array_parameters():
    # Load(byte[]): default call, 1 param, returns a class, takes SZARRAY of U1.
    assert _param_kinds(bytes.fromhex("0001127d1d05")) == ["byte[]"]
    assert _param_kinds(bytes.fromhex("00011283850e")) == ["other"]           # Load(string)
    assert _param_kinds(bytes.fromhex("0002127d1d051d05")) == ["byte[]", "byte[]"]
    assert _param_kinds(bytes.fromhex("0001127d1d1d05")) == ["other"]         # byte[][]
    assert _param_kinds(bytes.fromhex("00011283851283")) == []                # truncated: unknown
    assert _param_kinds(b"") == []


def test_deeply_nested_signatures_neither_recurse_nor_fail_the_read():
    pointers = bytes.fromhex("0001127d") + b"\x0f" * 5000 + b"\x08"   # int32 behind 5000 pointers
    assert _param_kinds(pointers) == ["other"]
    generic = bytes.fromhex("0001127d") + bytes.fromhex("1512" + "7d01") * 200 + b"\x08"
    assert _param_kinds(generic) == []                                  # too deep: unknown, no crash


@needs_net
def test_references_are_read_from_a_framework_assembly():
    refs = read_references(SYSTEM_NET.read_bytes())
    assert refs.error is None and refs.bad_rows == 0
    assert refs.member_refs > 100
    assert "LoadLibraryExW" in refs.declared["kernel32.dll"]
    assert refs.precise and refs.classes
    # what the IL calls is a subset of what is declared
    for dll, fns in refs.called.items():
        assert set(fns) <= set(refs.declared[dll])


MIXED_MODE = Path(r"C:\Program Files\Internet Explorer\iediagcmd.exe")  # C++/CLI


@pytest.mark.skipif(not MIXED_MODE.exists(), reason="iediagcmd.exe not available")
def test_native_method_bodies_of_mixed_mode_assemblies_are_not_malformed_rows():
    refs = read_references(MIXED_MODE.read_bytes())
    assert refs.error is None and refs.bad_rows == 0 and refs.precise


@pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")
def test_non_dotnet_input_is_a_note_not_a_crash():
    assert read_references(NOTEPAD.read_bytes()).error
    assert read_references(b"MZ" + bytes(100)).error


def _tables_header_offset(data: bytes) -> int:
    pe = pefile.PE(data=data, fast_load=True)
    cor20 = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    md_rva = struct.unpack_from("<I", pe.get_data(cor20.VirtualAddress, 16), 8)[0]
    root = pe.get_offset_from_rva(md_rva)
    version_len = struct.unpack_from("<I", data, root + 12)[0]
    pos = root + 16 + version_len + 4
    while True:
        offset = struct.unpack_from("<I", data, pos)[0]
        end = data.index(b"\x00", pos + 8)
        if data[pos + 8:end] in (b"#~", b"#-"):
            return root + offset
        pos = (end + 4) & ~3


@needs_net
def test_declared_tables_larger_than_their_stream_are_refused():
    data = bytearray(SYSTEM_NET.read_bytes())
    rows = _tables_header_offset(bytes(data)) + 24      # first row count (the Module table)
    struct.pack_into("<I", data, rows, 0x7FFFFFFF)
    refs = read_references(bytes(data))
    assert refs.error == "declared metadata tables are larger than their stream"
    report = triage_bytes(bytes(data), use_yara=False)
    assert any(a.startswith(".NET metadata unreadable") for a in report.anomalies)


@needs_net
def test_dnfile_warnings_do_not_configure_logging():
    root = logging.getLogger()
    before = list(root.handlers)
    data = bytearray(SYSTEM_NET.read_bytes())
    struct.pack_into("<I", data, _tables_header_offset(bytes(data)) + 24, 0x7FFFFFFF)
    read_references(bytes(data))
    read_references(SYSTEM_NET.read_bytes())
    assert root.handlers == before


@needs_net
def test_triage_reports_pinvoke_and_member_refs():
    report = triage(SYSTEM_NET, verify_signature=False)
    d = report.dotnet
    assert d.member_refs > 100 and d.pinvoke_count >= len(d.pinvoke) > 0
    assert d.pinvoke_called is not None and d.pinvoke_called <= d.pinvoke_count
    assert report.verdict.value == "LIKELY_CLEAN"


def _caps(*members, pinvoke=None, imports=None, strings=(), classes=None):
    managed = {m.lower() for m in members}
    return {c.name: c for c in infer_capabilities(imports or {}, list(strings), managed=managed,
                                                  pinvoke=pinvoke, managed_classes=classes)}


def test_download_then_run_is_download_execute():
    caps = _caps("System.Net.WebClient::DownloadData", "System.Diagnostics.Process::Start")
    assert caps["download-execute"].severity == 3 and caps["download-execute"].source == "managed"
    # two ways to download are not a way to run
    assert "download-execute" not in _caps("System.Net.WebClient::DownloadData",
                                           "System.Net.WebClient::DownloadFile")
    # HttpClient's modern shape and VB's My namespace count too
    assert "download-execute" in _caps("System.Net.Http.HttpContent::ReadAsByteArrayAsync",
                                       "Microsoft.VisualBasic.Interaction::Shell")


def test_two_part_rules_need_both_parts_in_one_class_when_the_il_is_read():
    download, run = "system.net.webclient::downloaddata", "system.diagnostics.process::start"
    members = (download, run)
    assert "download-execute" not in _caps(*members, classes=[{download}, {run}])
    assert "download-execute" in _caps(*members, classes=[{download, run}])
    assert "download-execute" in _caps(*members, classes=None)          # IL unreadable: whole assembly


def test_loading_an_assembly_from_memory_is_reflective_loading():
    invoke = "System.Reflection.MethodBase::Invoke"
    for load in ("System.Reflection.Assembly::Load(byte[])", "System._AppDomain::Load(byte[])",
                 "System.Runtime.Loader.AssemblyLoadContext::LoadFromStream"):
        assert "reflective-loading" in _caps(load, invoke), load
    # a plugin loader that loads by name is not
    assert "reflective-loading" not in _caps("System.Reflection.Assembly::Load", invoke)


def test_managed_surveillance_and_exfiltration_tags():
    caps = _caps("System.Drawing.Graphics::CopyFromScreen", "System.Windows.Forms.Clipboard::GetText",
                 "System.Net.Mail.SmtpClient::Send",
                 "System.Security.Cryptography.ProtectedData::Unprotect")
    assert {"screen-capture", "clipboard-access", "email-exfiltration", "credential-access"} <= set(caps)
    assert techniques_for("email-exfiltration") and techniques_for("credential-access")
    assert "credential-access" in _caps(pinvoke={"crypt32.dll": ["CryptUnprotectData"]})


def test_shellcode_runner_is_matched_by_function_name_whatever_the_dll_spelling():
    gdffp = "System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer"
    for dll, fn in (("kernel32.dll", "VirtualAlloc"), ("kernelbase.dll", "VirtualAlloc"),
                    ("kernel32.dll", "VirtualProtect"), ("ntdll.dll", "NtAllocateVirtualMemory")):
        assert _caps(gdffp, pinvoke={dll: [fn]})["shellcode-execution"].severity == 3, (dll, fn)


def test_bare_pinvoke_names_match_the_native_rules():
    # DllImport without ExactSpelling names SetWindowsHookEx; the runtime adds A or W.
    caps = infer_capabilities({"user32.dll": ["SetWindowsHookEx", "ToUnicodeEx"],
                               "urlmon.dll": ["URLDownloadToFile"]}, [])
    assert {"keylogging", "download-execute"} <= {c.name for c in caps}


def test_native_and_managed_evidence_for_one_behaviour_is_one_capability():
    caps = infer_capabilities({"ws2_32.dll": ["connect", "send"]}, [],
                              managed={"system.net.webclient::downloadstring"})
    network = [c for c in caps if c.name == "network"]
    assert len(network) == 1
    assert "connect" in network[0].evidence and "system.net.webclient::downloadstring" in network[0].evidence


def test_run_key_strings_upgrade_managed_registry_writes():
    run_key = StringHit("registry", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, "utf-16le")
    caps = _caps("Microsoft.Win32.RegistryKey::SetValue", strings=[run_key])
    assert caps["persistence-registry"].severity == 3
