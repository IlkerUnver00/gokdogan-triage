"""PE loading and core static feature extraction.

Produces FileInfo + SectionInfo lists and structural anomaly notes.
Everything here is read-only parsing — the sample is never executed.
"""

from __future__ import annotations

import datetime
import hashlib
from pathlib import Path

import pefile

from .entropy import HIGH_ENTROPY, shannon_entropy
from .fuzzy import ssdeep_hash, tlsh_hash
from .models import FileInfo, SectionInfo

# Machine types we bother to name.
_MACHINE = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

_SUBSYSTEM = {
    1: "native",
    2: "GUI",
    3: "console",
}


class NotAPEError(ValueError):
    """Raised when the target file is not a parseable PE."""


def load_pe(path: str | Path) -> tuple[pefile.PE, bytes]:
    """Parse a PE file, returning the pefile object and raw bytes."""
    data = Path(path).read_bytes()
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        raise NotAPEError(f"{path}: not a valid PE file ({exc})") from exc
    return pe, data


def _section_name(section: pefile.SectionStructure) -> str:
    return section.Name.rstrip(b"\x00").decode("latin-1", errors="replace")


def _entry_section(pe: pefile.PE) -> str | None:
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= ep < end:
            return _section_name(section)
    return None


def _timestamp(pe: pefile.PE) -> tuple[str | None, str | None]:
    """Return (iso timestamp, anomaly note or None)."""
    ts = pe.FILE_HEADER.TimeDateStamp
    if ts == 0:
        return None, "compile timestamp is zero (deliberately wiped)"
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    iso = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if dt > now + datetime.timedelta(days=1):
        return iso, "compile timestamp is in the future"
    if dt.year < 1995:
        return iso, "compile timestamp predates the PE era"
    return iso, None


def build_file_info(path: str | Path, pe: pefile.PE, data: bytes) -> FileInfo:
    machine = _MACHINE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    bits = "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32"
    subsystem = _SUBSYSTEM.get(pe.OPTIONAL_HEADER.Subsystem, "other")
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    is_driver = pe.OPTIONAL_HEADER.Subsystem == 1 and not is_dll
    kind = "DLL" if is_dll else ("driver" if is_driver else "executable")

    try:
        imphash: str | None = pe.get_imphash() or None
    except Exception:
        imphash = None

    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    ts_iso, ts_anomaly = _timestamp(pe)

    return FileInfo(
        path=str(path),
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        imphash=imphash,
        ssdeep=ssdeep_hash(data),
        tlsh=tlsh_hash(data),
        file_type=f"{bits} {kind} ({subsystem}) {machine}",
        compile_timestamp=ts_iso,
        compile_timestamp_anomaly=ts_anomaly,
        is_dll=is_dll,
        is_driver=is_driver,
        is_signed=security_dir.VirtualAddress != 0 and security_dir.Size > 0,
        entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        entry_section=_entry_section(pe),
    )


def build_sections(pe: pefile.PE) -> list[SectionInfo]:
    sections: list[SectionInfo] = []
    for section in pe.sections:
        raw = section.get_data()
        is_exec = bool(section.Characteristics & 0x20000000)
        is_write = bool(section.Characteristics & 0x80000000)
        flags: list[str] = []
        if is_exec and is_write:
            flags.append("W+X")
        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
            flags.append("zero raw size (unpacking target)")
        ent = shannon_entropy(raw)
        if is_exec and ent >= HIGH_ENTROPY:
            flags.append("high-entropy executable section")
        sections.append(
            SectionInfo(
                name=_section_name(section),
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                entropy=round(ent, 3),
                md5=hashlib.md5(raw).hexdigest(),
                is_executable=is_exec,
                is_writable=is_write,
                flags=flags,
            )
        )
    return sections


def find_anomalies(pe: pefile.PE, data: bytes, sections: list[SectionInfo]) -> list[str]:
    """Structural oddities that legitimate compilers rarely produce."""
    anomalies: list[str] = []

    for s in sections:
        for flag in s.flags:
            anomalies.append(f"section {s.name!r}: {flag}")

    # Entry point outside any section, or in the last section (common after packing).
    entry_section = _entry_section(pe)
    if entry_section is None and pe.OPTIONAL_HEADER.AddressOfEntryPoint != 0:
        anomalies.append("entry point lies outside all sections")
    elif sections and entry_section == sections[-1].name and len(sections) > 1:
        anomalies.append(f"entry point in last section {entry_section!r}")

    # TLS callbacks run before the entry point — classic anti-analysis spot.
    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
        callbacks = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        if callbacks:
            anomalies.append("TLS callbacks present (code runs before entry point)")

    # Overlay: data appended past the last section.
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is not None:
        overlay_size = len(data) - overlay_offset
        # Signed files legitimately carry the Authenticode blob as overlay.
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        if overlay_size > max(security_dir.Size, 0) + 4096:
            pct = 100 * overlay_size // len(data)
            anomalies.append(f"overlay of {overlay_size} bytes ({pct}% of file) beyond last section")

    # Checksum mismatch (most malware doesn't bother fixing it; installers do).
    declared = pe.OPTIONAL_HEADER.CheckSum
    if declared != 0:
        try:
            if declared != pe.generate_checksum():
                anomalies.append("PE header checksum does not match computed checksum")
        except Exception:
            pass

    # No imports at all — impossible for a normal program, typical for packed ones.
    imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
    if not imports:
        anomalies.append("no import table")
    else:
        total = sum(len(entry.imports) for entry in imports)
        if total <= 5:
            anomalies.append(f"only {total} imported functions (likely resolved at runtime)")

    return anomalies


def _collect_imports(pe: pefile.PE, attr: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for entry in getattr(pe, attr, []) or []:
        dll = (entry.dll or b"?").decode("latin-1", errors="replace").lower()
        names = [
            imp.name.decode("latin-1", errors="replace")
            for imp in entry.imports
            if imp.name
        ]
        result.setdefault(dll, []).extend(names)
    return result


def imported_functions(pe: pefile.PE) -> dict[str, list[str]]:
    """Map of lowercase DLL name -> imported function names (normal imports)."""
    return _collect_imports(pe, "DIRECTORY_ENTRY_IMPORT")


def delay_imported_functions(pe: pefile.PE) -> dict[str, list[str]]:
    """Map of lowercase DLL name -> delay-loaded function names.

    Delay-load imports are resolved lazily at first use and don't appear in
    the normal import table, so APIs hidden here would otherwise escape
    capability inference.
    """
    return _collect_imports(pe, "DIRECTORY_ENTRY_DELAY_IMPORT")
