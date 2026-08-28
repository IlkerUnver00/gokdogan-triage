"""Managed (.NET) PE detection.

A .NET assembly carries a CLR header in the COM-descriptor data directory
(index 14). Detecting it matters for triage: managed binaries import almost
nothing native (typically just ``mscoree!_CorExeMain``), so the import-based
capability analysis is largely blind to them — the report should say so
rather than call a stealer "no capabilities". This module reads the
``IMAGE_COR20_HEADER`` for the runtime version and flags, and looks for the
fingerprints of common .NET obfuscators.
"""

from __future__ import annotations

import struct

import pefile

from .models import DotNetInfo

_COM_DESCRIPTOR = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]

# COR20 header flags.
_FLAGS = [
    (0x00001, "IL only"),
    (0x00002, "32-bit required"),
    (0x00008, "strong-name signed"),
    (0x00010, "native entry point"),
    (0x10000, "track debug data"),
    (0x20000, "32-bit preferred"),
]

# Obfuscator fingerprints (byte marker -> name). Cheap, string-based.
_OBFUSCATORS = [
    (b"ConfuserEx", "ConfuserEx"),
    (b"Confuser.Core", "Confuser"),
    (b"DotfuscatorAttribute", "Dotfuscator"),
    (b"SmartAssembly", "SmartAssembly"),
    (b"\x00.NET Reactor", ".NET Reactor"),
    (b"Babel.ObfuscatorAttribute", "Babel"),
    (b"Eazfuscator", "Eazfuscator.NET"),
    (b"NineRays", "Agile.NET"),
    (b"Obfuscar", "Obfuscar"),
]


def analyze_dotnet(pe: pefile.PE, data: bytes) -> DotNetInfo | None:
    """Return DotNetInfo if the PE is a managed assembly, else None."""
    try:
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_COM_DESCRIPTOR]
    except (AttributeError, IndexError):
        return None
    if not directory.VirtualAddress or directory.Size < 72:
        return None

    try:
        cor20 = pe.get_data(directory.VirtualAddress, 72)
    except Exception:  # pragma: no cover - defensive
        return None
    if len(cor20) < 20:
        return None

    # IMAGE_COR20_HEADER: cb(4) major(2) minor(2) metadata(8) flags(4) entry(4)
    _cb, major, minor = struct.unpack_from("<IHH", cor20, 0)
    flags, entry_token = struct.unpack_from("<II", cor20, 16)

    flag_names = [name for bit, name in _FLAGS if flags & bit]
    obfuscators = sorted({name for marker, name in _OBFUSCATORS if marker in data})

    return DotNetInfo(
        runtime_version=f"{major}.{minor}",
        flags=flag_names,
        entry_point_token=f"0x{entry_token:08x}",
        obfuscators=obfuscators,
    )
