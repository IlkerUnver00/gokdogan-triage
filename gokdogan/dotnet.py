"""Managed (.NET) PE analysis.

A .NET assembly carries a CLR header in the COM-descriptor data directory
(index 14). Managed binaries import almost nothing native (typically just
``mscoree!_CorExeMain``), so what they do has to be read from the .NET
metadata instead. This module reads the ``IMAGE_COR20_HEADER`` (runtime
version, flags), looks for the fingerprints of common .NET obfuscators, and,
with dnfile, reads what the code calls: members of other assemblies
(MemberRef), native functions declared with DllImport (P/Invoke), and which
of them each class's IL actually calls.
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field

import dnfile
import pefile

from .models import DotNetInfo

# dnfile logs every malformed blob it meets; a triage report is not the place.
_DNFILE_LOG = logging.getLogger("dnfile")
_DNFILE_LOG.addHandler(logging.NullHandler())
_DNFILE_LOG.propagate = False

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


# --- metadata: what managed code calls ------------------------------------

@dataclass
class ManagedReferences:
    """What an assembly's metadata and IL say it calls.

    members: lower-cased "namespace.type::member" for every member of another
    assembly it references (MemberRef), plus "...::load(byte[])" when an
    Assembly/AppDomain Load overload takes a byte array, which is how a
    payload is loaded from memory rather than from a file.
    declared / called: P/Invoke functions by lower-cased DLL, all of them and
    those some method body calls. A declaration is not a use: interop
    libraries declare functions for other assemblies to call.
    classes: per top-level class (nested classes folded in, so an async
    method's state machine counts with its method), the members and P/Invoke
    functions ("dll!name" and "name") its code calls.
    precise: the IL could be read and looks like ordinary compiled code, so
    `called` and `classes` can be trusted; otherwise rules fall back to the
    whole assembly and every declaration.
    """
    members: set[str] = field(default_factory=set)
    declared: dict[str, list[str]] = field(default_factory=dict)
    called: dict[str, list[str]] = field(default_factory=dict)
    classes: list[set[str]] = field(default_factory=list)
    precise: bool = False
    member_refs: int = 0
    bad_rows: int = 0
    error: str | None = None


# Budget for reading method bodies: large enough for any real assembly.
_MAX_CODE_BYTES = 64 * 1024 * 1024
# call, callvirt, newobj, ldftn, ldvirtftn + a MethodDef (0x06) or MemberRef (0x0A) token
_CALL_SITE = re.compile(rb"(?:\x28|\x6f|\x73|\xfe\x06|\xfe\x07)([\x00-\xff]{3})([\x06\x0a])", re.S)
# Share of method MemberRefs that no method body calls, above which the calls
# are probably resolved at runtime (ConfuserEx-style reference proxies).
_UNCALLED_LIMIT = 0.6


def read_references(data: bytes) -> ManagedReferences:
    """Read MemberRef, ImplMap and the IL call sites of a .NET assembly.

    Obfuscators rename an assembly's own types and methods, but calls into
    the framework stay references by name, so this survives most renaming.
    A malformed row is skipped and counted, not fatal.
    """
    refs = ManagedReferences()
    root = logging.getLogger()
    guard = None
    if not root.handlers:
        # dnfile also logs through the root logger, which would otherwise
        # configure console logging for the rest of the process.
        guard = logging.NullHandler()
        root.addHandler(guard)
    try:
        dn = dnfile.dnPE(data=data, fast_load=True, clr_lazy_load=True)
    except Exception as exc:
        refs.error = f"{type(exc).__name__}: {exc}"[:200]
        _drop(root, guard)
        return refs
    try:
        oversized = _tables_exceed_stream(dn)
        if oversized:
            refs.error = oversized
            return refs
        dn.parse_data_directories(directories=[_COM_DESCRIPTOR])
        tables = dn.net.mdtables if dn.net is not None else None
        if tables is None:
            refs.error = "no metadata tables"
            return refs
        _read_tables(dn, tables, refs)
    except Exception as exc:  # anything dnfile raises is a note, not a crash
        refs.error = f"{type(exc).__name__}: {exc}"[:200]
    finally:
        dn.close()
        _drop(root, guard)
    return refs


def _drop(root: logging.Logger, handler: logging.Handler | None) -> None:
    if handler is not None:
        root.removeHandler(handler)


def _tables_exceed_stream(dn) -> str | None:
    """Refuse metadata whose declared rows cannot fit in its own stream.

    dnfile builds a Python object per declared row before anything checks
    the count against the data, so a small file could otherwise declare
    millions of rows. Every row is at least 2 bytes.
    """
    directory = dn.OPTIONAL_HEADER.DATA_DIRECTORY[_COM_DESCRIPTOR]
    cor20 = dn.get_data(directory.VirtualAddress, 16)
    md_rva, md_size = struct.unpack_from("<II", cor20, 8)
    root = dn.get_data(md_rva, min(md_size, 4096))
    if root[:4] != b"BSJB":
        return "metadata root signature missing"
    version_len = struct.unpack_from("<I", root, 12)[0]
    pos = 16 + version_len + 2
    streams = struct.unpack_from("<H", root, pos)[0]
    pos += 2
    for _ in range(min(streams, 16)):
        offset, size = struct.unpack_from("<II", root, pos)
        end = root.index(b"\x00", pos + 8)
        name = root[pos + 8:end]
        pos = (end + 4) & ~3
        if name in (b"#~", b"#-"):
            header = dn.get_data(md_rva + offset, 24)
            valid = struct.unpack_from("<Q", header, 8)[0]
            count = bin(valid).count("1")
            rows = struct.unpack_from(f"<{count}I", dn.get_data(md_rva + offset + 24, 4 * count))
            if 2 * sum(rows) + 24 + 4 * count > size:
                return "declared metadata tables are larger than their stream"
            return None
    return "no metadata table stream"


def _read_tables(dn, tables, refs: ManagedReferences) -> None:
    member_names: list[str | None] = []   # MemberRef row i (1-based) -> name
    method_refs: set[int] = set()         # MemberRef rows that name methods, not fields
    for row in tables.MemberRef or []:
        refs.member_refs += 1
        name = None
        try:
            parent = row.Class.row if row.Class else None
            if parent is not None and hasattr(parent, "TypeName"):
                name = f"{parent.TypeNamespace}.{parent.TypeName}::{row.Name}".lstrip(".").lower()
                refs.members.add(name)
                raw = bytes(getattr(row.Signature, "value", b"") or b"")
                if raw[:1] != b"\x06":  # 0x06 marks a field signature
                    method_refs.add(len(member_names) + 1)
                if (parent.TypeName in ("Assembly", "AppDomain", "_AppDomain")
                        and str(row.Name).startswith("Load") and "byte[]" in _param_kinds(raw)):
                    name = f"{name}(byte[])"
                    refs.members.add(name)
        except Exception:
            refs.bad_rows += 1
        member_names.append(name)

    pinvoke: dict[int, tuple[str, str]] = {}  # MethodDef row -> (dll, function)
    for row in tables.ImplMap or []:
        try:
            scope = row.ImportScope.row if row.ImportScope else None
            dll = _dll_name(str(getattr(scope, "Name", "") or "?"))
            fn = str(row.ImportName)
            refs.declared.setdefault(dll, []).append(fn)
            target = row.MemberForwarded
            if target is not None and target.table is not None and target.table.name == "MethodDef":
                pinvoke[target.row_index] = (dll, fn)
        except Exception:
            refs.bad_rows += 1

    try:
        _read_call_sites(dn, tables, refs, member_names, method_refs, pinvoke)
    except Exception:
        refs.precise = False  # fall back to declarations and the whole assembly


def _dll_name(module: str) -> str:
    """DllImport("kernel32"), "KERNEL32.dll" and a full path are one DLL."""
    base = module.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return base if base.endswith((".dll", ".exe", ".drv", ".sys")) else base + ".dll"


def _read_call_sites(dn, tables, refs: ManagedReferences, member_names: list[str | None],
                     method_refs: set[int], pinvoke: dict[int, tuple[str, str]]) -> None:
    """Which MemberRefs and P/Invoke methods each top-level class's IL calls."""
    types = list(tables.TypeDef or [])
    enclosing: dict[int, int] = {}
    for row in tables.NestedClass or []:
        try:
            enclosing[row.NestedClass.row_index] = row.EnclosingClass.row_index
        except Exception:
            refs.bad_rows += 1

    def top(index: int) -> int:
        seen = set()
        while index in enclosing and index not in seen:
            seen.add(index)
            index = enclosing[index]
        return index

    owner: dict[int, int] = {}  # MethodDef row -> top-level TypeDef row
    for t_index, typedef in enumerate(types, 1):
        try:
            for method in typedef.MethodList or []:
                owner[method.row_index] = top(t_index)
        except Exception:
            refs.bad_rows += 1

    calls: dict[int, set[str]] = {}
    called_refs: set[int] = set()
    budget = _MAX_CODE_BYTES
    for m_index, method in enumerate(tables.MethodDef or [], 1):
        rva = getattr(method, "Rva", 0) or 0
        impl = getattr(method.struct, "ImplFlags", 0) or 0
        if not rva or impl & 0x7:
            continue  # no body, or native code (C++/CLI mixed mode), not IL
        if budget <= 0:
            refs.precise = False
            break
        try:
            code = _method_body(dn, rva)
        except Exception:
            refs.bad_rows += 1
            continue
        budget -= len(code)
        found = calls.setdefault(owner.get(m_index, 0), set())
        for match in _CALL_SITE.finditer(code):
            row = int.from_bytes(match.group(1), "little")
            if match.group(2) == b"\x0a":
                called_refs.add(row)
                if 0 < row <= len(member_names) and member_names[row - 1]:
                    found.add(member_names[row - 1])
                    if member_names[row - 1].endswith("(byte[])"):
                        found.add(member_names[row - 1][: -len("(byte[])")])
            elif row in pinvoke:
                dll, fn = pinvoke[row]
                refs.called.setdefault(dll, [])
                if fn not in refs.called[dll]:
                    refs.called[dll].append(fn)
                found.update({f"{dll}!{fn}".lower(), fn.lower()})
    refs.classes = [c for c in calls.values() if c]
    uncalled = len(method_refs - called_refs) / len(method_refs) if method_refs else 0.0
    refs.precise = budget > 0 and bool(calls) and uncalled <= _UNCALLED_LIMIT


def _method_body(dn, rva: int) -> bytes:
    """The IL bytes of the method body at rva (ECMA-335 II.25.4)."""
    first = dn.get_data(rva, 1)[0]
    if first & 0x3 == 0x2:  # tiny header: size in the upper six bits
        return dn.get_data(rva + 1, first >> 2)
    if first & 0x3 == 0x3:  # fat header
        header = dn.get_data(rva, 12)
        size_flags = struct.unpack_from("<H", header, 0)[0]
        code_size = struct.unpack_from("<I", header, 4)[0]
        return dn.get_data(rva + (size_flags >> 12) * 4, min(code_size, 16 * 1024 * 1024))
    raise ValueError("unknown method header")


# ECMA-335 II.23.2 signatures: just enough to see which parameters are byte[].
_SIMPLE_TYPES = set(range(0x01, 0x0F)) | {0x16, 0x18, 0x19, 0x1C}
_MAX_TYPE_DEPTH = 32


def _compressed(blob: bytes, pos: int) -> tuple[int, int]:
    b = blob[pos]
    if b & 0x80 == 0:
        return b, pos + 1
    if b & 0xC0 == 0x80:
        return ((b & 0x3F) << 8) | blob[pos + 1], pos + 2
    if b & 0xE0 == 0xC0:
        return int.from_bytes(bytes([b & 0x1F]) + blob[pos + 1:pos + 4], "big"), pos + 4
    raise ValueError("bad compressed integer")


def _skip_type(blob: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """Read one type at pos; return ("byte[]" or "other", position after it).

    Pointer, by-ref, modifier and array prefixes are read in a loop, so a
    long chain of them costs no recursion; generic arguments recurse, to a
    bounded depth.
    """
    if depth > _MAX_TYPE_DEPTH:
        raise ValueError("type nested too deeply")
    arrays = 0
    while True:
        et = blob[pos]
        pos += 1
        if et in (0x1F, 0x20):  # custom modifier + token
            _, pos = _compressed(blob, pos)
        elif et in (0x41, 0x45, 0x0F, 0x10):  # sentinel, pinned, pointer, by-ref
            continue
        elif et == 0x1D:  # single-dimension array of what follows
            arrays += 1
        else:
            break
    if et in _SIMPLE_TYPES:
        return ("byte[]" if arrays == 1 and et == 0x05 else "other"), pos
    if et in (0x11, 0x12, 0x13, 0x1E):  # value type, class, VAR, MVAR
        return "other", _compressed(blob, pos)[1]
    if et == 0x15:  # generic instance: kind, type token, argument count, arguments
        _, pos = _compressed(blob, pos + 1)
        count, pos = _compressed(blob, pos)
        for _ in range(count):
            pos = _skip_type(blob, pos, depth + 1)[1]
        return "other", pos
    raise ValueError(f"unsupported element type 0x{et:02x}")


def _param_kinds(blob: bytes) -> list[str]:
    """Kinds of a method signature's parameters; [] if it cannot be read."""
    try:
        conv, pos = blob[0], 1
        if conv & 0x10:  # generic method: type parameter count
            _, pos = _compressed(blob, pos)
        count, pos = _compressed(blob, pos)
        pos = _skip_type(blob, pos)[1]  # return type
        kinds = []
        for _ in range(min(count, 256)):
            kind, pos = _skip_type(blob, pos)
            kinds.append(kind)
        return kinds
    except (IndexError, ValueError, RecursionError):
        return []
