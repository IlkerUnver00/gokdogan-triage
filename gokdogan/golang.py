"""Go program analysis.

A Go binary links its own runtime and imports the same handful of kernel32
functions as every other Go binary, so its import table and imphash say
almost nothing about what it does. Two structures the Go linker always
writes do:

- the build info (``\\xff Go buildinf:``, Go 1.13+): toolchain version, main
  package and module, dependency modules and build settings;
- the function table (pclntab), which the runtime needs for stack traces
  and garbage collection and therefore survives ``-ldflags "-s -w"``: the
  name of every function, hence every package linked in, the Windows API
  wrappers among them, and the source file names.

Both are validated before they are believed. Git for Windows' C programs
carry the build-info magic as a string, so a header must sit 16-byte aligned
in a writable data section with this PE's pointer size; a Go program carried
as data by another file has a function table, but nothing in the host points
at it, so a table counts only when something in this image's own data does;
``confirmed`` when that is the program's runtime.firstmoduledata. Every offset and count is bounds-checked and every search
capped: the stage never raises and stays well under a second on hostile input.

This stage only describes the file. Nothing here is scored yet.
"""

from __future__ import annotations

import re
import struct
from collections import Counter
from dataclasses import dataclass
from itertools import pairwise

import pefile

from .models import GoInfo, GoModule

# ---------------------------------------------------------------- limits
MAX_SECTIONS = 96                 # pefile's own sanity bound is far higher
MAX_PCLNTAB_FILE = 128 << 20      # larger files: build info and build ID only
BUILDINFO_MAGIC = b"\xff Go buildinf:"
INFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")   # cmd/go module-info framing
INFO_END = bytes.fromhex("f932433186182072008242104116d8f2")
MAX_BI_CANDIDATES = 64            # decoy headers examined before giving up
MAX_BI_SCAN = 16 << 20            # bytes of one data section searched for the header
MAX_VERSION = 128
MAX_MODINFO = 1 << 20
MAX_MODINFO_LINES = 20_000
MAX_DEPS = 500
MAX_SETTINGS = 64
MAX_SETTING_VALUE = 512
BUILD_ID_WINDOW = 64 << 10        # external (cgo) linking puts crt0 before the build ID
MAX_NEEDLE_HITS = 4096            # raw hits of the known-magic needle examined
MAX_PCLN_CANDIDATES = 16
MAX_POINTER_SCAN = 16 << 20       # writable bytes searched for one pointer value
MAX_POINTER_TOTAL = 256 << 20     # ... and for all of them in one file
MAX_SHAPE_HITS = 100_000          # magic-agnostic search (garble randomises the magic)
MAX_SHAPE_CANDIDATES = 10_000
MAX_NFUNC = 2_000_000             # the largest real programs have ~130,000
MAX_NAMES = 400_000
MAX_NAMES_BYTES = 64 << 20
MAX_NAME_LEN = 4096
MAX_FILES = 200_000
MAX_PACKAGES = 3000
MAX_MAIN_FUNCS = 200
MAX_WINAPI = 1000
MAX_SOURCE_PATHS = 50
MAX_EMBEDDED = 8
MAX_VERSION_CANDIDATES = 16

# pclntab header magic (low byte) -> the table layouts of runtime/symtab.go.
_LAYOUT = {0xFB: "1.2-1.15", 0xFA: "1.16-1.17", 0xF0: "1.18-1.19", 0xF1: "1.20+"}
# Instruction-size quantum (pcHeader.minLC) by machine: x86/x64 1, ARM 4.
_MACHINE_QUANTUM = {0x8664: 1, 0x14C: 1, 0xAA64: 4, 0x1C4: 4}
_TOOLCHAIN = re.compile(r"go1(\.\d+){0,2}((rc|beta)\d+)?([ +-][\x20-\x7e]*)?|devel [\x20-\x7e]+")
_BUILD_ID = re.compile(rb'\xff Go build ID: "([\x21\x23-\x7e]{1,400})"\n \xff')
_VERSION_AT = re.compile(rb"go1\.\d{1,2}(?:\.\d{1,2})?(?:(?:rc|beta)\d{1,2})?")

STD_ROOTS = frozenset("""archive bufio builtin bytes cmd cmp compress container context crypto
database debug embed encoding errors expvar flag fmt go hash html image index internal io iter
log maps math mime net os path plugin reflect regexp runtime slices sort strconv strings structs
sync syscall testing text time unicode unique unsafe vendor weak""".split())


# ---------------------------------------------------------------- image view
def _union(ranges) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1]:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(a, b) for a, b in out]


@dataclass
class _Sec:
    name: str
    va: int
    vsize: int
    raw: int
    size: int
    chars: int

    @property
    def end(self) -> int:
        return self.raw + self.size

    @property
    def writable(self) -> bool:
        return bool(self.chars & 0x80000000)

    @property
    def executable(self) -> bool:
        return bool(self.chars & 0x20000020)


class _Image:
    """Bounds-checked view of the section table and raw bytes."""

    def __init__(self, pe: pefile.PE, data: bytes):
        self.data = data
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.ptr = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
        self.fmt = "<Q" if self.ptr == 8 else "<I"
        self.machine = pe.FILE_HEADER.Machine
        self.secs: list[_Sec] = []
        n = len(data)
        for s in pe.sections[:MAX_SECTIONS]:
            raw = s.PointerToRawData
            size = min(s.SizeOfRawData, max(0, n - raw))
            if raw >= n or size <= 0:
                continue
            self.secs.append(_Sec(s.Name.rstrip(b"\0").decode("latin-1", "replace"),
                                  s.VirtualAddress, s.Misc_VirtualSize, raw, size, s.Characteristics))
        # A hostile section table can map the same bytes many times: every
        # search walks the union of the raw ranges, so a byte is read once.
        self.all_ranges = _union((s.raw, s.end) for s in self.secs)
        self.rw_ranges = _union((s.raw, s.end) for s in self.secs if s.writable)
        self.ro_ranges = _union((s.raw, s.end) for s in self.secs if not s.writable)
        self.pointer_budget = MAX_POINTER_TOTAL

    def sec_of(self, off: int) -> _Sec | None:
        for s in self.secs:
            if s.raw <= off < s.end:
                return s
        return None

    def writable_sec_of(self, off: int) -> _Sec | None:
        for s in self.secs:
            if s.writable and s.raw <= off < s.end:
                return s
        return None

    @property
    def rw_size(self) -> int:
        return sum(hi - lo for lo, hi in self.rw_ranges)

    def find_pointer(self, value: int, limit: int = 8, from_end: bool = False) -> list[tuple[_Sec, int]]:
        """Pointer-aligned offsets in writable data that hold `value`: in the first
        MAX_POINTER_SCAN writable bytes, or the last ones with `from_end`. Every
        search draws on one per-file budget, so many candidates cannot add up."""
        if not 0 <= value < 1 << (8 * self.ptr):
            return []
        needle, out = struct.pack(self.fmt, value), []
        budget = min(MAX_POINTER_SCAN, self.pointer_budget)
        for lo, hi in (reversed(self.rw_ranges) if from_end else self.rw_ranges):
            if budget <= 0:
                break
            if from_end:
                lo = max(lo, hi - budget)
            else:
                hi = min(hi, lo + budget)
            budget -= hi - lo
            self.pointer_budget -= hi - lo
            q = self.data.find(needle, lo, hi)
            while q >= 0 and len(out) < limit:
                w = self.writable_sec_of(q)
                if w is not None and (q - w.raw) % self.ptr == 0:
                    out.append((w, q))
                q = self.data.find(needle, q + 1, hi)
            if len(out) >= limit:
                break
        return out

    def off_to_va(self, off: int) -> int | None:
        s = self.sec_of(off)
        return None if s is None else self.base + s.va + (off - s.raw)

    def va_to_off(self, va: int, n: int) -> int | None:
        rva = va - self.base
        for s in self.secs:
            if s.va <= rva < s.va + max(s.vsize, s.size):
                off = rva - s.va
                return s.raw + off if off + n <= s.size else None
        return None

    def in_code(self, va: int) -> bool:
        rva = va - self.base
        return any(s.executable and s.va <= rva < s.va + max(s.vsize, s.size) for s in self.secs)

    def word(self, off: int) -> int:
        return struct.unpack_from(self.fmt, self.data, off)[0]


# ---------------------------------------------------------------- build info
def _uvarint(b: bytes, pos: int) -> tuple[int, int]:
    x = shift = 0
    for i in range(10):
        if pos + i >= len(b):
            raise ValueError("truncated varint")
        c = b[pos + i]
        x |= (c & 0x7F) << shift
        if c < 0x80:
            return x, pos + i + 1
        shift += 7
    raise ValueError("varint too long")


def _go_string(img: _Image, va: int, cap: int) -> bytes | None:
    """A Go string header {data, len} at `va`, and the bytes it points at."""
    off = img.va_to_off(va, 2 * img.ptr)
    if off is None:
        return None
    ptr, n = img.word(off), img.word(off + img.ptr)
    if n > cap:
        return None
    if n == 0:
        return b""
    doff = img.va_to_off(ptr, n)
    return None if doff is None else img.data[doff:doff + n]


def _data_sections(img: _Image) -> list[_Sec]:
    """Go's own DataStart rule first, then other writable initialized-data sections."""
    first = next((s for s in img.secs if s.va and s.chars & ~0x00F00000 == 0xC0000040), None)
    rest = [s for s in img.secs if s is not first and s.writable and s.chars & 0x40
            and not s.executable and s.name != ".rsrc"]
    return ([first] if first else []) + rest


def _decode_buildinfo(img: _Image, i: int, end: int, info: GoInfo) -> tuple[str, bytes] | None:
    data = img.data
    if i + 32 > end:
        return None
    hdr = data[i:i + 32]
    ptr, flags = hdr[14], hdr[15]
    # Flag 0x2 is the inline form; 0x1 (big-endian) never occurs in a PE.
    if ptr != img.ptr or flags not in (0, 2):
        return None
    if flags == 2:                        # Go 1.18+: varint-prefixed strings follow
        if any(hdr[16:32]):
            return None
        n, pos = _uvarint(data, i + 32)
        if not 1 <= n <= MAX_VERSION or pos + n > len(data):
            return None
        vers = data[pos:pos + n]
        pos += n
        try:
            m, pos = _uvarint(data, pos)
        except ValueError:
            m = -1
        if m < 0 or m > len(data) - pos:
            mod = b""
            info.notes.append("module info length out of bounds")
        elif m > MAX_MODINFO:
            mod = data[pos:pos + MAX_MODINFO]
            info.notes.append(f"module info over {MAX_MODINFO} bytes, read in part")
        else:
            mod = data[pos:pos + m]
        info.buildinfo_format = "inline"
    else:                                 # Go 1.13-1.17: pointers to Go string headers
        if ptr == 4 and any(hdr[24:32]):
            return None
        vers = _go_string(img, struct.unpack_from(img.fmt, hdr, 16)[0], MAX_VERSION)
        if vers is None:
            return None
        mod = _go_string(img, struct.unpack_from(img.fmt, hdr, 16 + ptr)[0], MAX_MODINFO)
        if mod is None:
            mod = b""
            info.notes.append("module info unreadable")
        info.buildinfo_format = "pointer"
    if not vers or not all(0x20 <= c < 0x7F for c in vers):
        return None
    return vers.decode("ascii"), mod


def _buildinfo(img: _Image) -> tuple[GoInfo | None, int]:
    """(the build info, read into a record of its own, or None; the number of
    build-info-shaped headers rejected). The record joins the report only when
    the build info turns out to be this program's (_take_buildinfo)."""
    examined = rejected = 0
    searched: list[tuple[int, int]] = []
    for s in _data_sections(img):
        hi = min(s.end, s.raw + MAX_BI_SCAN)
        if any(a <= s.raw and hi <= b for a, b in searched):
            continue                      # the same bytes under another header
        searched.append((s.raw, hi))
        i = img.data.find(BUILDINFO_MAGIC, s.raw, hi)
        while i >= 0 and examined < MAX_BI_CANDIDATES:
            examined += 1
            if (s.va + i - s.raw) % 16 == 0:
                bi = GoInfo()
                try:
                    r = _decode_buildinfo(img, i, s.end, bi)
                except (ValueError, struct.error):
                    r = None
                if r is not None:
                    bi.version, mod = r
                    bi.version_source = "buildinfo"
                    bi.buildinfo_offset = i
                    _parse_modinfo(mod, bi)
                    return bi, rejected
            rejected += 1
            i = img.data.find(BUILDINFO_MAGIC, i + 1, hi)
    return None, rejected


def _take_buildinfo(info: GoInfo, bi: GoInfo) -> None:
    for name in ("version", "version_source", "buildinfo_format", "buildinfo_offset", "main_path",
                 "main_module", "deps", "dep_count", "settings"):
        setattr(info, name, getattr(bi, name))
    info.notes[:0] = bi.notes


_ESC = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}
_OCTAL = re.compile(r"[0-7]{3}")
_HEX = {2: re.compile(r"[0-9a-fA-F]{2}"), 4: re.compile(r"[0-9a-fA-F]{4}"), 8: re.compile(r"[0-9a-fA-F]{8}")}


def _unquote(s: str) -> str:
    """Go's strconv.Unquote for a double-quoted string. Hex and octal escapes
    are bytes and the result is decoded as UTF-8; whatever Go would reject (an
    unknown escape, a surrogate, a bare quote) leaves the string as it was."""
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        return s
    out, i, body = bytearray(), 0, s[1:-1]
    while i < len(body):
        ch = body[i]
        if ch == '"':
            return s
        if ch != "\\":
            out += ch.encode("utf-8", "replace")
            i += 1
            continue
        e = body[i + 1:i + 2]
        if e in _ESC:
            out.append(_ESC[e])
            i += 2
        elif e and e in "01234567":
            digits = body[i + 1:i + 4]
            if not _OCTAL.fullmatch(digits) or int(digits, 8) > 0xFF:
                return s
            out.append(int(digits, 8))
            i += 4
        elif e and e in "xuU":
            width = {"x": 2, "u": 4, "U": 8}[e]
            digits = body[i + 2:i + 2 + width]
            if not _HEX[width].fullmatch(digits):
                return s
            v = int(digits, 16)
            if e == "x":
                out.append(v)
            elif v > 0x10FFFF or 0xD800 <= v <= 0xDFFF:
                return s
            else:
                out += chr(v).encode("utf-8")
            i += 2 + width
        else:
            return s
    return out.decode("utf-8", "replace")


_QUOTED_KEY = re.compile(r'("(?:[^"\\]|\\.)*")=(.*)\Z', re.S)


def _parse_modinfo(raw: bytes, info: GoInfo) -> None:
    """cmd/go's module info: tab-separated path/mod/dep/=>/build lines."""
    if len(raw) >= 33 and raw[-17:-16] == b"\n":
        if raw[:16] != INFO_START or raw[-16:] != INFO_END:
            info.notes.append("module info sentinels altered")
        raw = raw[16:-16]
    elif raw[:16] == INFO_START:
        raw = raw[16:]                    # read in part: the end sentinel was cut off
    elif raw:
        info.notes.append("module info present but not framed")
        return
    else:
        return
    last: GoModule | None = None
    bad = 0
    for n, line in enumerate(raw.decode("utf-8", "replace").split("\n")):
        if n >= MAX_MODINFO_LINES:
            info.notes.append("module info has too many lines, read in part")
            break
        if not line:
            continue
        kind, _, rest = line.partition("\t")
        parts = rest.split("\t")
        if kind == "path":
            info.main_path = rest[:300]
        elif kind in ("mod", "dep"):
            mod = GoModule(parts[0][:300], *(p[:100] for p in (parts + ["", ""])[1:3]))
            if kind == "mod":
                info.main_module = mod
            else:
                info.dep_count += 1
                if len(info.deps) < MAX_DEPS:
                    info.deps.append(mod)
            last = mod
        elif kind == "=>" and last is not None:
            last.replace = " ".join(p for p in parts[:2] if p)[:300]
        elif kind == "build":
            m = _QUOTED_KEY.match(rest) if rest.startswith('"') else None
            key, value = (m.group(1), m.group(2)) if m else rest.partition("=")[::2]
            if len(info.settings) < MAX_SETTINGS:
                info.settings[_unquote(key)[:64]] = _unquote(value)[:MAX_SETTING_VALUE]
        elif kind != "go":
            bad += 1
    if bad:
        info.notes.append(f"{bad} unrecognised module info lines")


def _build_id(img: _Image) -> str | None:
    """The Go build ID near the start of the first executable section."""
    for s in img.secs:
        if s.executable:
            m = _BUILD_ID.search(img.data, s.raw, s.raw + min(s.size, BUILD_ID_WINDOW))
            return m.group(1).decode("ascii") if m else None
    return None


# ---------------------------------------------------------------- pclntab
@dataclass
class _Table:
    off: int
    sec: _Sec
    layout: str
    magic: int
    nfunc: int
    offs: list[int] | None = None   # funcname, cu, filetab, pctab, pcln (relative), 1.16+
    header_ok: bool = False
    owned: bool = False
    confirmed: bool = False
    altered: bool = False


def _new(layout: str) -> bool:
    return layout in ("1.18-1.19", "1.20+")


def _read_header(img: _Image, off: int, sec: _Sec, layout: str) -> _Table | None:
    ptr = img.ptr
    if off + 8 + 8 * ptr > sec.end:
        return None
    magic = struct.unpack_from("<I", img.data, off)[0]
    nfunc = img.word(off + 8)
    t = _Table(off, sec, layout, magic, nfunc)
    if layout == "1.2-1.15":
        ftab_end = off + 8 + ptr + (2 * nfunc + 1) * ptr
        t.header_ok = 0 < nfunc <= MAX_NFUNC and ftab_end + 4 <= sec.end
        return t
    # 1.18+ adds textStart (zero since Go 1.26, never checked) before the offsets.
    first, hsize = (3, 8 + 8 * ptr) if _new(layout) else (2, 8 + 7 * ptr)
    if off + hsize > sec.end:
        return None
    nfiles = img.word(off + 8 + ptr)
    offs = [img.word(off + 8 + (first + k) * ptr) for k in range(5)]
    pair = 8 if _new(layout) else 2 * ptr
    t.offs = offs
    t.header_ok = (0 < nfunc <= MAX_NFUNC and 0 <= nfiles <= MAX_NFUNC
                   and hsize <= offs[0] <= hsize + 4096
                   and all(a < b for a, b in pairwise(offs))
                   and off + offs[4] + (nfunc + 1) * pair <= sec.end)
    return t


def _functab_sample_ok(img: _Image, t: _Table, samples: int = 64) -> bool:
    """Sampled functab entries lead to _func records whose name offset starts a
    NUL-preceded name; for 1.2-1.15 entry PCs also ascend. Names are not read,
    so encrypted entry offsets do not matter, and a forged nfunc costs 64 reads."""
    data, off, ptr = img.data, t.off, img.ptr
    step = max(1, t.nfunc // samples)
    good = total = 0
    if t.layout == "1.2-1.15":
        ftab = off + 8 + ptr
        last = -1
        for k in range(0, t.nfunc, step):
            total += 1
            p = ftab + 2 * k * ptr
            if p + 2 * ptr > t.sec.end:
                return False
            entry, funcoff = img.word(p), img.word(p + ptr)
            if entry <= last:
                return False
            last = entry
            fo = off + funcoff
            if fo + ptr + 4 > t.sec.end:
                continue
            no = off + struct.unpack_from("<i", data, fo + ptr)[0]
            if off < no < t.sec.end and data[no - 1] == 0 and 0x20 < data[no] < 0x7F:
                good += 1
        return total > 0 and good >= 0.9 * total
    fn, cu, pcln = off + t.offs[0], off + t.offs[1], off + t.offs[4]
    half = 4 if _new(t.layout) else ptr
    hfmt = "<I" if half == 4 else img.fmt
    for k in range(0, t.nfunc, step):
        total += 1
        p = pcln + k * 2 * half + half
        if p + half > t.sec.end:
            return False
        fo = pcln + struct.unpack_from(hfmt, data, p)[0]
        if fo + half + 4 > t.sec.end:
            continue
        nameoff = struct.unpack_from("<i", data, fo + half)[0]
        if 0 <= nameoff < cu - fn and (nameoff == 0 or data[fn + nameoff - 1] == 0):
            good += 1
    return total > 0 and good >= 0.9 * total


def _moduledata(img: _Image, t: _Table) -> None:
    """Does this image's runtime.firstmoduledata point at the table?

    The runtime checks only the header's magic, pad, minLC and ptrSize and then
    uses the moduledata slices, so those also give the table bounds when the
    header was altered."""
    ptr = img.ptr
    P = img.off_to_va(t.off)
    if P is None:
        return
    hits = img.find_pointer(P)
    if not hits:
        return
    t.owned = True
    sec_hi = img.base + t.sec.va + t.sec.size
    for w, q in hits:
        nwords = 14 if t.layout == "1.2-1.15" else 24
        if q + nwords * ptr > w.end:
            continue
        words = [img.word(q + k * ptr) for k in range(nwords)]
        if t.layout == "1.2-1.15":
            # pclntable {P, len, cap}, ftab {ptr, len, cap}, filetab, findfunctab, minpc, maxpc, text, etext
            ok = (words[3] == P + 8 + ptr and words[4] >= 1 and words[1] <= words[2]
                  and words[12] < words[13] and img.in_code(words[12]) and img.in_code(words[13] - 1))
            if ok:
                if not t.header_ok or words[4] - 1 != t.nfunc:
                    t.altered = True
                    t.nfunc = words[4] - 1
                    t.header_ok = 0 < t.nfunc <= MAX_NFUNC
                t.confirmed = True
                return
            continue
        # pcHeader, funcnametab, cutab, filetab, pctab, pclntable, ftab ({ptr, len, cap}
        # each), findfunctab, minpc, maxpc, text, etext: the same order up to Go 1.26.
        tbl = [words[1], words[4], words[7], words[10], words[13]]
        ok = (P < tbl[0] and all(a <= b for a, b in pairwise(tbl)) and tbl[4] < sec_hi
              and words[16] == tbl[4] and 1 <= words[17] <= MAX_NFUNC + 1
              and words[22] < words[23] and img.in_code(words[22]) and img.in_code(words[23] - 1))
        if not ok:
            continue
        rel = [v - P for v in tbl]
        if not (t.header_ok and rel == t.offs and words[17] == t.nfunc + 1):
            t.altered = True
            t.offs, t.nfunc = rel, words[17] - 1
            pair = 8 if _new(t.layout) else 2 * ptr
            t.header_ok = t.off + rel[4] + (t.nfunc + 1) * pair <= t.sec.end
        t.confirmed = True
        return


def _known_candidates(img: _Image, quantum: int, info: GoInfo):
    """Tables whose header has a known magic. One needle (the bytes after the
    magic's low byte) finds all four layouts in a single pass."""
    needle = b"\xff\xff\xff\x00\x00" + bytes([quantum, img.ptr])
    hits = yielded = 0
    for lo, hi in img.all_ranges:
        i = img.data.find(needle, lo + 1, hi)
        while i >= 0:
            hits += 1
            if hits > MAX_NEEDLE_HITS or yielded >= MAX_PCLN_CANDIDATES:
                info.notes.append("pclntab search capped")
                return
            s = img.sec_of(i - 1)
            if s is not None and img.data[i - 1] in _LAYOUT:
                yielded += 1
                yield i - 1, s, _LAYOUT[img.data[i - 1]]
            i = img.data.find(needle, i + 1, hi)


def _shape_candidates(img: _Image, quantum: int, info: GoInfo):
    """Tables with any magic: pad, pad, quantum, pointer size, 4-aligned, read-only."""
    tail = b"\x00\x00" + bytes([quantum, img.ptr])
    hits = tried = 0
    for lo, hi in img.ro_ranges:
        i = img.data.find(tail, lo + 4, hi)
        while i >= 0:
            hits += 1
            if hits > MAX_SHAPE_HITS or tried >= MAX_SHAPE_CANDIDATES:
                info.notes.append("magic-agnostic pclntab search capped")
                return
            off = i - 4
            s = img.sec_of(off)
            if s is not None and not s.writable and not (off - s.raw) & 3:
                tried += 1
                yield off, s
            i = img.data.find(tail, i + 1, hi)


def _find_pclntab(img: _Image, info: GoInfo, gate: bool) -> _Table | None:
    quanta = [_MACHINE_QUANTUM[img.machine]] if img.machine in _MACHINE_QUANTUM else [1, 4]
    for quantum in quanta:
        for off, sec, layout in _known_candidates(img, quantum, info):
            t = _read_header(img, off, sec, layout)
            if t is None:
                continue
            _moduledata(img, t)
            if t.owned and (t.confirmed or (t.header_ok and _functab_sample_ok(img, t))):
                if not t.confirmed:
                    info.notes.append("runtime.firstmoduledata not recognised")
                return t
            if not t.owned and t.header_ok and _functab_sample_ok(img, t):
                if len(info.embedded) < MAX_EMBEDDED:
                    info.embedded.append(f"Go program at 0x{off:x}: pclntab {layout}, {t.nfunc:,} "
                                         f"functions, not used by this image")
    if not gate:
        return None
    tried = 0                             # each one costs a pointer search
    for quantum in quanta:
        for off, sec in _shape_candidates(img, quantum, info):
            for layout in ("1.20+", "1.16-1.17"):
                t = _read_header(img, off, sec, layout)
                if t is None or not t.header_ok or not _functab_sample_ok(img, t):
                    continue
                if tried >= MAX_PCLN_CANDIDATES:
                    info.notes.append("magic-agnostic pclntab search capped")
                    return None
                tried += 1
                _moduledata(img, t)
                if t.owned:
                    return t
    return None


def _names(img: _Image, t: _Table, info: GoInfo) -> list[bytes]:
    data = img.data
    if t.layout != "1.2-1.15":
        # funcnametab is one block of NUL-terminated names.
        lo = t.off + t.offs[0]
        hi = min(t.off + t.offs[1], t.sec.end, lo + MAX_NAMES_BYTES)
        if hi - lo >= MAX_NAMES_BYTES:
            info.notes.append("function name table read in part")
        parts = data[lo:hi].split(b"\0", MAX_NAMES)
        if len(parts) > MAX_NAMES:
            info.notes.append("function names capped")
            parts = parts[:MAX_NAMES]
        return [n for n in parts if n and len(n) <= MAX_NAME_LEN]
    off, ptr, end = t.off, img.ptr, t.sec.end
    ftab = off + 8 + ptr
    seen: set[int] = set()
    out: list[bytes] = []
    total = 0
    for k in range(min(t.nfunc, MAX_NAMES)):
        p = ftab + (2 * k + 1) * ptr
        if p + ptr > end:
            break
        fo = off + img.word(p)
        if fo + ptr + 4 > end:
            continue
        no = off + struct.unpack_from("<i", data, fo + ptr)[0]
        if not off < no < end or no in seen:
            continue
        seen.add(no)
        e = data.find(b"\0", no, min(no + MAX_NAME_LEN, end))
        if e > no:
            total += e - no
            if total > MAX_NAMES_BYTES:   # forged records naming every byte of one long run
                info.notes.append("function name table read in part")
                break
            out.append(data[no:e])
    return out


def _files(img: _Image, t: _Table) -> list[bytes]:
    data = img.data
    if t.layout != "1.2-1.15":
        lo, hi = t.off + t.offs[2], min(t.off + t.offs[3], t.sec.end)
        return [n for n in data[lo:hi].split(b"\0", MAX_FILES)[:MAX_FILES] if n and len(n) <= MAX_NAME_LEN]
    off, ptr, end = t.off, img.ptr, t.sec.end
    after = off + 8 + ptr + (2 * t.nfunc + 1) * ptr
    if after + 4 > end:
        return []
    fto = off + struct.unpack_from("<I", data, after)[0]
    if fto + 4 > end:
        return []
    out = []
    seen: set[int] = set()
    total = 0
    for k in range(1, min(struct.unpack_from("<I", data, fto)[0], MAX_FILES)):
        p = fto + 4 * k
        if p + 4 > end:
            break
        so = off + struct.unpack_from("<I", data, p)[0]
        # Each entry starts its own NUL-terminated string; repeats are read once.
        if off < so < end and so not in seen and data[so - 1] == 0:
            seen.add(so)
            e = data.find(b"\0", so, min(so + MAX_NAME_LEN, end))
            if e > so:
                total += e - so
                if total > MAX_NAMES_BYTES:
                    break
                out.append(data[so:e])
    return out


# ---------------------------------------------------------------- names -> facts
_SYNTHETIC = ("go:", "type:", "type.", "gclocals", "go.shape.", "go.itab.", "go.buildid",
              "go.string.", "go.func.", "go.info.", "go.cuinfo.", "go.importpath.", "_")
_HOST = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")
_PATH_ELEM = re.compile(r"[a-z0-9_~-]+\.[a-z0-9_~-]+")
_NOT_HOSTS = (STD_ROOTS - {"go"}) | {"main"}


def package_of(name: str) -> str:
    """The package of a Go symbol name: "github.com/a/b.(*T).M" -> "github.com/a/b".

    Dots inside an import path's last element are written %2e by the linker;
    a dotted first element is a host name, a dotted middle element (nats.go)
    belongs to the path. Compiler-made symbols have no package ("")."""
    if name.startswith(_SYNTHETIC):
        return ""
    head = name
    for ch in "([ ":
        i = head.find(ch)
        if i >= 0:
            head = head[:i]
    if "/" not in head:
        dot = head.find(".")
        pkg = head[:dot] if dot > 0 else ""
        pkg = pkg.replace("%2e", ".") if "%" in pkg else pkg
        # "go.(*struct { sync.Mutex }).Lock": a promoted-method wrapper (Go 1.12-1.19),
        # not a package; the standard library's go/... packages always have a slash.
        return "" if pkg == "go" else pkg
    if head.count("/") > 32:              # no import path is this deep; each element costs a regex
        return ""
    parts = head.split("/")
    last = len(parts) - 1
    for k, part in enumerate(parts):
        dot = part.find(".")
        if dot < 0:
            if k == last:
                return ""
            continue
        if k < last and ((_HOST.fullmatch(part) is not None and part[:dot] not in _NOT_HOSTS) if k == 0
                         else (part.count(".") == 1 and _PATH_ELEM.fullmatch(part) is not None)):
            continue
        if dot == 0:
            return ""
        pkg = "/".join(parts[:k] + [part[:dot]])
        return pkg.replace("%2e", ".") if "%" in pkg else pkg
    return ""


def package_kind(pkg: str) -> str:
    """"std", "third-party" (a host-named path), "main" or "local"."""
    first = pkg.split("/", 1)[0]
    if pkg == "main":
        return "main"
    if "." in first:
        return "third-party"
    return "std" if first in STD_ROOTS else "local"


def _packages(names: list[str]) -> set[str]:
    pkgs: set[str] = set()
    prev_prefix = "\x00"
    for n in names:
        # Names come grouped by package: skip the ones plainly in the last one.
        if n.startswith(prev_prefix):
            rest = n[len(prev_prefix):]
            paren = rest.find("(")
            if "/" not in (rest if paren < 0 else rest[:paren]):
                continue
        p = package_of(n)
        if p:
            pkgs.add(p)
            path, slash, last = p.rpartition("/")
            prev_prefix = path + slash + last.replace(".", "%2e") + "."
    return pkgs


_WINAPI = re.compile(r"(?:syscall|internal/syscall/windows|(?:.*/vendor/)?golang\.org/x/sys/windows)"
                     r"\.([A-Z][A-Za-z0-9_]{0,80})")
_PROC_CALL = re.compile(r"(?:syscall|(?:.*/vendor/)?golang\.org/x/sys/windows)\.\(\*(?:Lazy)?Proc\)\.Call")
_HASHY = re.compile(r"[A-Za-z0-9_]{5,16}")


def _garble_like(pkg: str) -> bool:
    """A one-element package name that looks like a hash (garble renames packages)."""
    if "/" in pkg or "." in pkg or pkg in STD_ROOTS or pkg == "main" or not _HASHY.fullmatch(pkg):
        return False
    upper = sum(c.isupper() for c in pkg)
    lower = sum(c.islower() for c in pkg)
    digit = sum(c.isdigit() for c in pkg)
    return upper >= 1 and lower >= 1 and (digit >= 1 or upper >= 2)


def _summarize(img: _Image, t: _Table, info: GoInfo) -> None:
    raw = _names(img, t, info)
    names = list(dict.fromkeys(n.decode("utf-8", "replace") for n in raw))
    info.name_count = len(names)
    pkgs = sorted(_packages(names))
    kinds = Counter(package_kind(p) for p in pkgs)
    info.package_count = len(pkgs)
    info.packages = pkgs[:MAX_PACKAGES]
    info.std_package_count = kinds["std"]
    info.third_party_count = kinds["third-party"]
    info.local_package_count = kinds["local"]
    info.main_functions = sorted(n for n in names if n.startswith("main."))[:MAX_MAIN_FUNCS]
    api = set()
    for n in names:
        if n.startswith(("syscall.", "internal/syscall/windows.")) or "golang.org/x/sys/windows." in n:
            m = _WINAPI.fullmatch(n)
            if m:
                api.add(m.group(1))
            elif _PROC_CALL.fullmatch(n):
                info.proc_call = True
    info.winapi = sorted(api)[:MAX_WINAPI]
    garbled = [p for p in pkgs if package_kind(p) == "local" and _garble_like(p)]
    if len(garbled) >= 5 and len(garbled) * 2 >= kinds["local"] + kinds["third-party"]:
        info.obfuscation.append(f"{len(garbled)} random-looking package paths (garble-style)")
    files = [f.decode("utf-8", "replace") for f in _files(img, t)]
    info.file_count = len(files)
    goroot = next((f[:-len("runtime/proc.go")] for f in files if f.endswith("/src/runtime/proc.go")), None)
    info.goroot = goroot[:300] if goroot else None
    own = sorted(f for f in files if (f[1:3] == ":/" or f[1:3] == ":\\" or f.startswith("/"))
                 and not (goroot and f.startswith(goroot)) and "/pkg/mod/" not in f)
    info.source_path_count = len(own)
    info.source_paths = [p[:300] for p in own[:MAX_SOURCE_PATHS]]
    if info.trimpath is None and files:
        info.trimpath = not own and goroot is None


def _runtime_version(img: _Image) -> str | None:
    """runtime.buildVersion: a "go1.x" string whose {ptr, len} header sits in
    writable data (exact even in Go 1.12, where strings are packed together).
    The header lies near the end of .data, so a large .data is searched from
    both ends."""
    data, seen = img.data, 0
    both_ends = img.rw_size > MAX_POINTER_SCAN
    for lo, hi in img.ro_ranges:
        i = data.find(b"go1.", lo, hi)
        while i >= 0 and seen < MAX_VERSION_CANDIDATES:
            seen += 1
            m = _VERSION_AT.match(data, i)
            va = img.off_to_va(i)
            if m and va is not None:
                hits = img.find_pointer(va) + (img.find_pointer(va, from_end=True) if both_ends else [])
                for w, q in hits:
                    if q + 2 * img.ptr <= w.end:
                        n = img.word(q + img.ptr)
                        if not 4 <= n <= 64:      # checked before the slice: a forged length
                            continue
                        cand = data[i:i + n]
                        if _TOOLCHAIN.fullmatch(cand.decode("latin-1")):
                            return cand.decode("ascii", "replace")
            i = data.find(b"go1.", i + 1, hi)
    return None


# ---------------------------------------------------------------- entry point
def analyze_go(pe: pefile.PE, data: bytes) -> GoInfo | None:
    """GoInfo when this image is a Go program, else None. Never raises."""
    info = GoInfo()
    found: dict = {}
    try:
        return _analyze(pe, data, info, found)
    except Exception as exc:  # a parser bug is a note, never a failed triage
        info.notes.append(f"Go stage error: {type(exc).__name__}: {exc}"[:200])
        if not info.evidence:             # keep what was read before the failure
            if found.get("buildinfo") is not None:
                _take_buildinfo(info, found["buildinfo"])
                info.evidence.append("buildinfo")
            if info.build_id is not None:
                info.evidence.append("build-id")
        return info if info.evidence else None


def _analyze(pe: pefile.PE, data: bytes, info: GoInfo, found: dict) -> GoInfo | None:
    img = _Image(pe, data)
    info.ptr_size = img.ptr
    bi, rejected = _buildinfo(img)
    found["buildinfo"] = bi
    has_bi = bi is not None
    info.build_id = _build_id(img)
    table = None
    if len(data) > MAX_PCLNTAB_FILE:
        info.notes.append("file over 128 MB: pclntab not read")
    else:
        # The magic-agnostic search costs more, so it runs only for a file that
        # already looks like Go; every runtime's scheduler reads GOMAXPROCS.
        gate = has_bi or info.build_id is not None or b"GOMAXPROCS" in data
        table = _find_pclntab(img, info, gate)
    # Build info next to someone else's function table belongs to the carried program.
    if has_bi and (table is not None or not info.embedded):
        info.evidence.append("buildinfo")
    if table is not None:
        info.evidence.append("pclntab")
    if info.build_id is not None:
        info.evidence.append("build-id")
    if not info.evidence:
        return None
    if "buildinfo" in info.evidence:
        _take_buildinfo(info, bi)
    cgo = info.settings.get("CGO_ENABLED")
    info.cgo = None if cgo is None else cgo == "1"
    tp = info.settings.get("-trimpath")
    info.trimpath = None if tp is None else tp == "true"
    if table is not None:
        info.confirmed = table.confirmed
        info.pclntab_layout = table.layout
        info.pclntab_offset = table.off
        info.function_count = table.nfunc
        if table.magic & 0xFF not in _LAYOUT or table.magic | 0xFF != 0xFFFFFFFF:
            info.obfuscation.append(f"pclntab magic replaced (0x{table.magic:08x})")
        if table.altered:
            info.obfuscation.append("pclntab header disagrees with runtime.firstmoduledata (altered)")
        if table.header_ok:
            _summarize(img, table, info)
        else:
            info.notes.append("pclntab tables unreadable")
    if info.version is None:
        v = _runtime_version(img)
        if v:
            info.version, info.version_source = v, "runtime"
    if "buildinfo" not in info.evidence and table is not None:
        minor = re.match(r"go1\.(\d+)", info.version or "")
        if table.layout != "1.2-1.15" or (minor and int(minor.group(1)) >= 13):
            info.obfuscation.append("no build info (removed)")
    if info.buildinfo_format == "inline" and not (info.main_path or info.main_module or info.settings):
        info.obfuscation.append("build info carries no module information (removed)")
    if "buildinfo" in info.evidence and not _TOOLCHAIN.fullmatch(info.version or ""):
        info.obfuscation.append(f"build info version {info.version!r} is not a Go toolchain version")
    if rejected and info.evidence:
        info.obfuscation.append(f"{rejected} malformed build info header(s) in the data section")
    if info.main_module is None and info.main_path:
        info.notes.append("no main module (GOPATH or vendor-mode build)")
    if img.pointer_budget <= 0:
        info.notes.append("pointer search budget spent")
    return info
