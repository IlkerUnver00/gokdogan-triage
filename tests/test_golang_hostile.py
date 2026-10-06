"""The Go stage against crafted input, and what its output may do downstream.

Each case was found in review: a reproducer first, then the guard."""

from __future__ import annotations

import struct
import time

import pefile
import pytest
from gofixtures import DATA, MODINFO, RDATA, TEXT, build_go_pe, build_pe

from gokdogan.cluster import cluster_reports
from gokdogan.engine import triage_bytes
from gokdogan.golang import _unquote, analyze_go, package_of
from gokdogan.html_report import render_html
from gokdogan.models import GoInfo
from gokdogan.report import go_lines, render_json
from gokdogan.summary import _flatten_for_csv


def go(blob: bytes) -> GoInfo | None:
    return analyze_go(pefile.PE(data=blob, fast_load=True), blob)


def timed(blob: bytes) -> tuple[GoInfo | None, float]:
    pe = pefile.PE(data=blob, fast_load=True)
    t = time.perf_counter()
    g = analyze_go(pe, blob)
    return g, time.perf_counter() - t


def _modinfo(build_line: bytes) -> bytes:
    return MODINFO[:-16] + build_line + b"\n" + MODINFO[-16:]


# --- strconv.Unquote, and what a forged setting can do to the writers ---------
@pytest.mark.parametrize("quoted,plain", [
    ('"\\ud800"', '"\\ud800"'),               # a surrogate: Go rejects it, so it stays raw
    ('"\\U0000DFFF"', '"\\U0000DFFF"'),
    ('"\\101\\102"', "AB"),                    # octal escapes are bytes
    ('"\\q"', '"\\q"'),                        # unknown escape
    ('"a\\\'b"', '"a\\\'b"'),                  # \' is not valid inside double quotes
    ('"a"b"', '"a"b"'),                        # a bare quote inside
    ('"\\xe2\\x82\\xac"', "\u20ac"),           # hex escapes are bytes, decoded as UTF-8
    ('"\\xe9\\x80"', "\ufffd"),                # invalid UTF-8 is replaced, not mojibake
    ('"tail\\"', '"tail\\"'),                  # a trailing backslash
])
def test_unquote_follows_go(quoted, plain):
    assert _unquote(quoted) == plain


def test_a_forged_setting_cannot_break_the_json_or_html_writers():
    blob = build_go_pe(64, modinfo=_modinfo(b'build\t-ldflags="-X main.k=\\ud800"\nbuild\t"\\udfff"=x'))
    report = triage_bytes(blob, name="forged.exe", use_yara=False)
    assert report.go.settings["-ldflags"] == '"-X main.k=\\ud800"'
    render_json(report).encode("utf-8")       # a lone surrogate would raise here
    render_html(report).encode("utf-8")


# --- package names ----------------------------------------------------------
@pytest.mark.parametrize("name,package", [
    ("go.(*struct { sync.Mutex; reflect.m sync.Map }).Lock", ""),   # Go 1.12-1.19 wrappers
    ("go.struct { io.Reader }.Read", ""),
    ("go.shape.int", ""),
    ("example%2ecom.F", "example.com"),
    ("a.b/" * 1015 + "x.F", ""),               # absurdly deep: given up on at once
])
def test_package_of_edge_cases(name, package):
    assert package_of(name) == package


# --- bounded work ---------------------------------------------------------------
def test_many_forged_shape_candidates_do_not_each_scan_the_data():
    # Each forged header passes the header and sample checks and would cost a
    # 16 MB pointer search; only MAX_PCLN_CANDIDATES may.
    n, stride = 400, 80
    ro = bytearray(n * stride + 256)
    for k in range(n):
        struct.pack_into("<IBBBB", ro, k * stride, 0, 0, 0, 1, 8)
        struct.pack_into("<8Q", ro, k * stride + 8, 1, 0, 0, 72, 73, 74, 75, 76)
    ro[-32:-21] = b"GOMAXPROCS\0"
    blob = build_pe(64, [(b".text", b"\xc3" * 0x200, TEXT), (b".rdata", bytes(ro), RDATA),
                         (b".data", bytes(16 << 20), DATA)])[0]
    g, seconds = timed(blob)
    assert g is None and seconds < 2.0


def _old_layout_with_file_entries(entries_to_first: bool) -> bytes:
    data = bytearray(build_go_pe(64, "1.2-1.15", files=["C:/" + "A" * 4000] + ["X"] * 200_000))
    off = data.find(b"\xfb\xff\xff\xff\x00\x00\x01\x08")
    nfunc = struct.unpack_from("<Q", data, off + 8)[0]
    fto = off + struct.unpack_from("<I", data, off + 16 + (2 * nfunc + 1) * 8)[0]
    count, first = struct.unpack_from("<II", data, fto)
    if entries_to_first:
        for k in range(1, count):
            struct.pack_into("<I", data, fto + 4 * k, first)
    return bytes(data)


def test_file_entries_naming_one_path_are_read_once():
    g, seconds = timed(_old_layout_with_file_entries(True))
    assert g.confirmed and g.source_path_count == 1 and seconds < 2.0


def test_names_pointing_into_one_long_run_are_capped():
    # 100,000 _func records whose names start at successive bytes of a 4,000-byte
    # run: each would copy its own ~2 KB suffix.
    n = 100_000
    names = ["A" * 4000] * (n // 4000 + 1) + ["x"] * (n - n // 4000 - 1)
    data = bytearray(build_go_pe(64, "1.2-1.15", names=names, files=["C:/a.go"]))
    off = data.find(b"\xfb\xff\xff\xff\x00\x00\x01\x08")
    nfunc = struct.unpack_from("<Q", data, off + 8)[0]
    ftab = off + 16
    names_at = struct.unpack_from("<i", data, off + struct.unpack_from("<Q", data, ftab + 8)[0] + 8)[0]
    for k in range(nfunc):
        fo = struct.unpack_from("<Q", data, ftab + 16 * k + 8)[0]
        struct.pack_into("<i", data, off + fo + 8, names_at + k)
    g, seconds = timed(bytes(data))
    assert seconds < 3.0 and "function name table read in part" in g.notes


def test_a_forged_version_length_is_checked_before_it_is_read():
    # 128 string headers point at "go1.22" strings with a length of 3: rejected
    # without copying, so a huge length would cost nothing either.
    text = bytearray(0x400)
    bid = b'\xff Go build ID: "a/b/c/d"\n \xff'
    text[:len(bid)] = bid
    ro = bytearray(4 << 20)
    for k in range(16):
        ro[k * 16:k * 16 + 6] = b"go1.22"
    rw = bytearray(0x1000)
    sections = [(b".text", bytes(text), TEXT), (b".rdata", bytes(ro), RDATA), (b".data", bytes(rw), DATA)]
    _, base, where = build_pe(64, sections)
    q = 0
    for k in range(16):
        for _ in range(8):
            struct.pack_into("<QQ", rw, q, base + where[b".rdata"][0] + k * 16, 1 << 40)
            q += 16
    sections[2] = (b".data", bytes(rw), DATA)
    g, seconds = timed(build_pe(64, sections)[0])
    assert g.evidence == ["build-id"] and g.version is None and seconds < 1.0


def test_the_runtime_version_is_found_at_the_end_of_a_large_data_section():
    g = go(build_go_pe(64, buildinfo=None, data_pad=17 << 20))
    assert g.confirmed and g.version == "go1.22.4" and g.version_source == "runtime"


def test_an_address_beyond_the_pointer_size_is_not_a_crash():
    # PE32 plus a section mapped at the top of the address space, where a decoy
    # table magic sits: packing that address used to raise and lose everything.
    good = build_go_pe(32)
    d = bytearray(good)
    e = struct.unpack_from("<I", d, 0x3C)[0]
    opt = struct.unpack_from("<H", d, e + 20)[0]
    n = struct.unpack_from("<H", d, e + 6)[0]
    table = e + 24 + opt
    d[table + 40 * n:table + 40 * (n + 1)] = struct.pack("<8sIIIIIIHHI", b".pad", 0x200, 0xFFFFF000, 0x200,
                                                            0, 0, 0, 0, 0, 0x40000040)
    struct.pack_into("<H", d, e + 6, n + 1)
    d[0x1D8:0x1E0] = bytes.fromhex("f1ffffff00000104")
    g = go(bytes(d))
    assert g is not None and g.confirmed and "buildinfo" in g.evidence


def test_build_info_notes_leave_with_the_build_info():
    # Altered sentinels belong to a carried program's build info: not this file's.
    blob = build_go_pe(64, moduledata=False, modinfo=b"\0" * 16 + MODINFO[16:-16] + b"\0" * 16)
    g = go(blob)
    assert g.evidence == ["build-id"] and g.notes == []


# --- what the report may print ------------------------------------------------
def test_control_characters_never_reach_the_terminal():
    g = GoInfo(version="go1.22.4", evidence=["pclntab"], main_path="evil\x1b[2Jx",
               main_functions=["main.\x1b]0;owned\x07"], source_paths=["C:/\x1b[1A/m.go"], source_path_count=1,
               settings={"-ldflags": "\x1b[41mX"})
    text = "".join(line for line, _ in go_lines(g))
    assert "\x1b" not in text and "\x07" not in text
    assert "evil\\x1b[2Jx" in text and "\\x07" in text


# --- downstream ------------------------------------------------------------------
def test_go_programs_do_not_cluster_on_their_shared_import_table():
    a = triage_bytes(build_go_pe(64), name="a.exe", use_yara=False)
    b = triage_bytes(build_go_pe(64, names=["main.main", "runtime.main", "other.F"]), name="b.exe", use_yara=False)
    a.file.imphash = b.file.imphash = "f" * 32
    a.file.ssdeep = b.file.ssdeep = None
    a.file.authentihash, b.file.authentihash = "1" * 64, "2" * 64
    a.rich = b.rich = None
    assert all(len(c.members) == 1 for c in cluster_reports([a, b]))
    a.go = b.go = None                       # the same files, were they not Go
    assert any(len(c.members) == 2 for c in cluster_reports([a, b]))


@pytest.mark.parametrize("value,cell", [
    ('=HYPERLINK("http://x","go1.22")', '\'=HYPERLINK("http://x","go1.22")'),
    ("+1", "'+1"), ("@SUM(A1)", "'@SUM(A1)"), ("-cmd", "'-cmd"),
    ("go1.22.4", "go1.22.4"), (42, 42), (True, "yes"), (["=a", "b"], "'=a; b"),
])
def test_csv_cells_cannot_become_formulas(value, cell):
    assert _flatten_for_csv(value) == cell
