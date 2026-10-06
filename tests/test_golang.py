"""The Go stage: build info, function table, ownership, and what it reads from them."""

from __future__ import annotations

import copy
import random
import struct
import time
from pathlib import Path

import pefile
import pytest
from archetypes import ARCHETYPES
from gofixtures import (
    DATA,
    FILES,
    LAYOUTS,
    MAGIC,
    MODINFO,
    PACKAGES,
    RDATA,
    TEXT,
    build_go_pe,
    build_pe,
    uvarint,
)

import gokdogan.engine as engine
from gokdogan.golang import _unquote, analyze_go, package_kind, package_of
from gokdogan.models import GoInfo
from gokdogan.verdict import score_report


def go(blob: bytes) -> GoInfo | None:
    return analyze_go(pefile.PE(data=blob, fast_load=True), blob)


def timed(blob: bytes) -> tuple[GoInfo | None, float]:
    pe = pefile.PE(data=blob, fast_load=True)
    t = time.perf_counter()
    g = analyze_go(pe, blob)
    return g, time.perf_counter() - t


# --- a) the layout matrix ---------------------------------------------------
# Go 1.18+ writes inline build info next to the 1.18+ tables; 1.13-1.17 the
# pointer form next to the older ones; a build can also carry none.
MATRIX = [(bits, layout, bi) for bits in (32, 64) for layout in LAYOUTS
          for bi in (("inline" if layout in ("1.18-1.19", "1.20+") else "pointer"), None)]


@pytest.mark.parametrize("bits,layout,buildinfo", MATRIX)
def test_every_layout_is_read_the_same(bits, layout, buildinfo):
    g = go(build_go_pe(bits, layout, buildinfo=buildinfo))
    assert g is not None and g.confirmed
    assert g.pclntab_layout == layout and g.ptr_size == bits // 8
    assert set(g.packages) == PACKAGES
    assert (g.std_package_count, g.third_party_count, g.local_package_count) == (8, 5, 1)
    assert g.version == "go1.22.4"
    assert g.version_source == ("buildinfo" if buildinfo else "runtime")
    assert {"VirtualAllocEx", "CreateProcess", "GetSystemDirectory"} <= set(g.winapi) and g.proc_call
    assert g.main_functions == ["main.main", "main.stealCookies"]
    assert g.goroot == "C:/Program Files/Go/src/" and g.source_path_count == 2
    assert g.source_paths == sorted(FILES[:2])
    if buildinfo:
        assert g.evidence == ["buildinfo", "pclntab", "build-id"]
        assert g.buildinfo_format == buildinfo and g.main_path == "stealer"
        assert g.main_module is not None and g.main_module.version == "(devel)"
        assert g.dep_count == 2 and g.deps[1].replace == "../sys"
        assert g.settings["-ldflags"] == '-s -w -H windowsgui -X "main.key=a b"'
        assert g.cgo is False and g.trimpath is False
        assert g.obfuscation == []
    else:
        assert g.evidence == ["pclntab", "build-id"]


# --- b) build info removed --------------------------------------------------
@pytest.mark.parametrize("layout", LAYOUTS[1:])
def test_missing_build_info_is_flagged_where_go_writes_it(layout):
    g = go(build_go_pe(64, layout, buildinfo=None))
    assert "no build info (removed)" in g.obfuscation


@pytest.mark.parametrize("version,flagged", [(b"go1.12.3", False), (b"go1.15.2", True)])
def test_old_tables_flag_missing_build_info_only_from_go_1_13(version, flagged):
    g = go(build_go_pe(64, "1.2-1.15", buildinfo=None, version=version))
    assert g.version == version.decode() and g.version_source == "runtime"
    assert ("no build info (removed)" in g.obfuscation) == flagged


# --- c) garble's shape --------------------------------------------------------
def test_a_replaced_magic_is_still_found_when_the_file_looks_like_go():
    g = go(build_go_pe(64, buildinfo=None, magic=0x5A17C0DE, build_id=None))
    assert g is not None and g.confirmed and set(g.packages) == PACKAGES
    assert "pclntab magic replaced (0x5a17c0de)" in g.obfuscation


def test_the_magic_agnostic_search_needs_a_reason_to_run():
    assert go(build_go_pe(64, buildinfo=None, magic=0x5A17C0DE, build_id=None, markers=False)) is None
    g = go(build_go_pe(64, buildinfo=None, magic=0x5A17C0DE, build_id=b"x/y", markers=False))
    assert g is not None and g.confirmed


# --- d) header altered: the runtime's own moduledata wins ---------------------
@pytest.mark.parametrize("layout", LAYOUTS)
def test_an_altered_header_is_read_through_moduledata(layout):
    g = go(build_go_pe(64, layout, buildinfo=None, zero_header=True))
    assert g is not None and g.confirmed and set(g.packages) == PACKAGES
    assert "pclntab header disagrees with runtime.firstmoduledata (altered)" in g.obfuscation


def test_a_forged_function_count_is_corrected_from_moduledata():
    blob = bytearray(build_go_pe(64, "1.20+"))
    i = blob.find(struct.pack("<I", 0xFFFFFFF1) + b"\0\0\x01\x08")
    struct.pack_into("<Q", blob, i + 8, 0xFFFFFFFF)
    g = go(bytes(blob))
    assert g.confirmed and g.function_count == 24 and set(g.packages) == PACKAGES
    assert any("altered" in o for o in g.obfuscation)


# --- e) a table nothing in the image points at is someone else's -------------
def test_build_info_next_to_a_carried_table_is_not_this_files():
    assert go(build_go_pe(64, moduledata=False, build_id=None)) is None


def test_a_carried_program_is_listed_but_the_build_id_decides():
    g = go(build_go_pe(64, moduledata=False))
    assert g.evidence == ["build-id"] and not g.confirmed and g.packages == []
    assert g.embedded == ["Go program at 0x640: pclntab 1.20+, 24 functions, not used by this image"]


@pytest.mark.parametrize("bits", (32, 64))
@pytest.mark.parametrize("where", ("data", "rdata"))
def test_a_stub_carrying_a_go_program_is_not_go(bits, where):
    payload = build_go_pe(bits)
    filler = b"\xcc" * 64
    sections = [(b".text", filler, TEXT), (b".rdata", payload if where == "rdata" else filler, RDATA),
                (b".data", payload if where == "data" else b"\0" * 64, DATA)]
    assert go(build_pe(bits, sections)[0]) is None


# --- f) one kind of evidence --------------------------------------------------
def test_build_info_opens_the_magic_agnostic_search():
    g = go(build_go_pe(64, magic=0x12345678, markers=False, build_id=None))
    assert g.evidence == ["buildinfo", "pclntab"] and g.confirmed
    assert "pclntab magic replaced (0x12345678)" in g.obfuscation


def test_build_info_alone_is_go_but_not_confirmed():
    g = go(build_go_pe(64, magic=0x12345678, markers=False, build_id=None, moduledata=False))
    assert g.evidence == ["buildinfo"] and not g.confirmed and g.version == "go1.22.4"
    assert g.main_path == "stealer" and g.packages == []


def test_a_build_id_alone_gives_no_version():
    g = go(build_go_pe(64, buildinfo=None, magic=0x12345678, markers=False, runtime_version=False,
                       moduledata=False))
    assert g.evidence == ["build-id"] and g.build_id == "aaaa/bbbb/cccc/dddd" and g.version is None


# --- g) what must not be called Go --------------------------------------------
GIT_TRAP = MAGIC + b"\x001.21.0\0This program was built by git-lfs"


@pytest.mark.parametrize("bits", (32, 64))
@pytest.mark.parametrize("placement", ("rdata unaligned", "rdata aligned", "data aligned"))
def test_the_git_exe_trap(bits, placement):
    # Git for Windows' C programs carry the magic as text (git-lfs detection).
    filler = b"\xcc" * 64
    trap = (b"\0" * 12 + GIT_TRAP) if placement == "rdata unaligned" else GIT_TRAP
    sections = [(b".text", filler, TEXT),
                (b".rdata", trap if placement.startswith("rdata") else filler, RDATA),
                (b".data", trap if placement == "data aligned" else b"\0" * 64, DATA)]
    assert go(build_pe(bits, sections)[0]) is None


def _bare(bits: int, data: bytes) -> bytes:
    """A PE with nothing Go-like but `data` in its .data section."""
    return build_pe(bits, [(b".text", b"\xcc" * 64, TEXT), (b".rdata", b"\0" * 64, RDATA),
                           (b".data", data, DATA)])[0]


def _inline(ptr: int = 8, flags: int = 2, pad: bytes = b"\0" * 16, version: bytes = b"go1.22.4",
            vlen: bytes | None = None) -> bytes:
    return (MAGIC + bytes([ptr, flags]) + pad + (uvarint(len(version)) if vlen is None else vlen)
            + version + uvarint(len(MODINFO)) + MODINFO)


@pytest.mark.parametrize("header", [
    pytest.param(b"\0" * 4 + _inline(), id="unaligned"),
    pytest.param(_inline(ptr=4), id="pointer size of the other PE class"),
    pytest.param(_inline(flags=1), id="big-endian flag"),
    pytest.param(_inline(flags=3), id="flags 3"),
    pytest.param(_inline(flags=4), id="flags 4"),
    pytest.param(_inline(pad=b"\0" * 15 + b"\1"), id="inline padding not zero"),
    pytest.param(_inline(version=b"", vlen=b"\0"), id="empty version"),
    pytest.param(_inline(version=b"g" * 129), id="version over 128"),
    pytest.param(MAGIC + b"\x08\x02" + b"\0" * 16 + b"\xff" * 10 + b"\x01", id="11-byte varint"),
    pytest.param(_inline(version=b"go1.22\x01"), id="unprintable version"),
    pytest.param(MAGIC + b"\x08\x02" + b"\0" * 16 + uvarint(1 << 30) + b"go1", id="version past the end"),
])
def test_malformed_inline_headers_are_not_go(header):
    assert go(_bare(64, header)) is None


@pytest.mark.parametrize("bits", (32, 64))
def test_pointer_form_with_wild_or_circular_pointers_is_not_go(bits):
    ptr = bits // 8
    w = "<Q" if ptr == 8 else "<I"
    base = 0x140000000 if bits == 64 else 0x400000
    data_va = base + 0x3000                       # .text and .rdata take a page each
    wild = MAGIC + bytes([ptr, 0]) + struct.pack(w + w[1], 0xDEADBEEF, 0xFEEDFACE)
    circular = MAGIC + bytes([ptr, 0]) + struct.pack(w + w[1], data_va, data_va)
    for header in (wild, circular):
        assert go(_bare(bits, header.ljust(64, b"\0"))) is None


def test_pe32_pointer_form_needs_zero_padding():
    w = "<I"
    header = MAGIC + bytes([4, 0]) + struct.pack(w + w[1], 0x403040, 0x403050) + b"\x01" * 8
    assert go(_bare(32, header.ljust(128, b"\0"))) is None


@pytest.mark.parametrize("bits", (32, 64))
def test_an_endian_flag_drops_the_build_info_but_the_table_still_says_go(bits):
    g = go(build_go_pe(bits, flags=3))
    assert g is not None and "buildinfo" not in g.evidence and g.confirmed


# --- h) accepted, with notes --------------------------------------------------
def test_a_version_that_is_not_a_toolchain_is_kept_and_flagged():
    g = go(build_go_pe(64, version=b"unknown"))
    assert g.version == "unknown"
    assert "build info version 'unknown' is not a Go toolchain version" in g.obfuscation


def test_empty_module_info_is_flagged():
    g = go(build_go_pe(64, modinfo=b""))
    assert g.main_path == "" and "build info carries no module information (removed)" in g.obfuscation


def test_module_info_is_capped():
    lines = b"".join(b"dep\tex.com/m%d\tv1.0.0\th1:x=\n" % k for k in range(100_000))
    g = go(build_go_pe(64, modinfo=MODINFO[:16] + lines + MODINFO[-16:]))
    assert len(g.deps) == 500 and g.dep_count == 20_000
    assert "module info has too many lines, read in part" in g.notes
    assert any("over 1048576 bytes" in n for n in g.notes)


def test_altered_sentinels_are_noted():
    g = go(build_go_pe(64, modinfo=b"\0" * 16 + MODINFO[16:-16] + b"\0" * 16))
    assert g.main_path == "stealer" and "module info sentinels altered" in g.notes


# --- i) hostile input stays bounded -------------------------------------------
@pytest.fixture(scope="module")
def hostile() -> dict[str, bytes]:
    tails = (b"\0\0\x01\x08" * 300_000) + b"GOMAXPROCS"
    needles = b"\xf1\xff\xff\xff\x00\x00\x01\x08" * 20_000
    headers = b"".join(MAGIC + b"\x08\x02" + b"\0" * 16 for _ in range(4000))
    old = bytearray(0x2100000)                    # room for the 32 MB function table it claims
    struct.pack_into("<IBBBBQ", old, 0x40, 0xFFFFFFFB, 0, 0, 1, 8, 2_000_000)
    return {
        "shape tails": _bare(64, tails),
        "needles": _bare(64, needles),
        "decoy build info": _bare(64, headers),
        "1.2 header with 2M functions over zeros": _bare(64, bytes(old)),
    }


@pytest.mark.parametrize("case", ["shape tails", "needles", "decoy build info",
                                  "1.2 header with 2M functions over zeros"])
def test_hostile_inputs_are_bounded(hostile, case):
    g, seconds = timed(hostile[case])
    assert seconds < 2.0
    assert g is None or not g.confirmed


def test_many_sections_mapping_the_same_bytes_are_read_once():
    blob = bytearray(build_pe(64, [(b".text", b"\xcc" * 64, TEXT), (b".data", b"\0" * 64, DATA)])[0])
    body = (b"\0\0\x01\x08" * 4 + MAGIC + b"\x08\x02" + b"\0" * 16) * ((16 << 20) // 48) + b"GOMAXPROCS"
    raw = len(blob)
    blob += body
    pe = pefile.PE(data=bytes(blob), fast_load=True)
    # Rewrite the section table so 96 headers all map the same raw bytes.
    sec = pe.sections[1]
    sec.PointerToRawData, sec.SizeOfRawData = raw, len(body)
    pe.FILE_HEADER.NumberOfSections = 2
    data = pe.write()
    pe = pefile.PE(data=data, fast_load=True)
    pe.sections.extend(copy.copy(pe.sections[1]) for _ in range(94))
    t = time.perf_counter()
    g = analyze_go(pe, data)
    assert time.perf_counter() - t < 2.0
    assert g is None or not g.confirmed


# --- j) hostile names -----------------------------------------------------------
def test_hostile_function_names_do_not_break_the_reading():
    names = ["syscall.Sys/all", "x" * 4096, "\udcff", "<script>alert(1)</script>.f", "main.main"]
    blob = build_go_pe(64, names=[n.encode("utf-8", "surrogateescape").decode("latin-1") for n in names])
    g = go(blob)
    assert g is not None and g.confirmed and "main.main" in g.main_functions


# --- k) fuzz ----------------------------------------------------------------------
@pytest.mark.parametrize("layout,buildinfo", [("1.20+", "inline"), ("1.2-1.15", None)])
def test_mutated_fixtures_never_raise(layout, buildinfo):
    base = build_go_pe(64, layout, buildinfo=buildinfo)
    rnd = random.Random(11)
    for _ in range(1500):
        d = bytearray(base)
        for _ in range(rnd.randint(1, 16)):
            d[rnd.randrange(0x400, len(d))] = rnd.randrange(256)
        if rnd.random() < 0.1:
            d = d[:rnd.randrange(0x400, len(d))]
        try:
            pe = pefile.PE(data=bytes(d), fast_load=True)
        except pefile.PEFormatError:
            continue
        t = time.perf_counter()
        g = analyze_go(pe, bytes(d))          # must not raise
        assert time.perf_counter() - t < 1.0
        assert g is None or isinstance(g, GoInfo)


# --- l) names to packages ---------------------------------------------------------
@pytest.mark.parametrize("name,package", [
    ("github.com/cli/cli/v2/pkg/cmd/root.NewCmdRoot", "github.com/cli/cli/v2/pkg/cmd/root"),
    ("go.uber.org/zap.(*Logger).Info", "go.uber.org/zap"),
    ("gopkg.in/yaml%2ev3.Marshal", "gopkg.in/yaml.v3"),
    ("github.com/nats-io/nats.go/encoders/builtin.(*JsonEncoder).Encode",
     "github.com/nats-io/nats.go/encoders/builtin"),
    ("a.com/x/cmd.T.a.com/y.M", "a.com/x/cmd"),
    ("crypto/hkdf.Key[go.shape.func() hash.Hash]", "crypto/hkdf"),
    ("vendor/golang.org/x/net/dns/dnsmessage.(*Parser).Start", "vendor/golang.org/x/net/dns/dnsmessage"),
    ("runtime.main", "runtime"),
    ("main.main", "main"),
    ("type:.eq.[2]interface {}", ""),
    ("go:buildid", ""),
    ("__x86.get_pc_thunk.bx", ""),
])
def test_package_of(name, package):
    assert package_of(name) == package


@pytest.mark.parametrize("package,kind", [
    ("net/http", "std"), ("vendor/golang.org/x/net/dns/dnsmessage", "std"),
    ("github.com/spf13/cobra", "third-party"), ("main", "main"), ("stealer/browser", "local"),
])
def test_package_kind(package, kind):
    assert package_kind(package) == kind


@pytest.mark.parametrize("quoted,plain", [
    ('"-s -w -X \\"main.key=a b\\""', '-s -w -X "main.key=a b"'),
    ('"tab\\there"', "tab\there"),
    ('"\\x41\\u00e7\\U0001F600"', "A\u00e7\U0001F600"),
    ('"\\xZZ"', '"\\xZZ"'),                 # bad escapes stay raw
    ('"\\U00110000"', '"\\U00110000"'),
    ("plain", "plain"),
])
def test_unquote(quoted, plain):
    assert _unquote(quoted) == plain


# --- m) no scoring change -----------------------------------------------------------
def _rich_go() -> GoInfo:
    return GoInfo(version="go1.22.4", evidence=["buildinfo", "pclntab"], confirmed=True,
                  winapi=["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
                  obfuscation=["pclntab magic replaced (0x5a17c0de)", "no build info (removed)"],
                  embedded=["Go program at 0x40: pclntab 1.20+, 24 functions, not used by this image"],
                  packages=sorted(PACKAGES), main_functions=["main.stealCookies"])


@pytest.mark.parametrize("name", sorted(ARCHETYPES))
def test_go_facts_do_not_change_any_score(name):
    make = ARCHETYPES[name][0]
    plain, with_go = make(), make()
    with_go.go = _rich_go()
    score_report(plain)
    score_report(with_go)
    assert (with_go.score, with_go.verdict, with_go.score_breakdown) == \
           (plain.score, plain.verdict, plain.score_breakdown)


def test_the_stage_changes_nothing_but_the_go_field(monkeypatch):
    blob = build_go_pe(64)
    with_go = engine.triage_bytes(blob, name="fixture.exe", use_yara=False)
    monkeypatch.setattr(engine, "analyze_go", lambda pe, data: None)
    without = engine.triage_bytes(blob, name="fixture.exe", use_yara=False)
    assert with_go.go is not None and without.go is None
    for field in ("score_breakdown", "anomalies", "capabilities", "verdict", "score"):
        assert getattr(with_go, field) == getattr(without, field), field


# --- real Go programs on this machine -----------------------------------------------
GH = Path(r"C:\Program Files\GitHub CLI\gh.exe")
WINCRED = Path(r"C:\Program Files\Docker\Docker\resources\bin\docker-credential-wincred.exe")
VMREST = Path(r"C:\Program Files (x86)\VMware\VMware Workstation\vmrest.exe")
GIT_DIRS = [Path(r"C:\Program Files\Git\mingw64\bin"), Path(r"C:\Program Files\Git\mingw64\libexec\git-core")]
NON_GO = [Path(r"C:\Windows\System32\notepad.exe"), Path(r"C:\Windows\System32\kernel32.dll")]


def _real(path: Path) -> GoInfo | None:
    data = path.read_bytes()
    return analyze_go(pefile.PE(data=data, fast_load=True), data)


@pytest.mark.skipif(not GH.exists(), reason="GitHub CLI not installed")
def test_gh():
    t = time.perf_counter()
    g = _real(GH)
    assert time.perf_counter() - t < 2.0
    assert g.version.startswith("go1.") and {"buildinfo", "pclntab"} <= set(g.evidence) and g.confirmed
    assert g.ptr_size == 8 and g.main_path == "github.com/cli/cli/v2/cmd/gh"
    assert g.main_module.path == "github.com/cli/cli/v2" and g.dep_count > 50
    assert "github.com/spf13/cobra" in g.packages and g.winapi


@pytest.mark.skipif(not VMREST.exists(), reason="VMware Workstation not installed")
def test_a_32_bit_cgo_program():
    g = _real(VMREST)
    assert g.ptr_size == 4 and g.confirmed and g.build_id


@pytest.mark.skipif(not WINCRED.exists(), reason="Docker Desktop not installed")
def test_a_whole_triage_of_a_go_program_reports_it():
    report = engine.triage(WINCRED, use_yara=False)
    assert report.go is not None and report.go.confirmed
    assert report.to_dict()["go"]["version"].startswith("go1.")


def _git_binaries_with_the_magic() -> list[Path]:
    out = []
    for d in GIT_DIRS:
        if d.is_dir():
            # git-lfs.exe is a real Go program shipped beside them.
            out += [p for p in d.glob("*.exe") if p.name != "git-lfs.exe" and MAGIC in p.read_bytes()]
    return out


@pytest.mark.skipif(not any(d.is_dir() for d in GIT_DIRS), reason="Git for Windows not installed")
def test_gits_c_programs_are_not_go():
    files = _git_binaries_with_the_magic()
    if not files:
        pytest.skip("this Git version carries no build-info text")
    assert [p.name for p in files if _real(p) is not None] == []


@pytest.mark.parametrize("path", NON_GO, ids=lambda p: p.name)
def test_native_windows_files_are_not_go(path):
    if not path.exists():
        pytest.skip(f"{path} not available")
    assert _real(path) is None


# --- reporting ----------------------------------------------------------------------
def _go_report():
    return engine.triage_bytes(build_go_pe(64), name="fixture.exe", use_yara=False)


def test_console_shows_the_go_block():
    import io

    from gokdogan.report import render_console

    buf = io.StringIO()
    render_console(_go_report(), buf)
    out = buf.getvalue()
    assert "  Go         : go1.22.4 (buildinfo + pclntab + build-id, confirmed) · 24 functions in 15 packages" in out
    assert "main stealer · module stealer (devel) · 2 dependencies" in out
    assert "third-party: a.com/x/cmd, github.com/kbinani/screenshot, go.uber.org/zap, golang.org/x/sys/" in out
    assert "Windows API linked: 5 (CreateProcess" in out
    assert "main.*: main.stealCookies" in out
    assert "source: C:/Users/bob/Desktop/stealer/browser/chrome.go (+1 more); GOROOT C:/Program Files/Go/src/" in out


def test_console_counts_what_it_does_not_show():
    from gokdogan.report import go_lines

    g = GoInfo(version="go1.24.1", evidence=["buildinfo"], winapi=[f"Api{k:02d}" for k in range(12)],
               packages=[f"ex{k}.com/p" for k in range(9)], third_party_count=9)
    text = " | ".join(line for line, _ in go_lines(g))
    assert "Windows API linked: 12 (Api00, Api01, Api02, Api03, Api04, Api05, Api06, Api07, +4 more)" in text
    assert "+3 more" in text


def test_html_escapes_everything_the_go_stage_read():
    from gokdogan.html_report import render_html
    from gokdogan.models import GoModule

    evil = "<script>alert(1)</script>"
    report = _go_report()
    g = report.go
    g.main_path = evil
    g.packages = [f"ex.com/{evil}"]
    g.deps = [GoModule(f"ex.com/{evil}", "v1", "", evil)]
    g.settings = {evil: evil}
    g.winapi = [evil]
    g.source_paths = [evil]
    g.embedded = [evil]
    g.notes = [evil]
    g.obfuscation = [evil]
    html = render_html(report)
    assert evil not in html and "&lt;script&gt;" in html


def test_the_summary_has_a_go_column_after_dotnet():
    from gokdogan.summary import FIELDS, summary_row

    assert FIELDS[FIELDS.index("dotnet") + 1] == "go"
    assert summary_row(_go_report())["go"] == "go1.22.4"


def test_sweep_rows_carry_the_go_facts():
    import sys
    from pathlib import Path as _P

    sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "scripts"))
    from benign_sweep import report_fields

    row = report_fields(_go_report(), use_yara=False)
    assert row["go"] is True
    go = row["features"]["go"]
    assert go["version"] == "go1.22.4" and go["confirmed"] and go["third_party"] == 5
    assert "github.com/kbinani/screenshot" in go["third_party_packages"] and go["local_packages"] == ["stealer/browser"]
    assert go["settings"]["-ldflags"].startswith("-s -w") and "VirtualAllocEx" in go["winapi"]
