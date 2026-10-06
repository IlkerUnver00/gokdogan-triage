"""In-memory Go-shaped PE images for tests (nothing is written to disk).

build_go_pe() lays out a minimal PE32 or PE32+ with .text (the build ID),
.rdata (a function table of the chosen layout, the packed version string,
the module info, a GOMAXPROCS marker) and .data (the build info,
runtime.firstmoduledata, the runtime.buildVersion string header). Each
structure has the shape the Go linker writes; there is no code to run.
"""

from __future__ import annotations

import struct

BASE32, BASE64 = 0x400000, 0x140000000
FA = 0x200
MAGIC = b"\xff Go buildinf:"
INFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
INFO_END = bytes.fromhex("f932433186182072008242104116d8f2")
LAYOUT_MAGIC = {"1.2-1.15": 0xFFFFFFFB, "1.16-1.17": 0xFFFFFFFA, "1.18-1.19": 0xFFFFFFF0,
                "1.20+": 0xFFFFFFF1}
LAYOUTS = list(LAYOUT_MAGIC)

# One name for every case package_of and the Windows API reading must handle.
NAMES = [
    "runtime.main", "runtime.goexit", "runtime.morestack", "main.main", "main.stealCookies",
    "fmt.Println", "net/http.(*Client).Do", "os/exec.(*Cmd).Run", "crypto/aes.NewCipher",
    "github.com/kbinani/screenshot.CaptureDisplay", "gopkg.in/yaml%2ev3.Marshal",
    "go.uber.org/zap.(*Logger).Info", "golang.org/x/sys/windows.VirtualAllocEx",
    "golang.org/x/sys/windows.WriteProcessMemory", "golang.org/x/sys/windows.(*LazyProc).Call",
    "syscall.CreateProcess", "syscall.LoadLibrary", "internal/syscall/windows.GetSystemDirectory",
    "slices.Sort[go.shape.int]", "type:.eq.[2]interface {}", "go:buildid", "_rt0_amd64_windows",
    "stealer/browser.(*Chrome).Passwords", "a.com/x/cmd.T.a.com/y.M",
]
PACKAGES = {"runtime", "main", "fmt", "net/http", "os/exec", "crypto/aes", "github.com/kbinani/screenshot",
            "gopkg.in/yaml.v3", "go.uber.org/zap", "golang.org/x/sys/windows", "syscall",
            "internal/syscall/windows", "slices", "stealer/browser", "a.com/x/cmd"}
FILES = ["C:/Users/bob/Desktop/stealer/main.go", "C:/Users/bob/Desktop/stealer/browser/chrome.go",
         "C:/Program Files/Go/src/runtime/proc.go", "C:/Program Files/Go/src/fmt/print.go",
         "C:/Users/bob/go/pkg/mod/github.com/kbinani/screenshot@v0.0.0/screenshot.go"]
MODINFO = (INFO_START + b"path\tstealer\nmod\tstealer\t(devel)\t\n"
           b"dep\tgithub.com/kbinani/screenshot\tv0.0.0-20230812\th1:abc=\n"
           b"dep\tgolang.org/x/sys\tv0.20.0\th1:def=\n=>\t../sys\t\n"
           b"build\t-ldflags=\"-s -w -H windowsgui -X \\\"main.key=a b\\\"\"\n"
           b"build\t-trimpath=false\nbuild\tCGO_ENABLED=0\nbuild\tGOOS=windows\n" + INFO_END)


def uvarint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def build_pe(bits: int, sections: list[tuple[bytes, bytes, int]]) -> tuple[bytes, int, dict]:
    """A PE from [(name, content, characteristics)]: (bytes, image base, {name: (rva, raw offset)})."""
    is64 = bits == 64
    base = BASE64 if is64 else BASE32
    opt_size = 0xF0 if is64 else 0xE0
    hdr_end = 0x40 + 4 + 20 + opt_size + 40 * len(sections)
    raw = (hdr_end + FA - 1) // FA * FA
    va = 0x1000
    table, body, where = [], b"", {}
    for name, content, ch in sections:
        size = (len(content) + FA - 1) // FA * FA
        table.append((name, len(content), va, size, raw + len(body), ch))
        where[name] = (va, raw + len(body))
        body += content.ljust(size, b"\0")
        va += (len(content) + 0xFFF) // 0x1000 * 0x1000
    dos = b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664 if is64 else 0x14C, len(sections), 0, 0, 0, opt_size, 0x22)
    if is64:
        opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 3, 0, 0, 0, 0, 0x1000, 0x1000,
                          base, 0x1000, FA, 6, 0, 0, 0, 6, 0, 0, va, raw, 0, 3, 0x8160,
                          0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 3, 0, 0, 0, 0, 0x1000, 0x1000,
                          0x3000, base, 0x1000, FA, 6, 0, 0, 0, 6, 0, 0, va, raw, 0, 3, 0x8140,
                          0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\0" * (opt_size - len(opt))
    sect = b"".join(struct.pack("<8sIIIIIIHHI", n, vs, v, rs, rp, 0, 0, 0, 0, c)
                    for n, vs, v, rs, rp, c in table)
    return (dos + b"PE\0\0" + coff + opt + sect).ljust(raw, b"\0") + body, base, where


TEXT, RDATA, DATA = 0x60000020, 0x40000040, 0xC0000040


def _pclntab(layout: str, ptr: int, names: list[str], files: list[str], magic: int) -> tuple[bytes, dict]:
    """(table bytes, offsets relative to the table start)."""
    w = "<Q" if ptr == 8 else "<I"
    nfunc = len(names)
    if layout == "1.2-1.15":
        # header | functab (entry, funcoff) * nfunc + end entry | u32 filetab offset | _funcs | names | filetab
        ftab = 8 + ptr
        after = ftab + (2 * nfunc + 1) * ptr
        funcs_at = (after + 4 + ptr - 1) // ptr * ptr
        fsize = ptr + 4 + 36
        names_at = funcs_at + nfunc * fsize
        blob_names, name_off = b"", []
        for n in names:
            name_off.append(names_at + len(blob_names))
            blob_names += n.encode() + b"\0"
        filetab_at = (names_at + len(blob_names) + 3) // 4 * 4
        file_strs_at = filetab_at + 4 * (len(files) + 1)
        file_blob, file_off = b"", []
        for f in files:
            file_off.append(file_strs_at + len(file_blob))
            file_blob += f.encode() + b"\0"
        out = bytearray(file_strs_at + len(file_blob))
        struct.pack_into("<IBBBB", out, 0, magic, 0, 0, 1, ptr)
        struct.pack_into(w, out, 8, nfunc)
        for k in range(nfunc):
            struct.pack_into(w + w[1], out, ftab + 2 * k * ptr, 0x1000 + 0x40 * k, funcs_at + k * fsize)
        struct.pack_into(w, out, ftab + 2 * nfunc * ptr, 0x1000 + 0x40 * nfunc)
        struct.pack_into("<I", out, after, filetab_at)
        for k in range(nfunc):
            struct.pack_into(w + "i", out, funcs_at + k * fsize, 0x1000 + 0x40 * k, name_off[k])
        out[names_at:names_at + len(blob_names)] = blob_names
        struct.pack_into("<I", out, filetab_at, len(files) + 1)
        for k, o in enumerate(file_off):
            struct.pack_into("<I", out, filetab_at + 4 * (k + 1), o)
        out[file_strs_at:] = file_blob
        return bytes(out), dict(nfunc=nfunc)
    new = layout in ("1.18-1.19", "1.20+")
    hsize = 8 + (8 if new else 7) * ptr
    pad = 24 if layout != "1.20+" else 0          # Go 1.21-1.25 leave 24 bytes after the header
    funcname = hsize + pad
    blob_names, name_off = b"", []
    for n in names:
        name_off.append(len(blob_names))
        blob_names += n.encode() + b"\0"
    cu = funcname + len(blob_names)
    cutab = b"".join(struct.pack("<I", k) for k in range(len(files)))
    filetab = cu + len(cutab)
    file_blob = b"".join(f.encode() + b"\0" for f in files)
    pctab = filetab + len(file_blob)
    pctab_blob = b"\x00" * 16
    pcln = (pctab + len(pctab_blob) + 7) // 8 * 8
    half = 4 if new else ptr
    pair = 2 * half
    funcs_at = (nfunc + 1) * pair
    fsize = half + 4 + 36
    out = bytearray(pcln + funcs_at + nfunc * fsize)
    struct.pack_into("<IBBBB", out, 0, magic, 0, 0, 1, ptr)
    words = [nfunc, len(files)] + ([0] if new else []) + [funcname, cu, filetab, pctab, pcln]
    for k, v in enumerate(words):
        struct.pack_into(w, out, 8 + k * ptr, v)
    out[funcname:cu] = blob_names
    out[cu:filetab] = cutab
    out[filetab:pctab] = file_blob
    hf = "<I" if half == 4 else w
    for k in range(nfunc + 1):
        struct.pack_into(hf + hf[1], out, pcln + k * pair, 0x40 * k, funcs_at + k * fsize if k < nfunc else 0)
    for k in range(nfunc):
        struct.pack_into(hf + "i", out, pcln + funcs_at + k * fsize, 0x40 * k, name_off[k])
    return bytes(out), dict(nfunc=nfunc, funcname=funcname, cu=cu, filetab=filetab, pctab=pctab, pcln=pcln,
                            names_len=len(blob_names), cutab_len=len(cutab), files_len=len(file_blob),
                            pctab_len=len(pctab_blob), pcln_len=len(out) - pcln)


def build_go_pe(bits: int = 64, layout: str = "1.20+", buildinfo: str | None = "inline",
                version: bytes = b"go1.22.4", modinfo: bytes = MODINFO, names: list[str] = NAMES,
                files: list[str] = FILES, magic: int | None = None, moduledata: bool = True,
                build_id: bytes | None = b"aaaa/bbbb/cccc/dddd", markers: bool = True,
                runtime_version: bool = True, zero_header: bool = False, flags: int | None = None,
                data_pad: int = 0) -> bytes:
    """A Go-shaped PE. buildinfo: "inline" (Go 1.18+), "pointer" (Go 1.13-1.17) or None.
    data_pad grows .data and moves the runtime.buildVersion header to its end,
    where the linker puts it in a large program."""
    ptr = bits // 8
    w = "<Q" if ptr == 8 else "<I"
    magic = LAYOUT_MAGIC[layout] if magic is None else magic
    pcl, meta = _pclntab(layout, ptr, names, files, magic)
    pcl_at = 0x40
    ver_packed = version + b"gsentinel"     # Go <= 1.17 packs strings with no terminator
    ver_at = pcl_at + len(pcl) + 8
    mod_at = ver_at + len(ver_packed) + 8
    marker_at = mod_at + len(modinfo) + 8
    rdata = bytearray(marker_at + 32)
    rdata[pcl_at:pcl_at + len(pcl)] = pcl
    rdata[ver_at:ver_at + len(ver_packed)] = ver_packed
    rdata[mod_at:mod_at + len(modinfo)] = modinfo
    if markers:
        rdata[marker_at:marker_at + 11] = b"GOMAXPROCS\0"
    text = bytearray(0x400)
    if build_id:
        bid = b'\xff Go build ID: "' + build_id + b'"\n \xff'
        text[0:len(bid)] = bid
    data = bytearray(0x400)
    sections = [(b".text", bytes(text), TEXT), (b".rdata", bytes(rdata), RDATA), (b".data", bytes(data), DATA)]
    _, base, where = build_pe(bits, sections)          # first pass: learn the addresses
    text_va, rdata_va, data_va = (base + where[n][0] for n in (b".text", b".rdata", b".data"))
    P = rdata_va + pcl_at
    if buildinfo == "inline":
        f = 2 if flags is None else flags
        blob = MAGIC + bytes([ptr, f]) + b"\0" * 16 + uvarint(len(version)) + version + uvarint(len(modinfo)) + modinfo
        data[0:len(blob)] = blob
        md_at = (len(blob) + 0x3F) // 0x40 * 0x40
    elif buildinfo == "pointer":
        f = 0 if flags is None else flags
        hdrs = 0x40
        data[0:16] = MAGIC + bytes([ptr, f])
        struct.pack_into(w, data, 16, data_va + hdrs)
        struct.pack_into(w, data, 16 + ptr, data_va + hdrs + 2 * ptr)
        struct.pack_into(w + w[1], data, hdrs, rdata_va + ver_at, len(version))
        struct.pack_into(w + w[1], data, hdrs + 2 * ptr, rdata_va + mod_at, len(modinfo))
        md_at = 0x80
    else:
        md_at = 0x40
    if len(data) < md_at + 0x200:                  # a large module info pushes the rest along
        data.extend(b"\0" * (md_at + 0x200 - len(data)))
    if moduledata:
        if layout == "1.2-1.15":
            words = [P, len(pcl), len(pcl), P + 8 + ptr, meta["nfunc"] + 1, meta["nfunc"] + 1, 0, 0, 0, 0,
                     text_va, text_va + 0x200, text_va, text_va + 0x200]
        else:
            m = meta
            tabs = [(m["funcname"], m["names_len"]), (m["cu"], m["cutab_len"]), (m["filetab"], m["files_len"]),
                    (m["pctab"], m["pctab_len"]), (m["pcln"], m["pcln_len"])]
            words = [P]
            for off, n in tabs:
                words += [P + off, n, n]
            words += [P + m["pcln"], m["nfunc"] + 1, m["nfunc"] + 1, 0, text_va, text_va + 0x200,
                      text_va, text_va + 0x200]
        for k, v in enumerate(words):
            struct.pack_into(w, data, md_at + k * ptr, v)
    if data_pad:
        data.extend(bytes(data_pad))
    if runtime_version:
        rv_at = len(data) - 0x40 if data_pad else md_at + 0x100
        struct.pack_into(w + w[1], data, rv_at, rdata_va + ver_at, len(version))
    if zero_header:
        # The runtime never reads these; for 1.2-1.15 the header is nfunc alone.
        for k in range(1 if layout == "1.2-1.15" else (8 if layout in ("1.18-1.19", "1.20+") else 7)):
            struct.pack_into(w, rdata, pcl_at + 8 + k * ptr, 0)
    sections = [(b".text", bytes(text), TEXT), (b".rdata", bytes(rdata), RDATA), (b".data", bytes(data), DATA)]
    return build_pe(bits, sections)[0]
