"""Stack-string recovery (pattern-based, no emulator).

Malware often builds a string on the stack one byte at a time so it never
appears contiguously in the file:

    mov byte ptr [ebp-0x20], 'h'
    mov byte ptr [ebp-0x1f], 't'
    mov byte ptr [ebp-0x1e], 't'
    mov byte ptr [ebp-0x1d], 'p'   ...

Full FLOSS recovers these by emulating code with unicorn; that is a heavy,
fragile dependency this tool deliberately avoids. Instead we scan the
executable sections for the exact x86 encodings of single-byte stack stores
(``C6 /0`` with an ebp/esp base) and reconstruct each run of printable
immediates ordered by displacement. It catches the common compiler idiom
with nothing but a byte scan — no disassembler, no emulator.
"""

from __future__ import annotations

from .models import DecodedString
from .strings_ext import classify

_MIN_LEN = 4
_MAX_RESULTS = 60


def _printable(byte: int) -> bool:
    return 0x20 <= byte <= 0x7E


def _emit(base: str, chars: dict[int, int], out: list[DecodedString], seen: set[str]) -> None:
    if len(chars) < _MIN_LEN:
        return
    # A real stack string writes *consecutive* slots; requiring contiguous
    # displacements rejects scattered incidental C6 /0 stores in normal code.
    disps = sorted(chars)
    if disps[-1] - disps[0] != len(disps) - 1:
        return
    text = bytes(chars[d] for d in disps).decode("latin-1")
    if not any(ch.isalnum() for ch in text) or text in seen:
        return
    seen.add(text)
    out.append(DecodedString(value=text[:300], encoding="stackstring",
                             category=classify(text) or "stackstring", offset=0))


def _scan(code: bytes, out: list[DecodedString], seen: set[str]) -> None:
    """Scan one code blob for runs of single-byte stack stores."""
    i, n = 0, len(code)
    run: dict[int, int] = {}
    run_base = ""

    def flush():
        nonlocal run, run_base
        if run:
            _emit(run_base, run, out, seen)
            run = {}
            run_base = ""

    while i < n - 2 and len(out) < _MAX_RESULTS:
        if code[i] != 0xC6:
            if run:
                flush()
            i += 1
            continue
        modrm = code[i + 1]
        disp = imm = base = length = None
        # C6 45 disp8 imm8  -> [ebp+disp8]
        if modrm == 0x45 and i + 3 < n:
            base, disp, imm, length = "ebp", _s8(code[i + 2]), code[i + 3], 4
        # C6 44 24 disp8 imm8 -> [esp+disp8]
        elif modrm == 0x44 and i + 4 < n and code[i + 2] == 0x24:
            base, disp, imm, length = "esp", _s8(code[i + 3]), code[i + 4], 5
        # C6 85 disp32 imm8 -> [ebp+disp32]
        elif modrm == 0x85 and i + 6 < n:
            base, disp, imm, length = "ebp", _s32(code[i + 2:i + 6]), code[i + 6], 7
        # C6 84 24 disp32 imm8 -> [esp+disp32]
        elif modrm == 0x84 and i + 7 < n and code[i + 2] == 0x24:
            base, disp, imm, length = "esp", _s32(code[i + 3:i + 7]), code[i + 7], 8

        if length and _printable(imm):
            if run_base and base != run_base:
                flush()
            run_base = base
            run[disp] = imm
            i += length
        else:
            if run:
                flush()
            i += 1
    if run:
        _emit(run_base, run, out, seen)


def _s8(b: int) -> int:
    return b - 256 if b >= 128 else b


def _s32(bs: bytes) -> int:
    v = int.from_bytes(bs, "little")
    return v - (1 << 32) if v >= (1 << 31) else v


def recover_stackstrings(pe) -> list[DecodedString]:
    """Recover stack strings from a PE's executable sections."""
    out: list[DecodedString] = []
    seen: set[str] = set()
    for section in getattr(pe, "sections", []):
        if not (section.Characteristics & 0x20000000):   # executable only
            continue
        try:
            code = section.get_data()
        except Exception:  # pragma: no cover - defensive
            continue
        _scan(code, out, seen)
        if len(out) >= _MAX_RESULTS:
            break
    return out
