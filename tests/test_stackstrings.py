from types import SimpleNamespace

from gokdogan.stackstrings import _scan, recover_stackstrings


def _ebp_store(disp8: int, ch: str) -> bytes:
    # C6 45 disp8 imm8  ->  mov byte [ebp+disp8], ch
    return bytes([0xC6, 0x45, disp8 & 0xFF, ord(ch)])


def _stackstring_ebp(text: str, start_disp: int = -0x10) -> bytes:
    return b"".join(_ebp_store(start_disp + i, c) for i, c in enumerate(text))


def _recover(code: bytes) -> list[str]:
    out, seen = [], set()
    _scan(code, out, seen)
    return [d.value for d in out]


def test_recovers_simple_ebp_stackstring():
    code = b"\x90\x90" + _stackstring_ebp("http://evil") + b"\xc3"
    assert "http://evil" in _recover(code)


def test_recovered_stackstring_is_classified():
    code = _stackstring_ebp("cmd.exe /c whoami")
    out, seen = [], set()
    _scan(code, out, seen)
    hit = next(d for d in out if "cmd.exe" in d.value)
    assert hit.encoding == "stackstring"
    assert hit.category == "command"


def test_esp_base_stackstring():
    # C6 44 24 disp8 imm8 -> mov byte [esp+disp8], ch
    def esp(disp, ch):
        return bytes([0xC6, 0x44, 0x24, disp & 0xFF, ord(ch)])
    code = b"".join(esp(0x10 + i, c) for i, c in enumerate("mutex_A1"))
    assert "mutex_A1" in _recover(code)


def test_short_runs_ignored():
    assert _recover(_stackstring_ebp("ab")) == []      # below min length


def test_non_printable_breaks_run():
    # a store of a non-printable byte splits the run
    code = _stackstring_ebp("abcd") + _ebp_store(-0x0c, "\x01") + _stackstring_ebp("wxyz", -0x08)
    recovered = _recover(code)
    assert "abcd" in recovered and "wxyz" in recovered


def test_recover_stackstrings_from_fake_pe():
    code = _stackstring_ebp("http://c2.example")
    section = SimpleNamespace(Characteristics=0x20000000, get_data=lambda: code)
    data_section = SimpleNamespace(Characteristics=0x40000000, get_data=lambda: b"ignored")
    pe = SimpleNamespace(sections=[data_section, section])
    values = [d.value for d in recover_stackstrings(pe)]
    assert "http://c2.example" in values


def test_rex_prefixed_x64_stackstring():
    # REX.W (0x48) prefix before each C6 45 store — common in x64 code
    def rex_ebp(disp, ch):
        return bytes([0x48, 0xC6, 0x45, disp & 0xFF, ord(ch)])
    code = b"".join(rex_ebp(-0x20 + i, c) for i, c in enumerate("http://x.io"))
    assert "http://x.io" in _recover(code)
