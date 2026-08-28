import base64

from gokdogan.capabilities import infer_capabilities
from gokdogan.decoded import _rol8, recover_encoded_strings


def _xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _add(data: bytes, key: int) -> bytes:
    return bytes((b + key) & 0xFF for b in data)


def _rol_bytes(data: bytes, count: int) -> bytes:
    return bytes(_rol8(b, count) for b in data)


def test_recovers_xor_encoded_url():
    plain = b"visit http://evil.example/gate.php now"
    blob = b"\x00" * 32 + _xor(plain, 0x5A) + b"\x00" * 32
    results = recover_encoded_strings(blob)
    urls = [d for d in results if d.category == "url"]
    assert any("evil.example" in d.value for d in urls)
    assert any(d.encoding == "xor-0x5a" for d in urls)


def test_recovers_add_encoded_command():
    plain = b"cmd.exe /c whoami && powershell -enc AAAA"
    blob = _add(plain, 0x0D)
    results = recover_encoded_strings(blob)
    assert any(d.category == "command" for d in results)
    assert any(d.encoding == "add-0x0d" for d in results)


def test_recovers_rol_encoded_registry():
    plain = b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run key"
    blob = _rol_bytes(plain, 3)
    results = recover_encoded_strings(blob)
    assert any(d.encoding == "rol-3" for d in results)
    assert any(d.category == "registry" for d in results)


def test_add_command_detected_via_command_anchor_only():
    # Contains "vssadmin"/"cmd.exe" but none of the URL/registry anchors —
    # exercises the full-anchor adjacency detection (not just the URL path).
    plain = b"cmd.exe /c vssadmin delete shadows /all /quiet"
    blob = b"\xff" * 8 + _add(plain, 0x0D) + b"\xff" * 8
    results = recover_encoded_strings(blob)
    assert any(d.category == "command" and d.encoding == "add-0x0d" for d in results)


def test_isolated_xor_url_with_nonprintable_padding():
    plain = b"http://c2.example/gate"
    blob = b"\xff" * 8 + _xor(plain, 0x5A) + b"\xff" * 8
    results = recover_encoded_strings(blob)
    assert any(d.value == "http://c2.example/gate" and d.encoding == "xor-0x5a" for d in results)


def test_base64_embedded_pe():
    fake_pe = b"MZ" + b"\x90" * 80
    blob = b"config=" + base64.b64encode(fake_pe) + b";"
    results = recover_encoded_strings(blob)
    assert any(d.category == "embedded-pe" and d.encoding == "base64" for d in results)


def test_base64_encoded_url():
    payload = base64.b64encode(b"http://10.10.10.10:8080/beacon")
    results = recover_encoded_strings(b"data: " + payload)
    assert any(d.category == "url" and d.encoding == "base64" for d in results)


def test_hex_encoded_url():
    payload = b"http://185.44.2.9/c2".hex().encode("ascii")
    results = recover_encoded_strings(b"target=" + payload + b";")
    assert any(d.category == "url" and d.encoding == "hex" for d in results)


def test_hex_embedded_pe():
    blob = (b"MZ" + b"\x90" * 90).hex().encode("ascii")
    results = recover_encoded_strings(b"stage1=" + blob)
    assert any(d.category == "embedded-pe" and d.encoding == "hex" for d in results)


def test_hex_sha256_is_not_reported():
    # a bare 64-char hex hash decodes to non-classifiable bytes -> dropped
    sha = (b"deadbeef" * 8)
    results = recover_encoded_strings(b"hash=" + sha)
    assert all(d.encoding != "hex" for d in results)


def test_clean_data_recovers_nothing():
    # Plain ASCII with no encoded anchors must not produce phantom hits.
    benign = b"The quick brown fox jumps over the lazy dog. " * 50
    assert recover_encoded_strings(benign) == []


def test_plaintext_url_is_not_double_reported():
    # An unencoded URL is handled by the normal string pass, not this one
    # (key 0 is skipped), so the XOR pass must not re-report it as xor-0x00.
    results = recover_encoded_strings(b"http://plain.example/path here")
    assert all(d.encoding != "xor-0x00" for d in results)


def test_decoded_yields_obfuscation_capability():
    plain = b"beacon http://c2.example/x"
    results = recover_encoded_strings(_xor(plain, 0x33))
    caps = infer_capabilities({}, [], None, None, results)
    obf = next((c for c in caps if c.name == "string-obfuscation"), None)
    assert obf is not None
    assert "T1140" in obf.attack
