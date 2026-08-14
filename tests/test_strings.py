from peregrine.strings_ext import analyze_strings, classify, extract_strings


def test_extract_ascii_and_wide():
    data = b"\x00\x01AAAAAAAA\x00\x02" + "wide-string!".encode("utf-16le") + b"\x00\x00"
    found, total = extract_strings(data, min_length=6)
    texts = [t for t, _, _ in found]
    assert "AAAAAAAA" in texts
    assert "wide-string!" in texts
    assert total == 2


def test_classify_url():
    assert classify("http://evil.example/payload.bin") == "url"
    assert classify("https://203.0.113.7:8443/gate.php") == "url"


def test_classify_ipv4_rejects_version_lookalikes():
    assert classify("203.0.113.7") == "ipv4"
    assert classify("6.1.7601.17514") is None
    assert classify("999.1.1.1") is None


def test_classify_registry_and_command():
    assert classify(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") == "registry"
    assert classify("cmd.exe /c whoami") == "command"
    assert classify("powershell -enc SQBFAFgA") == "command"
    assert classify("vssadmin delete shadows /all /quiet") == "command"


def test_classify_pdb_and_path():
    assert classify(r"C:\Users\dev\project\Release\stealer.pdb") == "pdb"
    assert classify(r"C:\ProgramData\svchost.exe") == "path"


def test_noise_is_dropped():
    assert classify("http://www.microsoft.com/pki/certs") is None
    assert classify("http://crl.digicert.com/sha2.crl") is None


def test_analyze_deduplicates_and_counts():
    blob = (b"http://evil.example/a\x00" * 5) + b"padding-padding"
    hits, stats = analyze_strings(blob, min_length=6)
    urls = [h for h in hits if h.category == "url"]
    assert len(urls) == 1
    assert stats["url"] == 5
