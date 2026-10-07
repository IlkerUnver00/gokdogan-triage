"""The bundled behaviour rules: what they must catch, and the benign text that
large programs carry and that they must not.

Samples are in-memory byte strings behind an MZ header; nothing runs."""

from __future__ import annotations

import pytest

yara = pytest.importorskip("yara")

from gokdogan.yara_scan import scan  # noqa: E402

RULES = ("PowerShell_EncodedCommand", "Shadow_Copy_Deletion", "Ransom_Note_Language")


def fired(text: bytes) -> set[str]:
    hits, error = scan(b"MZ" + b"\0" * 64 + text)
    assert error is None
    return {h.rule for h in hits} & set(RULES)


@pytest.mark.parametrize("text", [
    b"powershell.exe -NoProfile -enc SQBFAFgA",
    b"powershell -nop -windowstyle hidden -EncodedCommand AAAA",
    "powershell -noprofile -executionpolicy bypass -enc AAAA".encode("utf-16le"),
    b'"powershell" "-enc" "AAAA" -noprofile',
    # Go and Rust pack string literals with nothing between them.
    b"powershell.exe-NoProfile-enc",
])
def test_encoded_powershell_is_caught(text):
    assert "PowerShell_EncodedCommand" in fired(text)


@pytest.mark.parametrize("text", [
    b"bcdedit /set {default} recoveryenabled No",
    b'C:\\Windows\\System32\\bcdedit.exe" /set {default} bootstatuspolicy IgnoreShutdownFailures',
    b"bcdedit.exe -set {default} recoveryenabled No",
    "bcdedit /set {current} safeboot network".encode("utf-16le"),   # safe-mode reboot before encrypting
])
def test_turning_recovery_off_is_caught(text):
    assert "Shadow_Copy_Deletion" in fired(text)


@pytest.mark.parametrize("text", [
    b"Run:\n bcdedit /set hypervisorlaunchtype auto\n",
    b"bcdedit.exe /set {current} nx OptIn",
    b"safeboot",
])
def test_bcdedit_that_installers_run_is_not_caught(text):
    assert fired(text) == set()


@pytest.mark.parametrize("text", [
    b"Your files have been encrypted. Install the Tor Browser.",
    b"All your files are encrypted. Send bitcoin to receive the decryption key.",
    b"To decrypt your files, pay in bitcoin.",
    "Your important files have been encrypted. To recover your files, contact us.".encode("utf-16le"),
])
def test_ransom_notes_are_caught(text):
    assert "Ransom_Note_Language" in fired(text)


@pytest.mark.parametrize("text", [
    # Every Go program using crypto/tls has the error message; "bitcoin" can
    # come from any library's word list.
    b"bitcoin(?i)(?:pdh.dll ... tls: unsupported decryption key type (%T)",
    # Browsers and Node.js: crypto libraries and URL-scheme lists.
    b"bitcoin:\0geo:\0im:\0 ... the decryption key is invalid",
    # A forensic tool's artifact list.
    b"Tor Browser history\0Bitcoin wallet\0",
    # One note phrase alone, as a backup or encryption tool may print it.
    b"Your files have been encrypted successfully.",
])
def test_payment_words_without_a_note_are_not_a_ransom_note(text):
    assert fired(text) == set()


def test_sweep_rows_record_which_strings_matched():
    import sys
    from pathlib import Path

    from gofixtures import RDATA, TEXT, build_pe

    from gokdogan.engine import triage_bytes

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from benign_sweep import report_fields

    blob = build_pe(64, [(b".text", b"\xc3" * 64, TEXT),
                         (b".rdata", b"\0powershell.exe -NoProfile -enc SQBFAFgA\0", RDATA)])[0]
    row = report_fields(triage_bytes(blob, name="x.exe"), use_yara=True)
    assert row["yara_strings"]["PowerShell_EncodedCommand"] == ["$enc", "$nop", "$ps"]


def test_sweep_rows_record_the_command_strings():
    import sys
    from pathlib import Path

    from gofixtures import RDATA, TEXT, build_pe

    from gokdogan.engine import triage_bytes

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from benign_sweep import report_fields

    blob = build_pe(64, [(b".text", b"\xc3" * 64, TEXT),
                         (b".rdata", b"\0bcdedit /set hypervisorlaunchtype auto\0bcdedit /set testsigning on\0", RDATA)])[0]
    features = report_fields(triage_bytes(blob, name="x.exe", use_yara=False), use_yara=False)["features"]
    assert features["commands"] == ["bcdedit /set testsigning on"]
