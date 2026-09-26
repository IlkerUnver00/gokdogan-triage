"""Malware-shaped reports that guard detection while false positives are tuned.

gokdogan can only be calibrated against benign files on a normal machine;
live malware belongs in an isolated lab. These synthetic reports stand in for
the common shapes of malicious PEs, built from the evidence each shape leaves,
so a change that removes false positives cannot quietly remove detection too.
Each archetype records the lowest verdict it may receive.
"""

from __future__ import annotations

from gokdogan.models import (
    Capability,
    ConfigField,
    DecodedString,
    FileInfo,
    OverlayInfo,
    PackerInfo,
    SignatureInfo,
    TriageReport,
    Verdict,
    YaraHit,
)


def _file(**overrides) -> FileInfo:
    base = dict(path="sample.exe", size=180_000, md5="0" * 32, sha1="0" * 40, sha256="0" * 64,
                imphash=None, ssdeep=None, tlsh=None, file_type="PE32 executable (GUI) x86",
                compile_timestamp=None, compile_timestamp_anomaly=None, is_dll=False,
                is_driver=False, is_signed=False, entry_point=0x1000, entry_section=".text")
    base.update(overrides)
    return FileInfo(**base)


def _cap(name: str, severity: int) -> Capability:
    return Capability(name, name, severity, [])


def stealer() -> TriageReport:
    """Keylogger/stealer: hooks keys, grabs clipboard and screen, exfiltrates to Telegram."""
    return TriageReport(
        file=_file(),
        capabilities=[_cap("keylogging", 3), _cap("persistence-registry", 3), _cap("network", 2),
                      _cap("clipboard-access", 2), _cap("screen-capture", 2),
                      _cap("dynamic-api-resolution", 1)],
        string_stats={"url": 2, "domain": 1},
        config_extractions=[ConfigField("Telegram bot", "token", "123456:AAAbbbCCC")],
    )


_VSS = "vssadmin delete shadows /all /quiet"


def _shadow_copy_rule() -> YaraHit:
    # The rule and the anti-recovery capability read the same command string.
    return YaraHit("Shadow_Copy_Deletion", ["ransomware"], {"weight": 30, "overlaps": "anti-recovery"},
                   matched=["vssadmin delete shadows"])


def _anti_recovery() -> Capability:
    return Capability("anti-recovery", "", 3, [f"string: cmd.exe /c {_VSS}"], source="strings")


def ransomware() -> TriageReport:
    """Deletes shadow copies, encrypts, drops a ransom note."""
    return TriageReport(
        file=_file(),
        import_count=90,
        capabilities=[_anti_recovery(), _cap("crypto", 2), _cap("process-discovery", 1),
                      _cap("execution", 1)],
        string_stats={"command": 2},
        yara=[_shadow_copy_rule(), YaraHit("Ransom_Note_Language", ["ransomware"], {"weight": 25})],
    )


def quiet_ransomware() -> TriageReport:
    """The same without a plaintext ransom note (it is encrypted or downloaded)."""
    report = ransomware()
    report.yara = [_shadow_copy_rule()]
    return report


def shadow_copy_deletion() -> TriageReport:
    """Nothing but one backup-deletion command."""
    return TriageReport(file=_file(), import_count=40, capabilities=[_anti_recovery()],
                        string_stats={"command": 1}, yara=[_shadow_copy_rule()])


def small_rat() -> TriageReport:
    """Remote-access tool: many common behaviours from a small import table, no severity-3 tag."""
    return TriageReport(
        file=_file(),
        import_count=45,
        capabilities=[_cap(n, 2) for n in ("network", "screen-capture", "clipboard-access", "crypto",
                                          "privilege-manipulation", "persistence-service")]
        + [_cap(n, 1) for n in ("process-discovery", "dynamic-api-resolution", "execution")],
        string_stats={"ipv4": 1, "command": 1},
    )


def injector_by_name() -> TriageReport:
    """Imports two injection APIs and resolves the classic trio by name at runtime."""
    return TriageReport(
        file=_file(),
        import_count=35,
        capabilities=[Capability("process-injection", "", 3, ["QueueUserAPC", "VirtualProtectEx"]),
                      _cap("dynamic-api-resolution", 1)],
        yara=[YaraHit("Injection_API_Cluster", ["injection"], {"weight": 15, "overlaps": "process-injection"},
                      matched=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])],
    )


def packed_loader() -> TriageReport:
    """UPX-packed stub: nothing but packing signals is visible statically."""
    return TriageReport(
        file=_file(),
        packer=PackerInfo(detected=True, names=["UPX"]),
        overall_entropy=7.7,
        anomalies=["section 'UPX0': W+X", "section 'UPX0': zero raw size (unpacking target)",
                   "section 'UPX1': W+X", "section 'UPX1': high-entropy executable section"],
        capabilities=[_cap("dynamic-api-resolution", 1)],
        yara=[YaraHit("UPX_Packed", ["packer"], {"weight": 12})],
    )


def downloader() -> TriageReport:
    """Fetches and runs a second stage from an XOR-hidden URL."""
    return TriageReport(
        file=_file(),
        capabilities=[_cap("download-execute", 3), _cap("network", 2), _cap("execution", 1),
                      _cap("string-obfuscation", 2)],
        string_stats={"url": 1},
        decoded_strings=[DecodedString("http://203.0.113.7/stage2.bin", "xor-0x3c", "url", 0)],
    )


def injector() -> TriageReport:
    """Remote-process injector with runtime API resolution and a C2 domain."""
    return TriageReport(
        file=_file(),
        capabilities=[_cap("process-injection", 3), _cap("self-modifying-memory", 2),
                      _cap("dynamic-api-resolution", 1), _cap("process-discovery", 1)],
        string_stats={"domain": 1},
        anomalies=["only 4 imported functions (likely resolved at runtime)"],
    )


def signed_injector() -> TriageReport:
    """The same injector carrying a stolen but valid code-signing certificate."""
    report = injector()
    report.file = _file(is_signed=True)
    report.capabilities = report.capabilities + [_cap("persistence-registry", 3), _cap("network", 2)]
    report.signature = SignatureInfo(status="valid", present=True, verified=True, signer="Stolen Cert Ltd")
    return report


def padded_signed_dll() -> TriageReport:
    """3CX-style: a genuinely signed DLL with an encrypted payload in its certificate table."""
    return TriageReport(
        file=_file(is_dll=True, is_signed=True),
        overlay=OverlayInfo(offset=900_000, size=80_000, pct=8.0, entropy=7.9, type_guess="unknown",
                            contains_pe=False, is_signature=True, cert_padding=64_000),
        anomalies=["64000 bytes of unauthenticated data in the Authenticode certificate table "
                   "(CVE-2013-3900)"],
        capabilities=[_cap("self-modifying-memory", 2), _cap("dynamic-api-resolution", 1)],
        signature=SignatureInfo(status="valid", present=True, verified=True, signer="Vendor Inc"),
    )


def dropper() -> TriageReport:
    """Carries a second executable in an encrypted resource and writes it out."""
    return TriageReport(
        file=_file(),
        capabilities=[_cap("embedded-executable", 3), _cap("execution", 1),
                      _cap("persistence-registry", 1)],
        anomalies=["resource RCDATA/101: embedded PE executable (98304 bytes)",
                   "resource RCDATA/102: high entropy 7.95 (packed/encrypted)"],
    )


# name -> (factory, lowest acceptable verdict). The floors are what the
# engine gave these shapes at v0.5.2; calibration may raise, never lower them.
# One exception, made on purpose: quiet_ransomware was HIGH_RISK (68) at
# v0.5.2 because the capability (18) and the YARA rule (30) read the same
# shadow-copy command and were added up. Now they are one fact at the higher
# weight (30); with the command-string points it scores 50, SUSPICIOUS.
ARCHETYPES = {
    "stealer": (stealer, Verdict.HIGH_RISK),
    "ransomware": (ransomware, Verdict.HIGH_RISK),
    "quiet_ransomware": (quiet_ransomware, Verdict.SUSPICIOUS),
    "shadow_copy_deletion": (shadow_copy_deletion, Verdict.SUSPICIOUS),
    "small_rat": (small_rat, Verdict.SUSPICIOUS),
    "injector_by_name": (injector_by_name, Verdict.SUSPICIOUS),
    "packed_loader": (packed_loader, Verdict.SUSPICIOUS),
    "downloader": (downloader, Verdict.SUSPICIOUS),
    "injector": (injector, Verdict.SUSPICIOUS),
    "signed_injector": (signed_injector, Verdict.SUSPICIOUS),
    "padded_signed_dll": (padded_signed_dll, Verdict.LIKELY_CLEAN),
    "dropper": (dropper, Verdict.SUSPICIOUS),
}
