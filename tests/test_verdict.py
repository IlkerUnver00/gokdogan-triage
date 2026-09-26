from gokdogan.loader import is_packing_anomaly
from gokdogan.models import (
    Capability,
    FileInfo,
    OverlayInfo,
    PackerInfo,
    SignatureInfo,
    TriageReport,
    Verdict,
    YaraHit,
)
from gokdogan.verdict import HIGH_RISK_THRESHOLD, SUSPICIOUS_THRESHOLD, score_report


def _file_info(**overrides):
    base = dict(
        path="sample.exe",
        size=1024,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
        imphash=None,
        ssdeep=None,
        tlsh=None,
        file_type="PE32 executable (GUI) x86",
        compile_timestamp=None,
        compile_timestamp_anomaly=None,
        is_dll=False,
        is_driver=False,
        is_signed=False,
        entry_point=0x1000,
        entry_section=".text",
    )
    base.update(overrides)
    return FileInfo(**base)


def test_empty_report_is_clean():
    report = TriageReport(file=_file_info())
    score_report(report)
    assert report.score == 0
    assert report.verdict == Verdict.LIKELY_CLEAN


def test_packed_injector_is_high_risk():
    report = TriageReport(
        file=_file_info(),
        packer=PackerInfo(detected=True, names=["UPX"]),
        capabilities=[
            Capability("process-injection", "injects", 3, ["WriteProcessMemory"]),
            Capability("keylogging", "keylogs", 3, ["GetAsyncKeyState"]),
            Capability("network", "talks", 2, ["socket", "connect"]),
        ],
        anomalies=["no import table"],
    )
    score_report(report)
    assert report.verdict == Verdict.HIGH_RISK
    assert any("packer" in e.reason for e in report.score_breakdown)


def test_yara_weight_meta_is_honored():
    report = TriageReport(
        file=_file_info(),
        yara=[YaraHit(rule="Shadow_Copy_Deletion", meta={"weight": 30})],
    )
    score_report(report)
    assert report.score == 30
    assert report.verdict == Verdict.SUSPICIOUS


def _suspicious_caps():
    return [Capability("network", "talks", 2, ["socket", "connect"]),
            Capability("execution", "runs", 1, ["CreateProcessW"]),
            Capability("persistence-registry", "registry", 2, ["RegSetValueExW"]),
            Capability("crypto", "crypto", 2, ["CryptEncrypt", "CryptGenKey"]),
            Capability("screen-capture", "grabs", 2, ["BitBlt", "GetDC", "GetDIBits"])]


def test_signature_that_is_not_valid_earns_no_credit():
    # Anyone can self-sign, and an expired or unverified blob proves nothing.
    base = TriageReport(file=_file_info(), capabilities=_suspicious_caps())
    score_report(base)
    for status in ("expired", "untrusted", "unverified", "invalid"):
        signed = TriageReport(file=_file_info(is_signed=True), capabilities=_suspicious_caps(),
                              signature=SignatureInfo(status=status, present=True))
        score_report(signed)
        assert signed.score == base.score, status
        assert any(e.points == 0 and "no mitigation credit" in e.reason
                   for e in signed.score_breakdown), status


def test_valid_signature_over_padded_cert_table_earns_no_credit():
    # CVE-2013-3900: data hidden after the PKCS#7 blob keeps the signature
    # "valid"; the credit must not apply (the 3CX DLL pattern).
    padded = OverlayInfo(offset=1000, size=14000, pct=10.0, entropy=7.9, type_guess="unknown",
                         contains_pe=False, is_signature=True, cert_padding=4096)
    base = TriageReport(file=_file_info(), capabilities=_suspicious_caps())
    signed = TriageReport(file=_file_info(is_signed=True), capabilities=_suspicious_caps(),
                          overlay=padded,
                          signature=SignatureInfo(status="valid", present=True, verified=True,
                                                  signer="Contoso Ltd"))
    score_report(base)
    score_report(signed)
    assert signed.score == base.score
    assert not any(e.points < 0 and e.reason.startswith("Authenticode")
                   for e in signed.score_breakdown)


def test_valid_signature_mitigates_more():
    base = TriageReport(file=_file_info(), capabilities=_suspicious_caps())
    valid = TriageReport(file=_file_info(is_signed=True), capabilities=_suspicious_caps(),
                         signature=SignatureInfo(status="valid", present=True, verified=True,
                                                 signer="Contoso Ltd"))
    score_report(base)
    score_report(valid)
    assert valid.score == base.score - 15


def test_tampered_signature_penalizes():
    report = TriageReport(file=_file_info(is_signed=True),
                          signature=SignatureInfo(status="tampered", present=True))
    score_report(report)
    assert any(e.points == 30 for e in report.score_breakdown)
    # a tampered signature alone is enough to warrant a second look
    assert report.verdict == Verdict.SUSPICIOUS


def test_score_never_negative():
    report = TriageReport(file=_file_info(is_signed=True))
    score_report(report)
    assert report.score == 0


def _sev3_injector():
    return [Capability("process-injection", "injects", 3, ["WriteProcessMemory"], attack=["T1055"])]


def test_reputation_virustotal_feeds_score():
    from gokdogan.models import Reputation
    rep = [Reputation("VirusTotal", "found", detections="50/72", family="trojan.emotet")]
    report = TriageReport(file=_file_info(), reputation=rep)
    score_report(report)
    assert any("VirusTotal" in e.reason for e in report.score_breakdown)
    assert report.verdict in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK)


def test_reputation_low_detection_is_modest():
    from gokdogan.models import Reputation
    rep = [Reputation("VirusTotal", "found", detections="1/72")]
    report = TriageReport(file=_file_info(), reputation=rep)
    score_report(report)
    assert report.score < SUSPICIOUS_THRESHOLD  # 1/72 alone shouldn't flag


def test_valid_signature_floor_keeps_sev3_suspicious():
    # pre-signature score already >= SUSPICIOUS; a valid sig must not clear it
    report = TriageReport(
        file=_file_info(is_signed=True),
        capabilities=_sev3_injector() + [
            Capability("network", "", 2, []), Capability("persistence-registry", "", 2, [])],
        signature=SignatureInfo(status="valid", present=True, verified=True, signer="StolenCert"),
    )
    score_report(report)
    assert report.verdict == Verdict.SUSPICIOUS
    assert report.score >= SUSPICIOUS_THRESHOLD
    assert any("floor" in e.reason for e in report.score_breakdown)


def test_valid_signature_still_clears_benign():
    # a benign signed file (no sev-3, low base) must still land LIKELY_CLEAN
    report = TriageReport(
        file=_file_info(is_signed=True),
        capabilities=[Capability("network", "", 2, [])],
        signature=SignatureInfo(status="valid", present=True, verified=True, signer="MS"),
    )
    score_report(report)
    assert report.verdict == Verdict.LIKELY_CLEAN


def _packed_report(**overrides):
    # A UPX-style file: every signal below says "packed", none says "malicious".
    fields = dict(
        file=_file_info(),
        packer=PackerInfo(detected=True, names=["UPX"]),
        overall_entropy=7.6,
        anomalies=["section 'UPX0': W+X", "section 'UPX0': zero raw size (unpacking target)",
                   "section 'UPX1': W+X", "section 'UPX1': high-entropy executable section"],
        yara=[YaraHit(rule="UPX_Packed", tags=["packer"], meta={"weight": 12})],
    )
    fields.update(overrides)
    return TriageReport(**fields)


def test_packing_alone_is_capped_below_high_risk():
    report = _packed_report()
    score_report(report)
    assert report.score == SUSPICIOUS_THRESHOLD
    assert report.verdict == Verdict.SUSPICIOUS
    assert any(e.reason.startswith("cap: packing") for e in report.score_breakdown)


def test_packing_cap_leaves_behavioural_evidence_alone():
    report = _packed_report(capabilities=[Capability("process-injection", "", 3, [])],
                            anomalies=["section 'UPX0': W+X", "TLS callbacks present"])
    score_report(report)
    # packing group 15+10+6+12 = 43 -> capped at 30; injection 18 and the TLS
    # anomaly (a weak signal, 2) are not packing signals and count in full.
    assert report.score == SUSPICIOUS_THRESHOLD + 18 + 2
    assert report.score < HIGH_RISK_THRESHOLD


def test_packing_under_the_cap_is_untouched():
    report = TriageReport(file=_file_info(), packer=PackerInfo(detected=True, names=["UPX"]))
    score_report(report)
    assert report.score == 15
    assert not any(e.reason.startswith("cap:") for e in report.score_breakdown)


def test_stray_cert_bytes_below_threshold_keep_the_credit():
    stray = OverlayInfo(offset=1000, size=10000, pct=5.0, entropy=7.0, type_guess="unknown",
                        contains_pe=False, is_signature=True, cert_padding=1)
    base = TriageReport(file=_file_info(), capabilities=_suspicious_caps())
    signed = TriageReport(file=_file_info(is_signed=True), capabilities=_suspicious_caps(),
                          overlay=stray,
                          signature=SignatureInfo(status="valid", present=True, verified=True,
                                                  signer="Contoso Ltd"))
    score_report(base)
    score_report(signed)
    assert signed.score == base.score - 15


def test_packing_anomalies_are_matched_by_prefix_not_substring():
    assert is_packing_anomaly("section 'UPX0': W+X")
    assert is_packing_anomaly("no import table")
    assert is_packing_anomaly("only 3 imported functions (likely resolved at runtime)")
    assert is_packing_anomaly("entry point in last section 'UPX1'")
    # resource names and types are attacker-controlled free text
    assert not is_packing_anomaly("resource RCDATA/a: W+X: embedded PE executable")
    assert not is_packing_anomaly("resource no import table/x: high entropy")
    assert not is_packing_anomaly("TLS callbacks present (code runs before entry point)")


def test_attacker_named_resource_is_not_swallowed_by_the_packing_cap():
    report = _packed_report(anomalies=[
        "section 'UPX0': W+X", "section 'UPX0': zero raw size (unpacking target)",
        "section 'UPX1': W+X", "section 'UPX1': high-entropy executable section",
        "resource RCDATA/a: W+X: embedded PE executable (12288 bytes)",
    ])
    score_report(report)
    # packing 61 is capped at 30; the dropper anomaly still counts in full
    assert report.score == SUSPICIOUS_THRESHOLD + 6


def _common_caps():
    return [Capability(n, "", 2, []) for n in (
        "network", "crypto", "screen-capture", "clipboard-access", "privilege-manipulation",
        "persistence-service")] + [Capability(n, "", 1, []) for n in (
        "execution", "dynamic-api-resolution")]


def test_common_capabilities_of_a_large_program_are_capped():
    report = TriageReport(file=_file_info(), import_count=900, capabilities=_common_caps() + [
        Capability("process-injection", "", 3, []),
        Capability("string-obfuscation", "", 2, [], source="decoded"),
        Capability("persistence-registry", "", 2, [], source="strings")])
    score_report(report)
    # 6 x 8 + 2 x 2 = 52 common points -> 16; injection 18, obfuscation 8 and
    # the Run-key strings 8 are not import evidence and count in full
    assert report.score == 16 + 18 + 8 + 8
    assert any(e.reason.startswith("cap: common capabilities") for e in report.score_breakdown)


def test_common_capabilities_of_a_small_program_count_in_full():
    # Thirty imports carrying eight behaviours is not explained by size.
    report = TriageReport(file=_file_info(), import_count=30, capabilities=_common_caps())
    score_report(report)
    assert report.score == 52
    assert not any(e.reason.startswith("cap:") for e in report.score_breakdown)


def _injection_cluster(matched):
    return YaraHit(rule="Injection_API_Cluster", tags=["injection"],
                   meta={"weight": 15, "overlaps": "process-injection"}, matched=matched)


_TRIO = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]


def test_yara_rule_on_the_same_imports_is_counted_once():
    report = TriageReport(file=_file_info(), yara=[_injection_cluster(_TRIO)], capabilities=[
        Capability("process-injection", "", 3, sorted(_TRIO))])
    score_report(report)
    # max(18, 15), not 18 + 15
    assert report.score == 18
    assert any("counted once" in e.reason for e in report.score_breakdown)


def test_yara_rule_on_other_evidence_counts_in_full():
    # The injection capability fired on two other imports; the trio is only
    # present as strings (resolved by name at runtime): a second, hidden path.
    report = TriageReport(file=_file_info(), yara=[_injection_cluster(_TRIO)], capabilities=[
        Capability("process-injection", "", 3, ["QueueUserAPC", "VirtualProtectEx"])])
    score_report(report)
    assert report.score == 18 + 15


def _log_rule(matched):
    # A rule reading the same command strings as the anti-recovery capability.
    return YaraHit(rule="Log_Clearing", meta={"weight": 30, "overlaps": "anti-recovery"},
                   matched=matched)


def _anti_recovery(commands):
    return Capability("anti-recovery", "", 3, [f"string: {c}" for c in commands], source="strings")


def test_heavier_yara_rule_is_not_discarded_for_a_lighter_capability():
    report = TriageReport(file=_file_info(), yara=[_log_rule(["wevtutil cl Security"])],
                          capabilities=[_anti_recovery(["wevtutil cl Security"])])
    score_report(report)
    # one fact at the higher weight: 18 + (30 - 18)
    assert report.score == 30
    assert report.verdict == Verdict.SUSPICIOUS


def test_cut_short_match_list_is_not_treated_as_same_evidence():
    from gokdogan.yara_scan import MAX_MATCHED
    logs = [f"wevtutil cl Log{i}" for i in range(MAX_MATCHED)]
    report = TriageReport(file=_file_info(), yara=[_log_rule(logs)],
                          capabilities=[_anti_recovery(logs)])
    score_report(report)
    assert report.score == 18 + 30


def test_every_capability_string_is_compared_not_only_the_first_few():
    # Reports show the first few evidence strings; the comparison uses all.
    logs = [f"wevtutil cl Log{i}" for i in range(8)]
    report = TriageReport(file=_file_info(), yara=[_log_rule(["wevtutil cl Log7"])],
                          capabilities=[_anti_recovery(logs)])
    score_report(report)
    assert report.score == 30
