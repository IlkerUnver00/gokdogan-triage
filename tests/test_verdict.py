from gokdogan.models import (
    Capability,
    FileInfo,
    PackerInfo,
    TriageReport,
    Verdict,
    YaraHit,
)
from gokdogan.verdict import score_report


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


def test_signature_mitigates():
    unsigned = TriageReport(
        file=_file_info(),
        capabilities=[Capability("network", "talks", 2, ["socket", "connect"]),
                      Capability("execution", "runs", 1, ["CreateProcessW"]),
                      Capability("persistence-registry", "registry", 2, ["RegSetValueExW"]),
                      Capability("crypto", "crypto", 2, ["CryptEncrypt", "CryptGenKey"]),
                      Capability("screen-capture", "grabs", 2, ["BitBlt", "GetDC", "GetDIBits"])],
    )
    signed = TriageReport(file=_file_info(is_signed=True), capabilities=list(unsigned.capabilities))
    score_report(unsigned)
    score_report(signed)
    assert signed.score == unsigned.score - 8


def test_score_never_negative():
    report = TriageReport(file=_file_info(is_signed=True))
    score_report(report)
    assert report.score == 0
