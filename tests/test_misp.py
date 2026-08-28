import json

from gokdogan.misp import render_misp, to_misp_event
from gokdogan.models import (
    AttackTechnique,
    Capability,
    DecodedString,
    FileInfo,
    StringHit,
    TriageReport,
    Verdict,
    YaraHit,
)


def _report():
    fi = FileInfo(
        path=r"C:\samples\evil.exe", size=2048, md5="d" * 32, sha1="e" * 40, sha256="a" * 64,
        imphash="i" * 32, ssdeep="3:abc:d", tlsh=None, file_type="PE32 executable (GUI) x86",
        compile_timestamp=None, compile_timestamp_anomaly=None, is_dll=False, is_driver=False,
        is_signed=False, entry_point=0x1000, entry_section=".text",
        authentihash="f" * 64, impfuzzy="6:xyz:q",
    )
    return TriageReport(
        file=fi,
        strings=[StringHit("url", "http://evil.example/gate", 0, "ascii"),
                 StringHit("ipv4", "203.0.113.9", 0, "ascii")],
        string_stats={"url": 1, "ipv4": 1},
        decoded_strings=[DecodedString("http://c2.hidden/x", "xor-0x5a", "url", 0)],
        capabilities=[Capability("process-injection", "", 3, [], attack=["T1055"])],
        attack=[AttackTechnique("T1055", "Process Injection", "Defense Evasion", ["process-injection"])],
        yara=[YaraHit(rule="Injection_API_Cluster")],
        verdict=Verdict.HIGH_RISK, score=88,
    )


def test_misp_event_shape():
    event = to_misp_event(_report())["Event"]
    assert event["threat_level_id"] == "1"          # HIGH_RISK -> high
    assert "evil.exe" in event["info"]
    types = {a["type"]: a["value"] for a in event["Attribute"]}
    assert types["sha256"] == "a" * 64
    assert types["imphash"] == "i" * 32
    assert types["authentihash"] == "f" * 64
    assert types["filename"] == "evil.exe"


def test_misp_collects_iocs_from_strings_and_decoded():
    attrs = to_misp_event(_report())["Event"]["Attribute"]
    urls = [a["value"] for a in attrs if a["type"] == "url"]
    ips = [a["value"] for a in attrs if a["type"] == "ip-dst"]
    assert "http://evil.example/gate" in urls
    assert "http://c2.hidden/x" in urls          # recovered from an XOR-encoded string
    assert "203.0.113.9" in ips


def test_misp_tags_attack_and_verdict():
    tags = [t["name"] for t in to_misp_event(_report())["Event"]["Tag"]]
    assert any("T1055" in t for t in tags)
    assert any('verdict="HIGH_RISK"' in t for t in tags)
    assert any("Injection_API_Cluster" in t for t in tags)


def test_misp_json_is_valid():
    text = render_misp(_report())
    parsed = json.loads(text)
    assert "Event" in parsed
