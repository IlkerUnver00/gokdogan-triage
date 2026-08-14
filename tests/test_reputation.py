import io
import urllib.error

from peregrine import reputation
from peregrine.reputation import (
    lookup_malwarebazaar,
    lookup_virustotal,
    parse_malwarebazaar,
    parse_virustotal,
)

_VT_PAYLOAD = {
    "data": {"attributes": {
        "last_analysis_stats": {"malicious": 48, "suspicious": 2, "undetected": 20,
                                "harmless": 0, "timeout": 2},
        "popular_threat_classification": {"suggested_threat_label": "trojan.emotet/gen"},
        "first_submission_date": 1600000000,
    }}
}
_MB_PAYLOAD = {"query_status": "ok",
               "data": [{"signature": "Emotet", "first_seen": "2021-05-01 12:00:00"}]}


def test_parse_virustotal():
    rep = parse_virustotal("a" * 64, _VT_PAYLOAD)
    assert rep.status == "found"
    assert rep.detections == "50/72"          # (48 malicious + 2 suspicious) / 72 total
    assert rep.family == "trojan.emotet/gen"
    assert rep.first_seen == "2020-09-13"
    assert rep.link.endswith("a" * 64)


def test_parse_malwarebazaar_found_and_missing():
    found = parse_malwarebazaar("b" * 64, _MB_PAYLOAD)
    assert found.status == "found"
    assert found.family == "Emotet"

    missing = parse_malwarebazaar("b" * 64, {"query_status": "hash_not_found"})
    assert missing.status == "not_found"


def test_lookup_without_key_is_no_key_and_makes_no_call():
    vt = lookup_virustotal("a" * 64, None)
    mb = lookup_malwarebazaar("a" * 64, None)
    assert vt.status == "no_key" and mb.status == "no_key"
    assert "VT_API_KEY" in vt.note


def test_lookup_virustotal_with_injected_http():
    calls = {}

    def fake_get(url, headers, timeout=15):
        calls["url"] = url
        calls["headers"] = headers
        return _VT_PAYLOAD

    rep = lookup_virustotal("c" * 64, "SECRET", http_get=fake_get)
    assert rep.status == "found"
    assert calls["headers"]["x-apikey"] == "SECRET"
    assert ("c" * 64) in calls["url"]


def test_lookup_virustotal_404_is_not_found():
    def fake_get(url, headers, timeout=15):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))

    rep = lookup_virustotal("d" * 64, "SECRET", http_get=fake_get)
    assert rep.status == "not_found"


def test_lookup_virustotal_network_error():
    def fake_get(url, headers, timeout=15):
        raise urllib.error.URLError("no route to host")

    rep = lookup_virustotal("e" * 64, "SECRET", http_get=fake_get)
    assert rep.status == "error"
    assert "network error" in rep.note


def test_lookup_malwarebazaar_with_injected_http():
    def fake_post(url, fields, headers, timeout=15):
        assert fields["hash"] == "f" * 64
        assert headers["Auth-Key"] == "MBKEY"
        return _MB_PAYLOAD

    rep = lookup_malwarebazaar("f" * 64, "MBKEY", http_post=fake_post)
    assert rep.status == "found"
    assert rep.family == "Emotet"


def test_lookup_bundles_both():
    reps = reputation.lookup("a" * 64, None, None)
    assert {r.source for r in reps} == {"VirusTotal", "MalwareBazaar"}
    assert all(r.status == "no_key" for r in reps)
