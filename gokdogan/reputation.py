"""Optional reputation lookup — VirusTotal and MalwareBazaar.

This is the *only* part of gokdogan that touches the network, and it is
strictly opt-in: nothing here runs unless the CLI is given ``--reputation``
and an API key. Only the sample's **SHA-256 hash** is ever sent — never the
file — so an analyst can check "is this already known?" without uploading a
potentially sensitive or malicious sample anywhere.

Fetch and parse are separated so the parsing logic is unit-testable against
recorded JSON without any network access.
"""

from __future__ import annotations

import datetime
import json
import urllib.error
import urllib.parse
import urllib.request

from .models import Reputation

_VT_URL = "https://www.virustotal.com/api/v3/files/"
_VT_GUI = "https://www.virustotal.com/gui/file/"
_MB_URL = "https://mb-api.abuse.ch/api/v1/"
_MB_GUI = "https://bazaar.abuse.ch/sample/"
_TIMEOUT = 15


# --- HTTP (thin, injectable for tests) ----------------------------------

def _http_get_json(url: str, headers: dict[str, str], timeout: int = _TIMEOUT):
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _http_post_json(url: str, fields: dict[str, str], headers: dict[str, str], timeout: int = _TIMEOUT):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


# --- parsers (pure, unit-tested) ----------------------------------------

def parse_virustotal(sha256: str, payload: dict) -> Reputation:
    attrs = (payload or {}).get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 0
    label = (attrs.get("popular_threat_classification", {}) or {}).get("suggested_threat_label", "")
    first = attrs.get("first_submission_date", "")
    if isinstance(first, int) and first:
        first = datetime.datetime.fromtimestamp(first, tz=datetime.timezone.utc).strftime("%Y-%m-%d")
    return Reputation(
        source="VirusTotal",
        status="found",
        detections=f"{malicious + suspicious}/{total}" if total else "",
        family=str(label or ""),
        first_seen=str(first or ""),
        link=_VT_GUI + sha256,
    )


def parse_malwarebazaar(sha256: str, payload: dict) -> Reputation:
    status = (payload or {}).get("query_status", "")
    if status != "ok":
        return Reputation(source="MalwareBazaar", status="not_found",
                          note=f"query_status: {status}" if status else "empty response")
    data = (payload.get("data") or [{}])[0]
    return Reputation(
        source="MalwareBazaar",
        status="found",
        family=str(data.get("signature") or data.get("file_type") or ""),
        first_seen=str(data.get("first_seen") or ""),
        link=_MB_GUI + sha256,
    )


# --- lookups (network; injectable http_get/http_post for tests) ---------

def lookup_virustotal(sha256: str, api_key: str | None, *, http_get=_http_get_json) -> Reputation:
    if not api_key:
        return Reputation(source="VirusTotal", status="no_key",
                          note="set --vt-key or VT_API_KEY to enable")
    try:
        payload = http_get(_VT_URL + sha256, {"x-apikey": api_key})
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return Reputation(source="VirusTotal", status="not_found",
                              note="not seen by VirusTotal", link=_VT_GUI + sha256)
        return Reputation(source="VirusTotal", status="error", note=f"HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return Reputation(source="VirusTotal", status="error", note=f"network error: {exc}")
    except (ValueError, KeyError) as exc:
        return Reputation(source="VirusTotal", status="error", note=f"bad response: {exc}")
    return parse_virustotal(sha256, payload)


def lookup_malwarebazaar(sha256: str, api_key: str | None, *, http_post=_http_post_json) -> Reputation:
    if not api_key:
        return Reputation(source="MalwareBazaar", status="no_key",
                          note="set --mb-key or MB_API_KEY to enable")
    try:
        payload = http_post(_MB_URL, {"query": "get_info", "hash": sha256},
                            {"Auth-Key": api_key})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return Reputation(source="MalwareBazaar", status="error", note=f"network error: {exc}")
    except (ValueError, KeyError) as exc:
        return Reputation(source="MalwareBazaar", status="error", note=f"bad response: {exc}")
    return parse_malwarebazaar(sha256, payload)


def lookup(sha256: str, vt_key: str | None, mb_key: str | None) -> list[Reputation]:
    """Query both services; each degrades independently to a status note."""
    return [
        lookup_virustotal(sha256, vt_key),
        lookup_malwarebazaar(sha256, mb_key),
    ]
