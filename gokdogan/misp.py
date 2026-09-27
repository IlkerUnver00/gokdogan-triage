"""MISP event export.

Turns a triage report into a MISP-importable event JSON: file hashes as
attributes (md5/sha1/sha256/imphash/ssdeep/authentihash/impfuzzy), network
IOCs (urls / ips / domains, including ones recovered from encoded strings),
the filename, and tags for the verdict, the mapped ATT&CK techniques, the
matched YARA rules, and the inferred capabilities. Drop the file straight
into a MISP instance to share what gokdogan found.
"""

from __future__ import annotations

import json
import ntpath
from typing import Any

from .models import TriageReport, Verdict

# MISP threat_level_id: 1 high, 2 medium, 3 low, 4 undefined.
_THREAT_LEVEL = {Verdict.HIGH_RISK: "1", Verdict.SUSPICIOUS: "2", Verdict.LIKELY_CLEAN: "3"}

# gokdogan string category -> MISP attribute type.
_IOC_TYPE = {"url": "url", "ipv4": "ip-dst", "domain": "domain"}


# What is safe to push to an IDS by default. The sample's own file hashes
# are; its authentihash is not, because it excludes the certificate table and
# so equals the genuine vendor file's for a padded (CVE-2013-3900) sample.
# Filenames, fuzzy hashes and plaintext URL/domain strings found in a binary
# (CA URLs, vendor sites, docs links) are context for an analyst. Network IOCs
# the malware went out of its way to hide or configure (XOR/base64-decoded
# strings, extracted family config) are the opposite: those are marked to_ids.
_IDS_TYPES = {"md5", "sha1", "sha256"}
_NETWORK_TYPES = {"url", "ip-dst", "domain"}


def _attr(atype: str, value: str, category: str, to_ids: bool | None = None) -> dict[str, Any]:
    return {"type": atype, "category": category, "value": value,
            "to_ids": atype in _IDS_TYPES if to_ids is None else to_ids}


def to_misp_event(report: TriageReport) -> dict[str, Any]:
    f = report.file
    # ntpath splits on "\" and "/", so a report written on Windows names the
    # same file when it is exported on Linux.
    filename = ntpath.basename(f.path)
    attrs: list[dict[str, Any]] = [
        _attr("sha256", f.sha256, "Payload delivery"),
        _attr("sha1", f.sha1, "Payload delivery"),
        _attr("md5", f.md5, "Payload delivery"),
        _attr("filename", filename, "Payload delivery"),
    ]
    for atype, value in (("imphash", f.imphash), ("ssdeep", f.ssdeep),
                         ("authentihash", f.authentihash), ("impfuzzy", f.impfuzzy)):
        if value:
            attrs.append(_attr(atype, value, "Payload delivery"))

    # Network IOCs from classified strings and recovered encoded strings.
    seen: set[tuple[str, str]] = set()
    for hit in report.strings:
        misp_type = _IOC_TYPE.get(hit.category)
        if misp_type and (misp_type, hit.value) not in seen:
            seen.add((misp_type, hit.value))
            attrs.append(_attr(misp_type, hit.value, "Network activity"))
    for dec in report.decoded_strings:
        misp_type = _IOC_TYPE.get(dec.category or "")
        if misp_type and (misp_type, dec.value) not in seen:
            seen.add((misp_type, dec.value))
            attrs.append(_attr(misp_type, dec.value, "Network activity", to_ids=True))

    # Extracted family config as attributes (webhooks/urls as url, else text).
    for cfg in report.config_extractions:
        atype = "url" if cfg.value.lower().startswith("http") else "text"
        if (atype, cfg.value) not in seen:
            seen.add((atype, cfg.value))
            attrs.append(_attr(atype, cfg.value, "Payload delivery",
                               to_ids=atype in _NETWORK_TYPES))

    tags = [{"name": f'gokdogan:verdict="{report.verdict.value}"'}]
    for tech in report.attack:
        tags.append({"name": f'misp-galaxy:mitre-attack-pattern="{tech.id}"'})
    for cap in report.capabilities:
        tags.append({"name": f'gokdogan:capability="{cap.name}"'})
    for hit in report.yara:
        tags.append({"name": f'gokdogan:yara="{hit.rule}"'})

    return {
        "Event": {
            "info": f"gokdogan triage: {filename} ({report.verdict.value})",
            "analysis": "2",              # completed
            "threat_level_id": _THREAT_LEVEL[report.verdict],
            "distribution": "0",          # your organisation only
            "Attribute": attrs,
            "Tag": tags,
        }
    }


def render_misp(report: TriageReport) -> str:
    return json.dumps(to_misp_event(report), indent=2, ensure_ascii=False)
