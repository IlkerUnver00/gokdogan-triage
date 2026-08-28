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
import os
from typing import Any

from .models import TriageReport, Verdict

# MISP threat_level_id: 1 high, 2 medium, 3 low, 4 undefined.
_THREAT_LEVEL = {Verdict.HIGH_RISK: "1", Verdict.SUSPICIOUS: "2", Verdict.LIKELY_CLEAN: "3"}

# gokdogan string category -> MISP attribute type.
_IOC_TYPE = {"url": "url", "ipv4": "ip-dst", "domain": "domain"}


def _attr(atype: str, value: str, category: str) -> dict[str, str]:
    return {"type": atype, "category": category, "value": value, "to_ids": True}


def to_misp_event(report: TriageReport) -> dict[str, Any]:
    f = report.file
    attrs: list[dict[str, str]] = [
        _attr("sha256", f.sha256, "Payload delivery"),
        _attr("sha1", f.sha1, "Payload delivery"),
        _attr("md5", f.md5, "Payload delivery"),
        _attr("filename", os.path.basename(f.path), "Payload delivery"),
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
            attrs.append(_attr(misp_type, dec.value, "Network activity"))

    # Extracted family config as attributes (webhooks/urls as url, else text).
    for cfg in report.config_extractions:
        atype = "url" if cfg.value.lower().startswith("http") else "text"
        if (atype, cfg.value) not in seen:
            seen.add((atype, cfg.value))
            attrs.append(_attr(atype, cfg.value, "Payload delivery"))

    tags = [{"name": f'gokdogan:verdict="{report.verdict.value}"'}]
    for tech in report.attack:
        tags.append({"name": f'misp-galaxy:mitre-attack-pattern="{tech.id}"'})
    for cap in report.capabilities:
        tags.append({"name": f'gokdogan:capability="{cap.name}"'})
    for hit in report.yara:
        tags.append({"name": f'gokdogan:yara="{hit.rule}"'})

    return {
        "Event": {
            "info": f"gokdogan triage: {os.path.basename(f.path)} ({report.verdict.value})",
            "analysis": "2",              # completed
            "threat_level_id": _THREAT_LEVEL[report.verdict],
            "distribution": "0",          # your organisation only
            "Attribute": attrs,
            "Tag": tags,
        }
    }


def render_misp(report: TriageReport) -> str:
    return json.dumps(to_misp_event(report), indent=2, ensure_ascii=False)
