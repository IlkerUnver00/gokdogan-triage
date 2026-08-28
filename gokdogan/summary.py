"""Batch summary rows for CSV / JSONL output.

When triaging a whole dropzone, an analyst wants one flat row per sample —
sortable in a spreadsheet or streamable into a SIEM — not a directory of
verbose reports. ``summary_row`` flattens a TriageReport into stable,
scalar-friendly fields; CSV joins list fields with ``;`` while JSONL keeps
them as arrays.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .models import TriageReport

# Stable column order for CSV; also the key order for JSONL objects.
FIELDS = [
    "path", "sha256", "size", "type", "verdict", "score",
    "signature", "signer", "dotnet",
    "imphash", "rich_hash", "ssdeep",
    "packer", "capabilities", "attack", "yara",
    "embedded_pe", "encoded_strings", "config_blobs", "anomalies",
    "overlay", "vt", "mb_family",
]


def _reputation(report: TriageReport) -> tuple[str, str]:
    """(VirusTotal detections, MalwareBazaar family) — empty if not looked up."""
    vt = mb = ""
    for rep in report.reputation:
        if rep.source == "VirusTotal" and rep.status == "found":
            vt = rep.detections or "found"
        elif rep.source == "MalwareBazaar" and rep.status == "found":
            mb = rep.family or "found"
    return vt, mb


def _has_embedded_pe(report: TriageReport) -> bool:
    if any(c.name == "embedded-executable" for c in report.capabilities):
        return True
    return any(d.category == "embedded-pe" for d in report.decoded_strings)


def _overlay(report: TriageReport) -> str:
    ov = report.overlay
    if ov is None or ov.is_signature:
        return ""
    return "embedded-pe" if ov.contains_pe else ov.type_guess


def summary_row(report: TriageReport) -> dict[str, Any]:
    """Flatten a report into one summary record (list fields stay as lists)."""
    vt, mb_family = _reputation(report)
    return {
        "path": report.file.path,
        "sha256": report.file.sha256,
        "size": report.file.size,
        "type": report.file.file_type,
        "verdict": report.verdict.value,
        "score": report.score,
        "signature": report.signature.status if report.signature else "",
        "signer": report.signature.signer if report.signature else "",
        "dotnet": (report.dotnet.runtime_version if report.dotnet else ""),
        "imphash": report.file.imphash or "",
        "rich_hash": report.rich.hash if report.rich else "",
        "ssdeep": report.file.ssdeep or "",
        "packer": ", ".join(report.packer.names) if report.packer.detected else "",
        "capabilities": [c.name for c in report.capabilities],
        "attack": [t.id for t in report.attack],
        "yara": [h.rule for h in report.yara],
        "embedded_pe": _has_embedded_pe(report),
        "encoded_strings": len(report.decoded_strings),
        "config_blobs": len(report.config_blobs),
        "anomalies": len(report.anomalies),
        "overlay": _overlay(report),
        "vt": vt,
        "mb_family": mb_family,
    }


def _flatten_for_csv(value: Any) -> Any:
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return value


def write_csv(rows: list[dict[str, Any]], path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _flatten_for_csv(row.get(k, "")) for k in FIELDS})


def write_jsonl(rows: list[dict[str, Any]], path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def csv_string(rows: list[dict[str, Any]]) -> str:
    """Render rows to a CSV string (used for testing / stdout)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: _flatten_for_csv(row.get(k, "")) for k in FIELDS})
    return buffer.getvalue()
