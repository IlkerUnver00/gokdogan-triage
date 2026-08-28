"""Weighted scoring and final triage verdict.

The score is deliberately transparent: every point comes with a reason
string, and the console report prints the full breakdown. A triage tool
an analyst can't argue with is a triage tool nobody trusts.
"""

from __future__ import annotations

from .models import ScoreEntry, TriageReport, Verdict

SUSPICIOUS_THRESHOLD = 30
HIGH_RISK_THRESHOLD = 60

# Capability severity -> points per capability.
_CAP_POINTS = {1: 2, 2: 8, 3: 18}

# YARA meta "severity" values -> points (rules may declare their own weight).
_YARA_DEFAULT_POINTS = 15


def score_report(report: TriageReport) -> None:
    """Fill report.score, report.score_breakdown and report.verdict in place."""
    entries: list[ScoreEntry] = []

    if report.packer.detected:
        names = ", ".join(report.packer.names) or "unknown"
        entries.append(ScoreEntry(15, f"packer detected: {names}"))

    if report.overall_entropy >= 7.0:
        entries.append(ScoreEntry(10, f"overall file entropy {report.overall_entropy:.2f}"))

    for anomaly in report.anomalies:
        entries.append(ScoreEntry(6, f"anomaly: {anomaly}"))

    if report.file.compile_timestamp_anomaly:
        entries.append(ScoreEntry(5, report.file.compile_timestamp_anomaly))

    for cap in report.capabilities:
        entries.append(
            ScoreEntry(_CAP_POINTS.get(cap.severity, 2), f"capability: {cap.name}")
        )

    for hit in report.yara:
        points = hit.meta.get("weight", _YARA_DEFAULT_POINTS)
        if not isinstance(points, int):
            points = _YARA_DEFAULT_POINTS
        entries.append(ScoreEntry(points, f"YARA match: {hit.rule}"))

    ioc_count = sum(
        report.string_stats.get(k, 0) for k in ("url", "ipv4", "domain")
    )
    if ioc_count:
        entries.append(ScoreEntry(min(ioc_count, 10), f"{ioc_count} network IOC string(s)"))

    cmd_count = report.string_stats.get("command", 0)
    if cmd_count:
        entries.append(ScoreEntry(min(4 * cmd_count, 16), f"{cmd_count} suspicious command string(s)"))

    # Encoded IOCs/commands are especially damning: a benign program has no
    # reason to XOR-hide a URL or an embedded PE.
    hidden = [
        d for d in report.decoded_strings
        if d.category in ("url", "ipv4", "domain", "command", "embedded-pe")
    ]
    if hidden:
        entries.append(ScoreEntry(min(8 * len(hidden), 24),
                                  f"{len(hidden)} encoded IOC/payload string(s) recovered"))

    # Mitigating signal: an Authenticode blob doesn't prove the signature
    # is valid (that needs online chain verification), but unsigned +
    # suspicious is the more common malware shape.
    if report.file.is_signed and entries:
        entries.append(ScoreEntry(-8, "embedded Authenticode signature present (unverified)"))

    report.score_breakdown = entries
    report.score = max(0, sum(e.points for e in entries))

    if report.score >= HIGH_RISK_THRESHOLD:
        report.verdict = Verdict.HIGH_RISK
    elif report.score >= SUSPICIOUS_THRESHOLD:
        report.verdict = Verdict.SUSPICIOUS
    else:
        report.verdict = Verdict.LIKELY_CLEAN
