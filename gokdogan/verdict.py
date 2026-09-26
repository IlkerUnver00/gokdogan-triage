"""Weighted scoring and final triage verdict.

The score is deliberately transparent: every point comes with a reason
string, and the console report prints the full breakdown. A triage tool
an analyst can't argue with is a triage tool nobody trusts.
"""

from __future__ import annotations

from .entropy import HIGH_ENTROPY_FILE
from .loader import is_packing_anomaly
from .models import Capability, ScoreEntry, TriageReport, Verdict, YaraHit
from .overlay import MIN_HIDDEN_BYTES
from .yara_scan import MAX_MATCHED

SUSPICIOUS_THRESHOLD = 30
HIGH_RISK_THRESHOLD = 60

# Packer name, high entropy, packer YARA rules and the section/import
# anomalies an unpacking stub leaves are one fact seen several ways. Summing
# them let a plain UPX-packed utility reach HIGH_RISK with no behavioural
# evidence at all, so the group is capped: packing alone routes a sample to
# SUSPICIOUS (look closer or detonate it), never to HIGH_RISK.
_PACKING_CAP = SUSPICIOUS_THRESHOLD

# Network, crypto, registry, screen, clipboard, privileges, services: a large
# program imports enough APIs to have all of them, which says how big it is,
# not what it intends. On 2,888 benign binaries these tags stacking additively
# were the main source of false positives, and 139 of the 168 such files still
# on disk import 200 functions or more. So in a program that large, severity
# 1-2 tags read from imports and exports are capped together. In a smaller one
# the same tags are not explained by size and count in full (on that sample,
# lifting the cap below 200 imports flagged no further file; the closest, with
# 186 imports, reached 29). Severity 3 tags and tags read from content always
# count in full. Known limit: a sample that links 200 real functions gets the
# cap too; only duplicate and delay-load entries, which cost nothing, are
# kept out of the count (loader.distinct_import_count).
_COMMON_CAP = 16
_LARGE_IMPORT_TABLE = 200
_STRUCTURAL_SOURCES = {"imports", "exports", "managed"}

# Signals too common in benign software to carry full weight. TLS callbacks
# were present in 25% of the benign sweep (C++ thread_local, runtime init) and
# plaintext network IOC strings (URLs, IPs, domains) in 52% (certificate,
# vendor and documentation links). Both are real techniques, so they still
# count, just not as much.
_WEAK_ANOMALIES = ("TLS callbacks present",)
_WEAK_ANOMALY_POINTS = 2
_IOC_CAP = 5

# Capability severity -> points per capability.
_CAP_POINTS = {1: 2, 2: 8, 3: 18}

# YARA meta "severity" values -> points (rules may declare their own weight).
_YARA_DEFAULT_POINTS = 15


def score_report(report: TriageReport) -> None:
    """Fill report.score, report.score_breakdown and report.verdict in place."""
    entries: list[ScoreEntry] = []
    packing: list[ScoreEntry] = []

    def add(entry: ScoreEntry, is_packing: bool = False) -> None:
        entries.append(entry)
        if is_packing:
            packing.append(entry)

    if report.packer.detected:
        names = ", ".join(report.packer.names) or "unknown"
        add(ScoreEntry(15, f"packer detected: {names}"), is_packing=True)

    if report.overall_entropy >= HIGH_ENTROPY_FILE:
        add(ScoreEntry(10, f"overall file entropy {report.overall_entropy:.2f}"), is_packing=True)

    for anomaly in report.anomalies:
        points = _WEAK_ANOMALY_POINTS if anomaly.startswith(_WEAK_ANOMALIES) else 6
        add(ScoreEntry(points, f"anomaly: {anomaly}"), is_packing=is_packing_anomaly(anomaly))

    if report.file.compile_timestamp_anomaly:
        entries.append(ScoreEntry(5, report.file.compile_timestamp_anomaly))

    common_points = 0
    for cap in report.capabilities:
        entry = ScoreEntry(_CAP_POINTS.get(cap.severity, 2), f"capability: {cap.name}")
        entries.append(entry)
        if cap.severity <= 2 and cap.source in _STRUCTURAL_SOURCES:
            common_points += entry.points
    if report.import_count >= _LARGE_IMPORT_TABLE and common_points > _COMMON_CAP:
        entries.append(ScoreEntry(_COMMON_CAP - common_points,
                                  f"cap: common capabilities of a large program "
                                  f"({report.import_count} imports) capped at {_COMMON_CAP}"))

    capabilities = {c.name: c for c in report.capabilities}
    for hit in report.yara:
        points = hit.meta.get("weight", _YARA_DEFAULT_POINTS)
        if not isinstance(points, int):
            points = _YARA_DEFAULT_POINTS
        cap = capabilities.get(hit.meta.get("overlaps"))
        if cap is not None and _same_evidence(hit, cap):
            # One fact seen twice (an imported API name is also a string in the
            # file): count it once, at the higher of the two weights.
            entries.append(ScoreEntry(max(0, points - _CAP_POINTS.get(cap.severity, 2)),
                                      f"YARA match: {hit.rule} (same evidence as capability "
                                      f"{cap.name}, counted once)"))
            continue
        add(ScoreEntry(points, f"YARA match: {hit.rule}"), is_packing="packer" in hit.tags)

    ioc_count = sum(
        report.string_stats.get(k, 0) for k in ("url", "ipv4", "domain")
    )
    if ioc_count:
        entries.append(ScoreEntry(min(ioc_count, _IOC_CAP), f"{ioc_count} network IOC string(s)"))

    cmd_count = report.string_stats.get("command", 0)
    if cmd_count:
        entries.append(ScoreEntry(min(4 * cmd_count, 16), f"{cmd_count} suspicious command string(s)"))

    # Encoded IOCs/commands are especially damning: a benign program has no
    # reason to XOR-hide a URL or an embedded PE.
    hidden = [
        d for d in report.decoded_strings
        if d.category in ("url", "ipv4", "domain", "command", "lolbin", "embedded-pe")
    ]
    if hidden:
        entries.append(ScoreEntry(min(8 * len(hidden), 24),
                                  f"{len(hidden)} encoded IOC/payload string(s) recovered"))

    # Extracted family config (a Discord webhook, Telegram token, stager URL)
    # is about as close to a smoking gun as static triage gets.
    if report.config_extractions:
        families = sorted({c.family for c in report.config_extractions})
        entries.append(ScoreEntry(min(15 * len(families), 30),
                                  f"extracted config: {', '.join(families)}"))

    packed_points = sum(e.points for e in packing)
    if packed_points > _PACKING_CAP:
        entries.append(ScoreEntry(_PACKING_CAP - packed_points,
                                  f"cap: packing signals are one fact, capped at {_PACKING_CAP}"))

    # Online reputation (opt-in, attached by the CLI): the wider world's verdict.
    rep_points, rep_reasons = 0, []
    for rep in report.reputation:
        if rep.status != "found":
            continue
        if rep.source == "VirusTotal" and rep.detections:
            mal, _, total = rep.detections.partition("/")
            try:
                mal_n, total_n = int(mal), int(total)
            except ValueError:
                mal_n, total_n = 0, 0
            ratio = mal_n / total_n if total_n else 0.0
            pts = 30 if ratio >= 0.5 else 20 if ratio >= 0.2 else 10 if mal_n >= 1 else 0
            if pts:
                rep_points += pts
                rep_reasons.append(f"VirusTotal {rep.detections} engines flag it")
        elif rep.source == "MalwareBazaar":
            rep_points += 20
            rep_reasons.append("known sample on MalwareBazaar" + (f" ({rep.family})" if rep.family else ""))
    if rep_points:
        entries.append(ScoreEntry(min(rep_points, 35), "reputation: " + ", ".join(rep_reasons)))

    # Authenticode: only a *verified* signature is a mitigation. A tampered or
    # revoked one is damning. A signature that is present but not valid
    # (self-signed, expired, unverified) earns nothing: anyone can self-sign.
    # A valid signature over a certificate table that hides extra data earns
    # nothing either: that is exactly how the 3CX DLL stayed "signed".
    sig = report.signature
    sig_valid = sig is not None and sig.status == "valid"
    padded = report.overlay is not None and report.overlay.cert_padding >= MIN_HIDDEN_BYTES
    if sig is not None:
        if sig_valid and padded:
            entries.append(ScoreEntry(0, "Authenticode signature valid but the certificate "
                                         "table carries unauthenticated data — no mitigation "
                                         "credit"))
        elif sig_valid and entries:
            # A verified signature is a real mitigation. It is intentionally a
            # flat credit that at most downgrades a sample one tier (it can never
            # bridge the 30-point gap from HIGH_RISK to LIKELY_CLEAN), and a floor
            # below stops it clearing a sample that carries a sev-3 capability.
            entries.append(ScoreEntry(-15, f"Authenticode signature valid ({sig.signer or 'signed'})"))
        elif sig.status == "tampered":
            entries.append(ScoreEntry(30, "Authenticode digest mismatch — file modified after signing"))
        elif sig.status == "revoked":
            entries.append(ScoreEntry(15, "Authenticode signing certificate revoked"))
        elif sig.present and entries:
            entries.append(ScoreEntry(0, f"Authenticode signature present but {sig.status}"
                                         " — no mitigation credit"))

    report.score_breakdown = entries
    report.score = max(0, sum(e.points for e in entries))

    # Signed malware with a stolen/leaked cert is real: a valid signature must
    # never pull a sample that carries a high-severity capability all the way
    # down to LIKELY_CLEAN. Floor it at SUSPICIOUS when the pre-signature score
    # already crossed that line.
    if sig_valid and any(c.severity == 3 for c in report.capabilities):
        pre_sig = sum(e.points for e in entries if not e.reason.startswith("Authenticode signature valid"))
        if pre_sig >= SUSPICIOUS_THRESHOLD and report.score < SUSPICIOUS_THRESHOLD:
            report.score = SUSPICIOUS_THRESHOLD
            report.score_breakdown.append(
                ScoreEntry(0, "floor: valid signature does not clear a sev-3 capability"))

    if report.score >= HIGH_RISK_THRESHOLD:
        report.verdict = Verdict.HIGH_RISK
    elif report.score >= SUSPICIOUS_THRESHOLD:
        report.verdict = Verdict.SUSPICIOUS
    else:
        report.verdict = Verdict.LIKELY_CLEAN


def _same_evidence(hit: YaraHit, cap: Capability) -> bool:
    """True when everything the rule matched is already the capability's evidence.

    A rule naming the injection APIs also matches the import table of a file
    that imports them; the same names kept as GetProcAddress strings, or a
    backup-deletion command the capability never saw, are separate evidence.
    """
    if not hit.matched or len(hit.matched) >= MAX_MATCHED:  # nothing to compare, or cut short
        return False
    evidence = "\n".join(cap.evidence).lower()
    return all(m.lower() in evidence for m in hit.matched)
