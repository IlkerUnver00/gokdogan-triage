"""Command-line interface.

    gokdogan sample.exe
    gokdogan C:\\samples --json out\\
    gokdogan sample.exe --json report.json --rules my_rules\\
    gokdogan C:\\dropzone --csv triage.csv          # batch summary
    gokdogan C:\\dropzone --jsonl triage.jsonl      # stream into a SIEM
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .baseline import diff_reports
from .cluster import cluster_reports
from .engine import NotAPEError, triage
from .fuzzy import compare_ssdeep, compare_tlsh, ssdeep_hash, tlsh_hash
from .html_report import render_html
from .misp import render_misp
from .models import Verdict
from .report import render_console, render_json, render_navigator_layer
from .reputation import lookup as reputation_lookup
from .summary import summary_row, write_csv, write_jsonl
from .verdict import score_report

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi", ".bin"}

# Exit codes let gokdogan slot into pipelines:
#   0 = all clean, 1 = usage/parse error, 2 = suspicious, 3 = high risk
_EXIT = {Verdict.LIKELY_CLEAN: 0, Verdict.SUSPICIOUS: 2, Verdict.HIGH_RISK: 3}


def _resolve_output(arg: str | None, n_targets: int) -> tuple[Path | None, Path | None]:
    """Resolve an output path argument to (directory, file) — exactly one set.

    A directory is used when scanning many files or when the path already
    exists as a directory; otherwise the path is treated as a single file.
    """
    if not arg:
        return None, None
    path = Path(arg)
    if n_targets > 1 or path.is_dir():
        path.mkdir(parents=True, exist_ok=True)
        return path, None
    return None, path


def _print_comparison(report, ref_ssdeep: str | None, ref_tlsh: str | None) -> None:
    """Print fuzzy similarity between a report's sample and the reference."""
    ss = compare_ssdeep(report.file.ssdeep, ref_ssdeep)
    tl = compare_tlsh(report.file.tlsh, ref_tlsh)
    parts = []
    if ss is not None:
        verdict = "identical" if ss == 100 else ("related" if ss >= 50 else "weak/none")
        parts.append(f"ssdeep {ss}/100 ({verdict})")
    if tl is not None:
        verdict = "identical" if tl == 0 else ("related" if tl <= 150 else "unrelated")
        parts.append(f"TLSH distance {tl} ({verdict})")
    if not parts:
        parts.append("no comparable fuzzy hashes")
    print(f"  compare vs reference: {'; '.join(parts)}")


def _print_clusters(reports: list) -> None:
    clusters = cluster_reports(reports)
    print(f"\n── Clusters ── {len(reports)} sample(s), "
          f"{len(clusters)} related group(s)", file=sys.stderr)
    if not clusters:
        print("  no related samples found", file=sys.stderr)
        return
    for i, cluster in enumerate(clusters, 1):
        print(f"  [{i}] {len(cluster.members)} files "
              f"(by {', '.join(cluster.bases)}):", file=sys.stderr)
        for path in cluster.members:
            print(f"        {path}", file=sys.stderr)


def _print_baseline_diff(report, baseline_report) -> None:
    d = diff_reports(report, baseline_report)
    if d.identical:
        print("  baseline: identical to reference (bit-for-bit minus signature)")
        return
    bits = [f"imphash {'match' if d.same_imphash else 'DIFFERS'}"]
    if d.sections_added:
        bits.append(f"+sections {','.join(d.sections_added)}")
    if d.sections_removed:
        bits.append(f"-sections {','.join(d.sections_removed)}")
    if d.sections_changed:
        bits.append(f"changed {','.join(d.sections_changed)}")
    if abs(d.entropy_delta) >= 0.1:
        bits.append(f"entropy {d.entropy_delta:+.2f}")
    if d.capabilities_added:
        bits.append(f"NEW capabilities: {', '.join(d.capabilities_added)}")
    print(f"  baseline diff: {'; '.join(bits)}")


def _collect_targets(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(
            p for p in path.rglob("*")
            if p.is_file() and p.suffix.lower() in PE_EXTENSIONS
        )
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gokdogan",
        description="Static PE malware triage: hashes, entropy, packer, strings, capabilities, YARA, verdict.",
    )
    parser.add_argument("target", help="PE file or directory of PE files")
    parser.add_argument("--json", metavar="PATH",
                        help="write JSON report to file (or directory when scanning a directory)")
    parser.add_argument("--html", metavar="PATH",
                        help="write a self-contained HTML report to file "
                             "(or directory when scanning a directory)")
    parser.add_argument("--attack-layer", metavar="PATH",
                        help="write a MITRE ATT&CK Navigator layer (.json) to file "
                             "(or directory when scanning a directory)")
    parser.add_argument("--misp", metavar="PATH",
                        help="write a MISP-importable event (.json) to file "
                             "(or directory when scanning a directory)")
    parser.add_argument("--compare", metavar="PATH",
                        help="reference file to fuzzy-compare each target against "
                             "(prints ssdeep similarity 0-100 and TLSH distance)")
    parser.add_argument("--baseline", metavar="PATH",
                        help="known-good reference PE to diff each target against "
                             "(sections/hashes/capabilities added or changed)")
    parser.add_argument("--csv", metavar="PATH",
                        help="write a one-row-per-sample CSV summary (batch triage)")
    parser.add_argument("--jsonl", metavar="PATH",
                        help="write a one-object-per-sample JSONL summary (batch triage)")
    parser.add_argument("--reputation", action="store_true",
                        help="OPT-IN network lookup: send each sample's SHA-256 (never the file) "
                             "to VirusTotal / MalwareBazaar. Off by default.")
    parser.add_argument("--vt-key", metavar="KEY", default=os.environ.get("VT_API_KEY"),
                        help="VirusTotal API key (or set VT_API_KEY)")
    parser.add_argument("--mb-key", metavar="KEY", default=os.environ.get("MB_API_KEY"),
                        help="MalwareBazaar Auth-Key (or set MB_API_KEY)")
    parser.add_argument("--rules", metavar="DIR", help="YARA rules directory (default: bundled rules/)")
    parser.add_argument("--no-yara", action="store_true", help="skip YARA scanning")
    parser.add_argument("--no-verify-sig", action="store_true",
                        help="skip Authenticode signature verification (Windows-only, offline)")
    parser.add_argument("--min-strlen", type=int, default=6, metavar="N",
                        help="minimum string length to extract (default 6)")
    parser.add_argument("--cluster", action="store_true",
                        help="group related samples in a directory by shared hashes / fuzzy similarity")
    parser.add_argument("--quiet", action="store_true", help="one summary line per file instead of a full report")
    parser.add_argument("--version", action="version", version=f"gokdogan {__version__}")
    args = parser.parse_args(argv)

    targets = _collect_targets(Path(args.target))
    if not targets:
        print(f"error: no PE files found at {args.target!r}", file=sys.stderr)
        return 1

    json_dir, json_file = _resolve_output(args.json, len(targets))
    html_dir, html_file = _resolve_output(args.html, len(targets))
    layer_dir, layer_file = _resolve_output(args.attack_layer, len(targets))
    misp_dir, misp_file = _resolve_output(args.misp, len(targets))

    if args.reputation:
        if not (args.vt_key or args.mb_key):
            print("error: --reputation needs an API key (--vt-key/--mb-key or VT_API_KEY/MB_API_KEY)",
                  file=sys.stderr)
            return 1
        print(f"note: --reputation will send {len(targets)} SHA-256 hash(es) (not the files) "
              "to VirusTotal/MalwareBazaar", file=sys.stderr)

    baseline_report = None
    if args.baseline:
        try:
            baseline_report = triage(args.baseline, use_yara=False, verify_signature=False)
        except (NotAPEError, OSError) as exc:
            print(f"error reading --baseline reference {args.baseline}: {exc}", file=sys.stderr)
            return 1

    ref_ssdeep = ref_tlsh = None
    if args.compare:
        try:
            ref_bytes = Path(args.compare).read_bytes()
            ref_ssdeep, ref_tlsh = ssdeep_hash(ref_bytes), tlsh_hash(ref_bytes)
        except OSError as exc:
            print(f"error reading --compare reference {args.compare}: {exc}", file=sys.stderr)
            return 1

    # In batch (summary) mode the per-file console report is suppressed unless
    # explicitly asked for; the CSV/JSONL is the deliverable.
    batch = bool(args.csv or args.jsonl)
    rows = []
    reports = []
    tally = {Verdict.LIKELY_CLEAN: 0, Verdict.SUSPICIOUS: 0, Verdict.HIGH_RISK: 0}

    worst = 0
    for target in targets:
        try:
            report = triage(
                target,
                rules_dir=args.rules,
                min_string_length=args.min_strlen,
                use_yara=not args.no_yara,
                verify_signature=not args.no_verify_sig,
            )
        except NotAPEError as exc:
            print(f"skipped: {exc}", file=sys.stderr)
            continue
        except OSError as exc:
            print(f"error reading {target}: {exc}", file=sys.stderr)
            continue

        # Reputation is the only network step and stays out of the pure,
        # offline engine — attached here only when explicitly opted in.
        if args.reputation:
            report.reputation = reputation_lookup(report.file.sha256, args.vt_key, args.mb_key)
            score_report(report)  # reputation is a scoring signal; re-score with it attached

        if args.quiet or batch or args.cluster:
            print(f"{report.verdict.value:<13} score={report.score:<4} "
                  f"{report.file.sha256[:16]}  {target}")
        else:
            render_console(report)

        if args.compare:
            _print_comparison(report, ref_ssdeep, ref_tlsh)
        if baseline_report is not None:
            _print_baseline_diff(report, baseline_report)

        if json_dir is not None:
            (json_dir / (target.name + ".json")).write_text(render_json(report), encoding="utf-8")
        elif json_file is not None:
            json_file.write_text(render_json(report), encoding="utf-8")

        if html_dir is not None:
            (html_dir / (target.name + ".html")).write_text(render_html(report), encoding="utf-8")
        elif html_file is not None:
            html_file.write_text(render_html(report), encoding="utf-8")

        if layer_dir is not None:
            (layer_dir / (target.name + ".attack.json")).write_text(
                render_navigator_layer(report), encoding="utf-8")
        elif layer_file is not None:
            layer_file.write_text(render_navigator_layer(report), encoding="utf-8")

        if misp_dir is not None:
            (misp_dir / (target.name + ".misp.json")).write_text(
                render_misp(report), encoding="utf-8")
        elif misp_file is not None:
            misp_file.write_text(render_misp(report), encoding="utf-8")

        if batch:
            rows.append(summary_row(report))
        if args.cluster:
            reports.append(report)
        tally[report.verdict] += 1
        worst = max(worst, _EXIT[report.verdict])

    if args.csv:
        write_csv(rows, args.csv)
    if args.jsonl:
        write_jsonl(rows, args.jsonl)
    if args.cluster:
        _print_clusters(reports)

    scanned = sum(tally.values())
    if scanned > 1 or batch:
        print(
            f"\n{scanned} file(s): "
            f"{tally[Verdict.HIGH_RISK]} high-risk, "
            f"{tally[Verdict.SUSPICIOUS]} suspicious, "
            f"{tally[Verdict.LIKELY_CLEAN]} clean",
            file=sys.stderr,
        )

    return worst


if __name__ == "__main__":
    sys.exit(main())
