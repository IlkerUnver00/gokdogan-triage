"""Benign false-positive sweep.

Triage every PE under the given directories (default: this machine's System32
and Program Files), treat each one as benign, and report how often the verdict
says otherwise and which signals are responsible. That measures one half of a
benchmark, the false-positive rate. Recall needs a labelled malware corpus
handled in an isolated lab, which this script deliberately never touches.

    python scripts/benign_sweep.py --out sweep_results/all                  # every PE <= 12 MB
    python scripts/benign_sweep.py --limit 3000 --out sweep_results/tune    # random sample
    # the same files, scored by another engine (e.g. a worktree of a release)
    python scripts/benign_sweep.py --paths-from sweep_results/tune/results.jsonl \
        --engine ../gokdogan-v0.5.2 --out sweep_results/tune_old
    # a held-out sample: files (and byte-identical copies) of the tuning run left out
    python scripts/benign_sweep.py --limit 3000 --seed 2 \
        --exclude-results sweep_results/tune/results.jsonl --out sweep_results/holdout
    python scripts/benign_sweep.py --report sweep_results/tune/results.jsonl

Paths and hashes in the output describe this machine, so the output folder is
git-ignored; only the summary numbers belong in docs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import os
import queue
import random
import re
import signal
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_ROOTS = [
    r"C:\Windows\System32",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]
PE_EXTENSIONS = (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi")
SUSPICIOUS, HIGH_RISK = 30, 60

# Reason text -> stable signal key: drop what is specific to one file (names,
# counts, sizes, signer) so the same signal aggregates across the corpus.
_NORMALIZE = [
    (re.compile(r"^anomaly: section '.*?': (.*)$"), r"anomaly: section \1"),
    # One signal, three spellings: a PE at offset 0, a DOS stub further in,
    # or several resources aggregated into one note.
    (re.compile(r"^anomaly: (?:\d+ resources carry an embedded executable|"
                r"resource .*?: (?:embedded PE executable|contains an embedded executable)).*$"),
     "anomaly: resource embedded executable"),
    (re.compile(r"^anomaly: (?:\d+ resources are high-entropy|resource .*?: high entropy).*$"),
     "anomaly: resource high entropy"),
    (re.compile(r"^anomaly: resource .*?: (.*?)(?: \(.*)?$"), r"anomaly: resource \1"),
    (re.compile(r"^anomaly: \d+ bytes of unauthenticated data.*$"),
     "anomaly: unauthenticated certificate-table data"),
    (re.compile(r"^anomaly: entry point in last section .*$"), "anomaly: entry point in last section"),
    (re.compile(r"^anomaly: overlay contains an embedded executable.*$"),
     "anomaly: overlay contains an embedded executable"),
    (re.compile(r"^anomaly: overlay is an? (.*?) \(.*$"), r"anomaly: overlay is \1"),
    (re.compile(r"^anomaly: high-entropy overlay.*$"), "anomaly: high-entropy overlay"),
    (re.compile(r"^anomaly: Authenticode signature (\w+):.*$"), r"anomaly: Authenticode signature \1"),
    (re.compile(r"^anomaly: \.NET obfuscator detected:.*$"), "anomaly: .NET obfuscator detected"),
    (re.compile(r"^overall file entropy .*$"), "overall file entropy"),
    (re.compile(r"^packer detected: .*$"), "packer detected"),
    (re.compile(r"^\d+ network IOC string\(s\)$"), "network IOC strings"),
    (re.compile(r"^\d+ suspicious command string\(s\)$"), "suspicious command strings"),
    (re.compile(r"^\d+ encoded IOC/payload string\(s\) recovered$"), "encoded IOC/payload strings"),
    (re.compile(r"^reputation: .*$"), "reputation"),
    (re.compile(r"^Authenticode signature valid \(.*\)$"), "Authenticode signature valid"),
    (re.compile(r"^Authenticode signature present but (\w+).*$"),
     r"Authenticode signature present but \1"),
    (re.compile(r"^cap: packing.*$"), "cap: packing"),
    (re.compile(r"^cap: common capabilities.*$"), "cap: common capabilities"),
]
_DIGITS = re.compile(r"\d+")


def normalize(reason: str) -> str:
    """Collapse a score-breakdown reason into a corpus-wide signal key."""
    for pattern, replacement in _NORMALIZE:
        if pattern.match(reason):
            return pattern.sub(replacement, reason)
    return _DIGITS.sub("N", reason)


def _code_hash(package_dir: Path) -> str:
    """SHA-256 over the engine's source and rule files, in a stable order."""
    digest = hashlib.sha256()
    for f in sorted(package_dir.rglob("*")):
        if f.suffix in (".py", ".yar", ".yara"):
            digest.update(f.relative_to(package_dir).as_posix().encode())
            digest.update(f.read_bytes())
    return digest.hexdigest()


def collect(roots: list[str], max_bytes: int) -> tuple[list[str], dict[str, int]]:
    """PE files under roots (by extension and MZ header), plus skip counts."""
    found: list[str] = []
    skipped: Counter = Counter()
    for root in roots:
        for dirpath, _dirs, files in os.walk(root, onerror=lambda _e: skipped.update(["unreadable dir"])):
            for name in files:
                if not name.lower().endswith(PE_EXTENSIONS):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    size = os.path.getsize(path)
                    if size > max_bytes:
                        skipped["larger than --max-mb"] += 1
                        continue
                    with open(path, "rb") as fh:
                        if fh.read(2) != b"MZ":
                            skipped["no MZ header"] += 1
                            continue
                except OSError:
                    skipped["unreadable file"] += 1
                    continue
                found.append(path)
    return found, dict(skipped)


_started_queue = None
_worker_token = None
# How long a finished worker's last row may take to arrive before the item it
# held counts as lost (a worker also exits normally after maxtasksperchild).
_GRACE_SECONDS = 10.0


def _init_worker(started_queue) -> None:
    global _started_queue, _worker_token
    _started_queue = started_queue
    # Windows reuses PIDs; this token names one worker process for its life.
    _worker_token = f"{os.getpid()}-{time.time_ns()}"


def report_start(item: str) -> None:
    """Called by a worker as it starts an item, so the parent can time it out."""
    if _started_queue is not None:
        _started_queue.put((_worker_token, os.getpid(), item, time.time()))


def report_fields(report, use_yara: bool) -> dict:
    """The per-file fields every sweep records from a TriageReport."""
    return dict(
        # False when YARA was off or could not run (e.g. yara-python missing):
        # two sweeps compare only if both scored with the same rules.
        yara=use_yara and report.yara_error is None,
        sha256=report.file.sha256,
        size=report.file.size,
        verdict=report.verdict.value,
        score=report.score,
        signature=report.signature.status if report.signature else None,
        signed=report.file.is_signed,
        is_dll=report.file.is_dll,
        dotnet=report.dotnet is not None,
        packed=report.packer.detected,
        breakdown=[[e.points, e.reason] for e in report.score_breakdown],
    )


def _triage_one(args: tuple[str, bool]) -> dict:
    path, use_yara = args
    report_start(path)
    started = time.perf_counter()
    row: dict = {"path": path}
    try:
        from gokdogan.engine import triage

        row.update(report_fields(triage(path, use_yara=use_yara), use_yara))
    except Exception as exc:  # a parser failure is a result, not a crash
        row.update(error=f"{type(exc).__name__}: {exc}")
    row["seconds"] = round(time.perf_counter() - started, 3)
    return row


def run(paths: list[str], jobs: int, use_yara: bool, out_jsonl: Path,
        timeout: float = 120.0, exclude_hashes: frozenset[str] = frozenset(),
        worker=_triage_one, extra: tuple = ()) -> list[dict]:
    """Triage paths in a worker pool; a file that runs past `timeout` seconds
    (or kills its worker) becomes an error row instead of stalling the sweep.
    Rows whose hash is in `exclude_hashes` are kept but marked excluded.

    `worker` receives ``(path, use_yara, *extra)``, must call report_start(path)
    first and return a row whose "path" is that same string (other sweeps,
    such as recall_sweep.py, plug their own reader in here)."""
    rows: list[dict] = []
    finished: set[str] = set()
    paths = list(dict.fromkeys(paths))  # a repeated path could never finish twice
    results: queue.Queue = queue.Queue()
    started_q = multiprocessing.Queue()
    running: dict[str, tuple[int, str, float]] = {}  # worker token -> (pid, path, start)
    gone: dict[str, float] = {}  # worker token -> when its process was first missed
    started = time.perf_counter()
    pool = multiprocessing.Pool(jobs, initializer=_init_worker, initargs=(started_q,),
                                maxtasksperchild=40)

    def fail(path: str, reason: str) -> None:
        results.put({"path": path, "error": reason, "failure": reason.split()[0]})

    try:
        for p in paths:
            pool.apply_async(worker, ((p, use_yara, *extra),), callback=results.put,
                             error_callback=lambda exc, p=p: results.put(
                                 {"path": p, "error": f"{type(exc).__name__}: {exc}"}))
        with out_jsonl.open("w", encoding="utf-8") as sink:
            while len(finished) < len(paths):
                live = {w.pid for w in pool._pool if w.is_alive()}
                while True:
                    try:
                        token, pid, path, t0 = started_q.get_nowait()
                    except queue.Empty:
                        break
                    # Another token on this PID: that worker died and Windows
                    # gave its PID to a new one. The same token starting a new
                    # item only means its last row is still on the way.
                    for other, (other_pid, other_path, _) in list(running.items()):
                        if other != token and other_pid == pid:
                            del running[other]
                            gone.pop(other, None)
                            if other_path not in finished:
                                fail(other_path, "worker died on this file")
                    if path not in finished:
                        running[token] = (pid, path, t0)
                now = time.time()
                for token, (pid, path, t0) in list(running.items()):
                    if path in finished:
                        del running[token]
                        gone.pop(token, None)
                    elif pid not in live:
                        # Exited (a crash, or maxtasksperchild after its last item):
                        # give a row already sent time to arrive before failing it.
                        if now - gone.setdefault(token, now) > _GRACE_SECONDS:
                            del running[token]
                            gone.pop(token, None)
                            fail(path, "worker died on this file")
                    elif now - t0 > timeout:
                        del running[token]
                        fail(path, f"timeout after {timeout:.0f}s")
                        try:
                            os.kill(pid, signal.SIGTERM)  # the pool starts a replacement
                        except OSError:
                            pass
                try:
                    row = results.get(timeout=0.2)
                except queue.Empty:
                    continue
                if row["path"] in finished:
                    continue  # finished just as it was timed out
                finished.add(row["path"])
                if row.get("sha256") in exclude_hashes:
                    row["excluded"] = "same bytes as a file of an excluded run"
                rows.append(row)
                sink.write(json.dumps(row) + "\n")
                if len(rows) % 50 == 0:
                    sink.flush()  # a killed run keeps what it measured
                if len(rows) % 250 == 0 or len(rows) == len(paths):
                    rate = len(rows) / (time.perf_counter() - started)
                    print(f"  {len(rows)}/{len(paths)} files, {rate:.1f}/s", file=sys.stderr)
    finally:
        pool.terminate()
        pool.join()
    return rows


def summarize(rows: list[dict]) -> dict:
    """Aggregate verdicts and per-signal contributions over unique files.

    Rows marked excluded (same bytes as a file of an excluded run) are left
    out, so re-summarising a held-out run gives the numbers it gave.
    """
    unique: dict[str, dict] = {}
    errors = []
    excluded = 0
    for row in rows:
        if row.get("excluded"):
            excluded += 1
        elif "error" in row:
            errors.append(row)
        else:
            unique.setdefault(row["sha256"], row)
    files = list(unique.values())
    verdicts = Counter(r["verdict"] for r in files)

    fired: Counter = Counter()
    fired_fp: Counter = Counter()
    points_fp: defaultdict = defaultdict(int)
    for r in files:
        flagged = r["score"] >= SUSPICIOUS
        seen: set[str] = set()
        for points, reason in r["breakdown"]:
            key = normalize(reason)
            if flagged:
                points_fp[key] += points
            if key in seen:
                continue
            seen.add(key)
            fired[key] += 1
            if flagged:
                fired_fp[key] += 1

    n = len(files) or 1
    flagged_n = verdicts["SUSPICIOUS"] + verdicts["HIGH_RISK"]
    signals = sorted(
        ({"signal": k, "files": fired[k], "flagged_files": fired_fp[k],
          "points_in_flagged": points_fp[k]} for k in fired),
        key=lambda s: -s["points_in_flagged"],
    )
    worst = sorted(files, key=lambda r: -r["score"])[:25]
    # A timeout or a dead worker is not a parse error: those files may be
    # exactly the ones an engine would flag, so they are counted apart.
    failures = sum(1 for r in errors if r.get("failure"))
    return {
        "files": len(files),
        "duplicates_skipped": len(rows) - len(files) - len(errors) - excluded,
        "excluded_same_bytes": excluded,
        "errors": len(errors) - failures,
        "timeouts_or_crashes": failures,
        "verdicts": dict(verdicts),
        "suspicious_or_worse_rate": round(flagged_n / n, 4),
        "high_risk_rate": round(verdicts["HIGH_RISK"] / n, 4),
        "signals": signals,
        "worst": [{"path": r["path"], "score": r["score"], "verdict": r["verdict"],
                   "top": sorted(({"points": p, "reason": t} for p, t in r["breakdown"]),
                                 key=lambda e: -e["points"])[:6]} for r in worst],
        "error_samples": [{"path": r["path"], "error": r["error"]} for r in errors[:10]],
    }


def to_markdown(summary: dict, skipped: dict[str, int] | None = None) -> str:
    v = summary["verdicts"]
    run_args = (summary.get("engine") or {}).get("args") or {}
    lines = [
        "# Benign sweep",
        "",
        f"- Unique files: **{summary['files']}** "
        f"(duplicates: {summary['duplicates_skipped']}, parse errors: {summary['errors']}, "
        f"timeouts/crashes: {summary.get('timeouts_or_crashes', 0)}, "
        f"same bytes as an excluded run: {summary.get('excluded_same_bytes', 0)})",
        f"- LIKELY_CLEAN {v.get('LIKELY_CLEAN', 0)} · SUSPICIOUS {v.get('SUSPICIOUS', 0)} · "
        f"HIGH_RISK {v.get('HIGH_RISK', 0)}",
        f"- False positives: **{summary['suspicious_or_worse_rate']:.1%}** SUSPICIOUS or worse, "
        f"**{summary['high_risk_rate']:.1%}** HIGH_RISK",
    ]
    if skipped:
        lines.append("- Not scanned: " + ", ".join(f"{k} {n}" for k, n in sorted(skipped.items())))
    if run_args:
        shown = {k: run_args[k] for k in ("max_mb", "limit", "seed", "paths_from", "exclude_results")
                 if run_args.get(k)}
        lines.append("- Run: " + ", ".join(f"{k}={val}" for k, val in shown.items()))
    lines += ["", "## Signals behind the false positives", "",
              "| signal | files | in flagged files | points in flagged files |", "|---|---:|---:|---:|"]
    for s in summary["signals"][:30]:
        lines.append(f"| {s['signal']} | {s['files']} | {s['flagged_files']} | {s['points_in_flagged']} |")
    lines += ["", "## Highest-scoring benign files", ""]
    for w in summary["worst"]:
        top = "; ".join(f"{e['points']:+d} {e['reason'][:60]}" for e in w["top"])
        lines.append(f"- **{w['score']}** {w['verdict']} `{os.path.basename(w['path'])}` — {top}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--roots", nargs="*", default=DEFAULT_ROOTS, help="directories to sweep")
    ap.add_argument("--out", default="sweep_results", help="output folder (git-ignored)")
    ap.add_argument("--limit", type=int, default=0, help="random sample of N files (0 = all)")
    ap.add_argument("--seed", type=int, default=1, help="sampling seed")
    ap.add_argument("--max-mb", type=float, default=12.0, help="skip files larger than this")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--no-yara", action="store_true", help="skip the YARA stage")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="seconds before one file is recorded as a timeout")
    ap.add_argument("--exclude-results", metavar="JSONL", nargs="*", default=[],
                    help="leave out every file (by path and hash) of earlier runs: a held-out "
                         "sample to check calibration done on those runs")
    ap.add_argument("--paths-from", metavar="JSONL",
                    help="sweep exactly the files of an earlier results.jsonl (a seed picks a "
                         "different sample once files on disk change)")
    ap.add_argument("--engine", metavar="DIR",
                    help="import gokdogan from this directory (e.g. a worktree of an older "
                         "release) and refuse to run if another copy is picked up")
    ap.add_argument("--report", metavar="JSONL", help="only re-summarise an earlier results.jsonl")
    args = ap.parse_args(argv)
    if args.engine:
        # Workers are spawned with the parent's sys.path, so this reaches them too.
        sys.path.insert(0, os.path.abspath(args.engine))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    skipped: dict[str, int] | None = None
    if args.report:
        rows = [json.loads(line) for line in Path(args.report).read_text(encoding="utf-8").splitlines()
                if line.strip()]
        sidecar = Path(args.report).with_name("engine.json")
        engine = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar.exists() else None
        if args.exclude_results:
            excluded = {json.loads(line).get("sha256") for f in args.exclude_results
                        for line in Path(f).read_text(encoding="utf-8").splitlines() if line.strip()}
            for row in rows:
                if row.get("sha256") in excluded:
                    row["excluded"] = "same bytes as a file of an excluded run"
    else:
        import gokdogan

        # Record which engine scored the files: a sweep is only comparable with
        # another if both ran the code they claim to (workers import it afresh).
        # The version string does not change between commits, so the code
        # itself is hashed; the arguments say how the sample was drawn.
        engine = {"version": gokdogan.__version__, "path": os.path.dirname(gokdogan.__file__),
                  "code_sha256": _code_hash(Path(gokdogan.__file__).parent), "args": vars(args)}
        if args.engine and not os.path.abspath(engine["path"]).lower().startswith(
                os.path.abspath(args.engine).lower()):
            ap.error(f"--engine {args.engine} requested but gokdogan came from {engine['path']}")
        (out / "engine.json").write_text(json.dumps(engine, indent=1), encoding="utf-8")
        print(f"engine: gokdogan {engine['version']} from {engine['path']} "
              f"(code {engine['code_sha256'][:12]})", file=sys.stderr)
        if args.paths_from:
            paths = [json.loads(line)["path"] for line in
                     Path(args.paths_from).read_text(encoding="utf-8").splitlines() if line.strip()]
            missing = [p for p in paths if not os.path.isfile(p)]
            paths = [p for p in paths if os.path.isfile(p)]
            skipped = {"listed but no longer on disk": len(missing)} if missing else {}
        else:
            paths, skipped = collect(args.roots, int(args.max_mb * 1024 * 1024))
        seen_hashes: frozenset[str] = frozenset()
        if args.exclude_results:
            earlier = [json.loads(line) for f in args.exclude_results
                       for line in Path(f).read_text(encoding="utf-8").splitlines() if line.strip()]
            seen_paths = {r["path"].lower() for r in earlier}
            # Same bytes under another path (a copied DLL) are not held out either;
            # those rows are marked in results.jsonl and left out of the summary.
            seen_hashes = frozenset(r["sha256"] for r in earlier if "sha256" in r)
            before = len(paths)
            paths = [p for p in paths if p.lower() not in seen_paths]
            skipped["in an excluded earlier run"] = before - len(paths)
        if args.limit and args.limit < len(paths):
            skipped["not in the random sample"] = len(paths) - args.limit
            paths = random.Random(args.seed).sample(paths, args.limit)
        print(f"sweeping {len(paths)} files with {args.jobs} workers", file=sys.stderr)
        rows = run(paths, args.jobs, not args.no_yara, out / "results.jsonl", args.timeout,
                   seen_hashes)

    summary = summarize(rows)
    summary["skipped"] = skipped
    summary["engine"] = engine
    (out / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    (out / "summary.md").write_text(to_markdown(summary, skipped), encoding="utf-8")
    v = summary["verdicts"]
    print(f"{summary['files']} unique files: {v.get('SUSPICIOUS', 0)} suspicious, "
          f"{v.get('HIGH_RISK', 0)} high-risk -> {summary['suspicious_or_worse_rate']:.1%} "
          f"flagged ({out / 'summary.md'})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
