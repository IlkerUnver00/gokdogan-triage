"""Benign false-positive sweep.

Triage every PE under the given directories (default: this machine's System32,
Program Files and the .NET runtime folder), treat each one as benign, and report how often the verdict
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
import faulthandler
import hashlib
import json
import multiprocessing
import multiprocessing.connection
import os
import random
import re
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

DEFAULT_ROOTS = [
    r"C:\Windows\System32",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows\Microsoft.NET",  # the .NET runtime and GAC: every .NET rule must see it
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
    """SHA-256 over the engine's source and rule files, in a stable order.

    Line endings are folded to LF: git checks a commit out with CRLF on
    Windows and LF on Linux, and a recall run in a Linux lab must match a
    benign sweep of the same commit on Windows."""
    digest = hashlib.sha256()
    for f in sorted(package_dir.rglob("*")):
        if f.suffix in (".py", ".yar", ".yara"):
            digest.update(f.relative_to(package_dir).as_posix().encode())
            digest.update(f.read_bytes().replace(b"\r\n", b"\n"))
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


# Each worker process talks to the parent over a pipe of its own. Nothing is
# shared between workers, so killing one that runs past the timeout cannot
# leave a lock held that the others need (a multiprocessing.Pool's shared
# queues can), and the parent always knows which item each worker holds.
_conn = None       # this worker's end of its pipe; None in the parent
_TASKS_PER_WORKER = 40  # then a fresh process, so a leak in one file cannot grow
# The parent's ends of the live workers' pipes. A forked worker inherits them
# and closes them first, so that it sees EOF if the parent dies.
_parent_ends: set = set()
_MAX_JOBS_WINDOWS = 60  # Windows waits on at most 63 handles; one pipe per busy worker


def worker_count(jobs: int, items: int) -> int:
    """How many workers run() starts for `jobs` requested and `items` to do."""
    if sys.platform == "win32":
        jobs = min(jobs, _MAX_JOBS_WINDOWS)
    return max(0, min(jobs, items))


def report_start(item: str) -> None:
    """Called by a worker as it starts an item. The timeout counts from when
    the parent hands the item over; this restarts it (a fresh process's
    start-up does not count) and marks the item begun: a worker lost before
    this call says nothing about the file, which is then tried once more."""
    if _conn is not None:
        _conn.send(("start", None))


def report_progress(**fields) -> None:
    """Called by a worker mid-item with what it has learnt so far (such as the
    sample's sha256): the parent puts it on the row if the item then times
    out or kills its worker."""
    if _conn is not None:
        _conn.send(("progress", fields))


def _exit_with_parent() -> None:
    """The per-file timeout lives in the parent: if the parent dies, a worker
    stuck in a file must not run on for ever."""
    parent = multiprocessing.parent_process()
    if parent is not None and parent.sentinel is not None:
        multiprocessing.connection.wait([parent.sentinel])
        os._exit(1)


def _hard_limit(timeout: float) -> float:
    """When a worker ends itself on one file: well after the parent would have
    killed it, so this only matters once the parent is gone."""
    return timeout * 1.5 + 30


def _worker_main(conn, worker, use_yara: bool, extra: tuple, timeout: float) -> None:
    global _conn
    for inherited in list(_parent_ends):  # fork copies them; spawn and forkserver do not
        inherited.close()
    _parent_ends.clear()
    threading.Thread(target=_exit_with_parent, daemon=True).start()
    # The thread above needs the GIL, which a runaway regex can hold for good;
    # faulthandler's watchdog is C and ends the process without it.
    backstop = open(os.devnull, "w")  # noqa: SIM115 - for the life of the process
    _conn = conn
    for _ in range(_TASKS_PER_WORKER):
        try:
            item = conn.recv()
        except (EOFError, OSError):
            return
        if item is None:
            return
        faulthandler.dump_traceback_later(_hard_limit(timeout), exit=True, file=backstop)
        try:
            row = worker((item, use_yara, *extra))
        except Exception as exc:
            row = {"path": item, "error": f"{type(exc).__name__}: {exc}"}
        finally:
            faulthandler.cancel_dump_traceback_later()
        conn.send(("row", row))


_stuck: list[int] = []  # workers that outlived a kill (stuck in the kernel): their pids


def exit_past_stuck_workers() -> None:
    """Called once the results are written. A worker that could not be killed
    would hold multiprocessing's exit handlers (and a forkserver or resource
    tracker) until the kernel lets it go, so the sweep leaves without them."""
    if _stuck:
        print(f"warning: {len(_stuck)} worker(s) could not be killed "
              f"(pid {', '.join(map(str, _stuck))}); exiting without waiting for them",
              file=sys.stderr)
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)


class _Worker:
    """One worker process, its pipe, and the item it holds."""

    def __init__(self, ctx, worker, use_yara: bool, extra: tuple, timeout: float, live: set):
        self.conn, child = ctx.Pipe()
        _parent_ends.add(self.conn)
        self.proc = ctx.Process(target=_worker_main,
                                args=(child, worker, use_yara, extra, timeout), daemon=True)
        try:
            self.proc.start()
        except BaseException:
            _parent_ends.discard(self.conn)
            self.conn.close()
            raise
        finally:
            child.close()
        self.live = live
        live.add(self)  # run() stops everything in here, however it ends
        self.item: str | None = None
        self.given = 0          # items handed to this process
        self.began = False      # the worker reported starting its current item
        self.since = 0.0        # when the current item was handed over or began
        self.progress: dict = {}
        self.killed = False     # killed on a timeout: never reused, even if slow to die

    def give(self, item: str) -> bool:
        try:
            self.conn.send(item)
        except (OSError, ValueError):
            return False
        self.item, self.began, self.since, self.progress = item, False, time.monotonic(), {}
        self.given += 1
        return True

    def drain(self) -> list[dict]:
        """Rows already sent; start and progress notes are applied as read.
        Stops at a closed or garbled pipe (the process is gone)."""
        rows = []
        while True:
            try:
                if not self.conn.poll():
                    break
                kind, payload = self.conn.recv()
            except Exception:  # EOF, or a message cut short by a kill
                break
            if kind == "start":
                self.began, self.since = True, time.monotonic()
            elif kind == "progress" and isinstance(payload, dict):
                self.progress.update(payload)
            elif kind == "row" and self.item is not None:
                if not isinstance(payload, dict):
                    payload = {"error": f"the worker returned {type(payload).__name__}, not a row"}
                rows.append(dict(payload, path=self.item))
                self.item = None
        return rows

    def kill(self) -> None:
        if self.killed:
            return
        self.killed = True
        if self.proc.is_alive():
            self.proc.kill()
            self.proc.join(1)
        if self.proc.is_alive():
            # Stuck in the kernel (a hung disk, say): leave it behind.
            getattr(multiprocessing.process, "_children", set()).discard(self.proc)
            _stuck.append(self.proc.pid)

    def stop(self) -> None:
        if self not in self.live:
            return  # stopped already
        self.kill()
        self.conn.close()
        _parent_ends.discard(self.conn)
        self.live.discard(self)
        if not self.proc.is_alive():
            self.proc.close()  # its sentinel and, under fork, the pipes a later worker would inherit


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
        # None from an engine without the Go stage (--engine): unknown, not "not Go".
        go=(report.go is not None) if hasattr(report, "go") else None,
        packed=report.packer.detected,
        breakdown=[[e.points, e.reason] for e in report.score_breakdown],
        # Structure, so a later analysis can weigh features the score does not
        # use yet without another lab run.
        features=_features(report),
    )


def _features(report) -> dict:
    f, ov = report.file, report.overlay
    resource_types = sorted({r.type for r in report.resources})
    return dict(
        subsystem=getattr(f, "subsystem", ""), managed=getattr(f, "managed", False),
        is_driver=f.is_driver, entry_point=f.entry_point, entry_section=f.entry_section,
        import_count=getattr(report, "import_count", None),   # older engines (--engine) lack some
        delay_imports=len(getattr(report, "delay_imports", [])),
        overall_entropy=report.overall_entropy, image_entropy=getattr(report, "image_entropy", None),
        compile_timestamp=f.compile_timestamp, rich_header=report.rich is not None,
        resources=len(report.resources), resource_types=resource_types[:20],
        version_info="RT_VERSION" in resource_types, manifest="RT_MANIFEST" in resource_types,
        overlay=None if ov is None else dict(
            size=ov.size, payload=getattr(ov, "payload_size", None), entropy=ov.entropy,
            type=ov.type_guess, signature_only=ov.is_signature),
        sections=[[s.name, s.raw_size, s.virtual_size, s.entropy, s.is_executable, s.is_writable]
                  for s in report.sections[:32]],
        string_stats=dict(report.string_stats),
        go=_go_features(getattr(report, "go", None)),
    )


# Build settings worth comparing across programs; the rest (paths, flags of
# cgo compilers) would only bloat the rows.
_GO_SETTINGS = ("-buildmode", "-compiler", "-trimpath", "-ldflags", "-tags", "CGO_ENABLED", "GOARCH",
                "GOOS", "GOAMD64", "GO386", "vcs", "vcs.modified")


def _go_features(go) -> dict | None:
    """What the Go stage read, for the analysis of Go programs (10-20 KB a file)."""
    if go is None:
        return None
    from gokdogan.golang import package_kind

    kinds = {p: package_kind(p) for p in go.packages}
    mod = go.main_module
    return dict(
        version=go.version, version_source=go.version_source, evidence=list(go.evidence),
        confirmed=go.confirmed, ptr=go.ptr_size, buildinfo=go.buildinfo_format, layout=go.pclntab_layout,
        functions=go.function_count, names=go.name_count, packages=go.package_count,
        std=go.std_package_count, third_party=go.third_party_count, local=go.local_package_count,
        third_party_packages=[p for p in go.packages if kinds[p] == "third-party"][:300],
        local_packages=[p for p in go.packages if kinds[p] == "local"][:100],
        main=go.main_path, module=None if mod is None else f"{mod.path} {mod.version}".rstrip(),
        deps=go.dep_count, modules=[d.path for d in go.deps][:300],
        settings={k: v[:200] for k, v in go.settings.items() if k in _GO_SETTINGS},
        winapi=list(go.winapi), proc_call=go.proc_call, main_functions=go.main_functions[:50],
        build_id=go.build_id is not None, cgo=go.cgo, trimpath=go.trimpath,
        source_paths=go.source_path_count, goroot=go.goroot is not None,
        obfuscation=list(go.obfuscation), embedded=len(go.embedded), notes=go.notes[:5],
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
    """Triage paths in worker processes; a file that runs past `timeout` seconds
    (or kills its worker) becomes an error row instead of stalling the sweep.
    Rows whose hash is in `exclude_hashes` are kept but marked excluded.

    `worker` receives ``(path, use_yara, *extra)``, calls report_start(path)
    first, and returns the item's row (other sweeps, such as recall_sweep.py,
    plug their own reader in here). An item is always either waiting or held
    by exactly one worker, so none can be lost or counted twice."""
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    rows: list[dict] = []
    pending = deque(dict.fromkeys(paths))  # a repeated path is triaged once
    total = len(pending)
    jobs = worker_count(jobs, total)
    attempts: Counter = Counter()
    ctx = multiprocessing.get_context()
    started = time.perf_counter()
    workers: list[_Worker] = []
    live: set[_Worker] = set()  # every worker started and not yet stopped

    with out_jsonl.open("w", encoding="utf-8") as sink:
        def record(row: dict) -> None:
            if row.get("sha256") in exclude_hashes:
                row["excluded"] = "same bytes as a file of an excluded run"
            rows.append(row)
            sink.write(json.dumps(row) + "\n")
            if len(rows) % 50 == 0:
                sink.flush()  # a killed run keeps what it measured
            if len(rows) % 250 == 0 or len(rows) == total:
                rate = len(rows) / (time.perf_counter() - started)
                print(f"  {len(rows)}/{total} files, {rate:.1f}/s", file=sys.stderr)

        def fail(w: _Worker, reason: str, died: bool) -> None:
            item = w.item
            w.item = None
            if died and not w.began:
                # Lost before it started the item (it died idle, or while
                # starting up): that says nothing about the file.
                if attempts[item] < 2:
                    pending.appendleft(item)
                    return
                reason = "worker died before starting this file"
            # what the worker reported before it failed (e.g. the sample's hash)
            record(dict(w.progress, path=item, error=reason, failure=reason.split()[0]))

        def feed(w: _Worker) -> _Worker:
            """Give w the next item, replacing it first if it is gone, was
            killed, or has done its share (the parent counts, so no item goes
            to a worker that is about to exit)."""
            while pending and w.item is None:
                if w.killed or w.given >= _TASKS_PER_WORKER or not w.proc.is_alive():
                    w.stop()
                    w = _Worker(ctx, worker, use_yara, extra, timeout, live)
                item = pending.popleft()
                attempts[item] += 1
                if not w.give(item):
                    pending.appendleft(item)
                    attempts[item] -= 1
                    w.stop()
                    w = _Worker(ctx, worker, use_yara, extra, timeout, live)
            return w

        try:
            for _ in range(jobs):  # one at a time, so an interrupt stops those started
                workers.append(_Worker(ctx, worker, use_yara, extra, timeout, live))
                workers[-1] = feed(workers[-1])
            while len(rows) < total:
                busy = [w for w in workers if w.item is not None]
                if busy:
                    # A worker that dies closes its end of the pipe, which wakes this too.
                    multiprocessing.connection.wait([w.conn for w in busy], timeout=0.5)
                for i, w in enumerate(workers):
                    if w.item is not None:
                        for row in w.drain():
                            record(row)
                    if w.item is None:
                        pass
                    elif not w.proc.is_alive():
                        for row in w.drain():  # anything sent just before it exited
                            record(row)
                        if w.item is not None:
                            fail(w, "worker died on this file", died=True)
                    elif time.monotonic() - w.since > timeout:
                        w.kill()
                        for row in w.drain():  # finished as it was being killed
                            record(row)
                        if w.item is not None:
                            fail(w, f"timeout after {timeout:g}s", died=False)
                    workers[i] = feed(w)
        finally:
            for w in list(live):
                w.stop()
    return rows


def summarize(rows: list[dict]) -> dict:
    """Aggregate verdicts and per-signal contributions over unique files.

    Rows marked excluded (same bytes as a file of an excluded run) are left
    out, so re-summarising a held-out run gives the numbers it gave.
    """
    unique: dict[str, dict] = {}
    errors = []
    excluded = 0
    # Rows arrive in the order workers finish; sorting by path makes the file
    # kept for a hash, and every tie below, the same on every run.
    for row in sorted(rows, key=lambda r: r.get("path", "")):
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
        key=lambda s: (-s["points_in_flagged"], -s["files"], s["signal"]),
    )
    worst = sorted(files, key=lambda r: (-r["score"], r["path"]))[:25]
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
    if args.jobs < 1 or args.timeout <= 0 or args.max_mb <= 0:
        ap.error("--jobs, --timeout and --max-mb must be positive")
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
        print(f"sweeping {len(paths)} files with {worker_count(args.jobs, len(paths))} workers",
              file=sys.stderr)
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
    exit_past_stuck_workers()
    return 0


if __name__ == "__main__":
    sys.exit(main())
