"""Detection-rate (recall) sweep over a labelled malware corpus.

The benign sweep measures how often gokdogan flags clean software; this one
measures how often it flags malware. Run it only inside an isolated analysis
VM that holds the corpus. gokdogan never executes a sample, and this script
never writes one to disk: samples may sit in the corpus folder as
password-protected ZIPs (MalwareBazaar style, password "infected"), which are
read into memory and triaged there with triage_bytes().

    python scripts/recall_sweep.py --corpus /mnt/corpus --manifest /mnt/corpus/manifest.csv \
        --jobs 2 --out recall_results
    # outside the lab: add the benign sweep of the same engine for a threshold table
    python scripts/recall_sweep.py --report recall_results/results.jsonl \
        --benign sweep_results/holdout/results.jsonl --out recall_results

Every run splits the corpus by hash into a tuning part and a held-out part
(30% by default, stable across runs). The analysis tables come from the
tuning part only; quote the held-out rate. The results hold hashes, verdicts
and score reasons, never sample bytes, so they can leave the lab.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import shutil
import stat
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from benign_sweep import (  # noqa: E402
    HIGH_RISK,
    SUSPICIOUS,
    _code_hash,
    exit_past_stuck_workers,
    normalize,
    report_fields,
    report_progress,
    report_start,
    run,
    worker_count,
)

SYNCED_FOLDERS = {"onedrive", "dropbox", "google drive", "googledrive", "icloud drive", "iclouddrive"}
# Linux filesystem types that live on another machine: network shares, the
# host's folders in a VM (Hyper-V/WSL 9p, virtiofs, VirtualBox, VMware), xrdp
# drive redirection (~/thinclient_drives), and FUSE clients of remote or cloud
# storage.
REMOTE_FS_TYPES = {
    "cifs", "smb3", "smbfs", "nfs", "nfs4", "afs", "ceph", "glusterfs", "lustre", "davfs",
    "9p", "drvfs", "virtiofs", "vboxsf", "vmhgfs",
    "fuse.vmhgfs-fuse", "prl_fs", "fuse.prl_fsd", "fuse.xrdp-chansrv", "fuse.sshfs",
    "fuse.rclone", "fuse.gvfsd-fuse", "fuse.kio-fuse", "fuse.onedriver",
    "fuse.google-drive-ocamlfuse", "fuse.s3fs", "fuse.gcsfuse", "fuse.mount-s3", "fuse.goofys",
    "fuse.glusterfs", "fuse.ceph-fuse", "fuse.davfs2",
}
SKIP_NAMES = {"manifest.csv", "readme.txt", "readme.md"}
SCORE_BINS = ((0, 0), (1, 9), (10, 19), (20, 29), (30, 39), (40, 59), (60, 10**6))
THRESHOLDS = (10, 15, 20, 25, 30, 35, 40, 50, 60)
SIGNATURE_CREDIT = 15  # what a valid Authenticode signature takes off (verdict.py)
# Compression methods read with a bounded output: stored, deflate, and WinZip
# AES around either (pyzipper). bzip2 and LZMA cannot be bounded, so a member
# using them is skipped rather than risk a decompression bomb.
_ZIP_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
_AES_METHOD = 99
_YEAR = re.compile(r"\b(19[89]\d|20\d\d)\b")
# "archive.zip::<index>::<member name>": the archive path ends at the first
# ".zip::<digits>::", so "::" elsewhere in a folder or member name is kept.
_MEMBER = re.compile(r"^(.*?\.zip)::(\d+)::(.*)$", re.IGNORECASE | re.DOTALL)


def _member(item: str) -> tuple[str, int, str] | None:
    """(archive, index, name) for a ZIP member item, None for a plain file."""
    match = _MEMBER.match(item)
    return (match.group(1), int(match.group(2)), match.group(3)) if match else None


# --- reading samples -----------------------------------------------------

def _is_link(path: str) -> bool:
    """A symbolic link, or on Windows a junction or other reparse point."""
    if os.path.islink(path):
        return True
    try:
        attributes = os.lstat(path).st_file_attributes  # Windows only
    except (OSError, AttributeError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def collect(corpus: Path, max_bytes: int) -> tuple[list[str], Counter, list[str]]:
    """Sample identifiers, skip counts and unreadable archives.

    An identifier is a file path, or "archive.zip::<index>::<name>" for the
    index-th member of a ZIP (names can repeat inside one archive).
    """
    items: list[str] = []
    skipped: Counter = Counter()
    unreadable: list[str] = []
    root = os.path.abspath(corpus)
    checked = {os.stat(corpus).st_dev}  # filesystems the guard has seen (main() checks the root)

    def check_device(path: str, device: int) -> None:
        # Another filesystem inside the corpus is a mount (a host share
        # mounted into it, say): the guard checks it where it starts.
        if device not in checked:
            _refuse_synced(Path(path))
            checked.add(device)

    def unlistable(error: OSError) -> None:
        if os.path.abspath(error.filename or "") == root:
            raise SystemExit(f"cannot list the corpus folder {corpus}: {error.strerror}")
        skipped["unreadable folder"] += 1

    for dirpath, dirs, files in os.walk(corpus, onerror=unlistable):
        try:
            check_device(dirpath, os.stat(dirpath).st_dev)
        except OSError:
            pass
        followed = []
        for name in dirs:
            link = os.path.join(dirpath, name)
            if _is_link(link):  # a linked folder is checked where it leads, not followed
                _refuse_synced(Path(link))
                skipped["linked folder (not followed)"] += 1
            else:
                followed.append(name)
        dirs[:] = sorted(followed)
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            if name.lower() in SKIP_NAMES:
                continue
            if os.path.islink(path):
                _refuse_synced(Path(path))  # a link out of the corpus is checked where it leads
            try:
                st = os.stat(path)
                check_device(path, st.st_dev)  # a file mounted on its own
            except OSError:
                st = None
            if name.lower().endswith(".zip"):
                try:
                    with zipfile.ZipFile(path) as z:
                        for index, info in enumerate(z.infolist()):
                            if info.is_dir():
                                continue
                            if info.compress_type not in _ZIP_METHODS | {_AES_METHOD}:
                                skipped["unsupported ZIP compression (bzip2/LZMA)"] += 1
                            elif info.file_size > max_bytes:
                                skipped["larger than --max-mb"] += 1  # as declared; reads are bounded too
                            else:
                                items.append(f"{path}::{index}::{info.filename}")
                except (OSError, zipfile.BadZipFile, ValueError, NotImplementedError, EOFError):
                    skipped["unreadable zip"] += 1
                    unreadable.append(path)
                continue
            if st is None:
                skipped["unreadable file"] += 1
            elif st.st_size > max_bytes:
                skipped["larger than --max-mb"] += 1
            else:
                items.append(path)
    return items, skipped, unreadable


def aes_members(items: list[str]) -> int:
    """How many listed ZIP members are WinZip-AES encrypted (need pyzipper)."""
    count = 0
    for archive in {m[0] for m in map(_member, items) if m}:
        try:
            with zipfile.ZipFile(archive) as z:
                count += sum(info.compress_type == _AES_METHOD for info in z.infolist())
        except Exception:
            pass
    return count


def read_sample(item: str, password: bytes, max_bytes: int) -> bytes:
    """The sample's bytes, decrypted in memory and never more than max_bytes.

    The size a ZIP declares is the archive author's claim; reading at most
    max_bytes + 1 bytes bounds what a lying member can make us allocate.
    Nothing is written to disk.
    """
    member = _member(item)
    if member is None:
        with open(item, "rb") as fh:
            data = fh.read(max_bytes + 1)
    else:
        archive, index, name = member
        # The standard library decrypts ZipCrypto (MalwareBazaar's daily
        # batches) faster than pyzipper; WinZip AES (a single sample
        # downloaded from its API) needs pyzipper.
        with zipfile.ZipFile(archive) as z:
            info = z.infolist()[index]
            if info.filename != name:
                raise ValueError("archive changed since it was listed")
            aes = info.compress_type == _AES_METHOD
            if not aes:
                if info.compress_type not in _ZIP_METHODS:
                    raise ValueError("unsupported ZIP compression (bzip2/LZMA)")
                with z.open(info, pwd=password) as fh:
                    data = fh.read(max_bytes + 1)
        if aes:
            try:
                import pyzipper
            except ImportError:
                raise RuntimeError("AES-encrypted ZIP: pip install pyzipper") from None
            with pyzipper.AESZipFile(archive) as z:
                z.setpassword(password)
                info = z.infolist()[index]
                if info.filename != name:
                    raise ValueError("archive changed since it was listed")
                if info.compress_type not in _ZIP_METHODS:
                    raise ValueError("unsupported ZIP compression (bzip2/LZMA)")
                with z.open(info) as fh:
                    data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("larger than --max-mb")
    return data


def _triage_sample(args: tuple[str, bool, bytes, int]) -> dict:
    item, use_yara, password, max_bytes = args
    report_start(item)
    started = time.perf_counter()
    row: dict = {"path": item}
    try:
        from gokdogan.engine import NotAPEError, triage_bytes

        data = read_sample(item, password, max_bytes)
        sha = hashlib.sha256(data).hexdigest()
        row["sha256"] = sha  # kept on every failure below, so it can be split and counted
        report_progress(sha256=sha)  # ... and on a timeout or a dead worker's row too
        if data[:2] != b"MZ":
            row.update(error="not a PE (no MZ header)", not_pe=True)
        else:
            try:
                row.update(report_fields(triage_bytes(data, name=sha, use_yara=use_yara), use_yara))
            except NotAPEError as exc:
                row.update(error=f"MZ file the PE parser rejects ({exc})"[:300], unparsed=True)
            except Exception as exc:  # the engine failed on a PE: a miss for recall
                row.update(error=f"{type(exc).__name__}: {exc}"[:300], crashed=True)
        del data
    except Exception as exc:  # the sample could not be read
        row.update(error=f"read failed: {type(exc).__name__}: {exc}"[:300], unreadable=True)
    row["seconds"] = round(time.perf_counter() - started, 3)
    return row


# --- statistics ----------------------------------------------------------

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes in n trials (n=0: no information)."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def rate(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "ci95": [round(lo, 4), round(hi, 4)]}


def fmt(r: dict) -> str:
    if not r["n"]:
        return "–"
    return f"{r['rate']:.1%} ({r['k']}/{r['n']}; {r['ci95'][0]:.1%}–{r['ci95'][1]:.1%})"


def split_of(sha256: str, holdout_fraction: float) -> str:
    """Stable tuning/held-out assignment from the hash, whatever the run."""
    return "holdout" if int(sha256[:8], 16) / 0x100000000 < holdout_fraction else "tune"


# --- manifest and summary ------------------------------------------------

def load_manifest(path: str | None) -> dict[str, dict]:
    """sha256 -> row of a CSV with a "sha256" column (family, first_seen, ... optional)."""
    if not path:
        return {}
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        reader.fieldnames = [(f or "").strip().lower() for f in reader.fieldnames or []]
        if "sha256" not in reader.fieldnames:
            raise SystemExit(f"{path}: the manifest needs a 'sha256' column "
                             f"(found: {', '.join(reader.fieldnames) or 'none'})")
        for column in ("family", "first_seen"):
            if column not in reader.fieldnames:
                print(f"warning: {path} has no '{column}' column; those tables will say 'unknown'",
                      file=sys.stderr)
        manifest = {}
        for r in reader:
            sha = (r.get("sha256") or "").strip().lower()
            if sha:
                manifest[sha] = {k: (v or "").strip() for k, v in r.items() if k}
        return manifest


def _year(first_seen: str) -> str:
    match = _YEAR.search(first_seen or "")
    return match.group(1) if match else "unknown"


def samples(rows: list[dict], manifest: dict[str, dict], holdout_fraction: float) -> dict:
    """Unique triaged samples joined with the manifest, failures, and bookkeeping counts.

    A PE the engine could not score (parser rejected it, it crashed or timed
    out) is a sample the triage failed to flag: those rows are returned as
    failures and count as misses in the intent-to-triage rate.
    """
    unique: dict[str, dict] = {}
    failures: dict[str, dict] = {}   # sha256 (or path) -> failed PE row
    counts: Counter = Counter()
    seen: set[str] = set()
    for row in rows:
        sha = row.get("sha256")
        if sha:
            seen.add(sha)
        if row.get("not_pe"):
            counts["not a PE (no MZ header)"] += 1
        elif row.get("unreadable"):
            counts["could not be read"] += 1
        elif manifest and sha and sha not in manifest:
            counts["not in manifest"] += 1
        elif "error" in row:
            kind = ("PE parser rejected it" if row.get("unparsed") else
                    "engine error" if row.get("crashed") else "timeout or worker died")
            counts[kind] += 1
            key = sha or row["path"]
            if key not in unique:
                failures[key] = dict(row, split=split_of(sha, holdout_fraction) if sha else None)
        elif sha in unique:
            counts["duplicate"] += 1
        else:
            entry = manifest.get(sha, {})
            failures.pop(sha, None)
            unique[sha] = dict(row, family=entry.get("family") or "unknown",
                               year=_year(entry.get("first_seen", "")),
                               split=split_of(sha, holdout_fraction))
    if manifest:
        counts["in manifest, not in the corpus"] = len(set(manifest) - seen)
    return {"samples": list(unique.values()), "failures": list(failures.values()),
            "counts": dict(sorted(counts.items()))}


def _score_if_signature_valid(row: dict) -> int:
    """The score a signed sample would get with a valid signature (verdict.py):
    15 points off, but never below SUSPICIOUS with a severity-3 capability."""
    if not row.get("signed"):
        return row["score"]
    credited = max(0, row["score"] - SIGNATURE_CREDIT)
    severe = any(p == 18 and reason.startswith("capability: ") for p, reason in row["breakdown"])
    if severe and row["score"] >= SUSPICIOUS:
        return max(credited, SUSPICIOUS)
    return credited


def _detection(group: list[dict], failed: int = 0) -> dict:
    n = len(group)
    out = {
        "suspicious_or_worse": rate(sum(r["score"] >= SUSPICIOUS for r in group), n),
        "high_risk": rate(sum(r["score"] >= HIGH_RISK for r in group), n),
    }
    if failed:
        # Counting every PE the engine could not score as a miss.
        out["intent_to_triage"] = rate(out["suspicious_or_worse"]["k"], n + failed)
    signed = [r for r in group if r.get("signed")]
    if signed:
        # triage_bytes cannot verify Authenticode (it needs a file), so every
        # signature scored as "unverified". Had each one been valid:
        out["suspicious_or_worse_if_signatures_valid"] = rate(
            sum(_score_if_signature_valid(r) >= SUSPICIOUS for r in group), n)
        out["signed"] = len(signed)
    return out


def _clip(text: str, n: int = 120) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def summarize(rows: list[dict], manifest: dict[str, dict], holdout_fraction: float) -> dict:
    joined = samples(rows, manifest, holdout_fraction)
    all_s = joined["samples"]
    failures = joined["failures"]
    parts = {"holdout": [s for s in all_s if s["split"] == "holdout"],
             "tune": [s for s in all_s if s["split"] == "tune"], "all": all_s}
    failed = {"holdout": sum(f["split"] == "holdout" for f in failures),
              "tune": sum(f["split"] == "tune" for f in failures), "all": len(failures)}

    # Everything below the headline is read to decide what to change, so it
    # comes from the tuning part only: the held-out part stays unread.
    tune = parts["tune"]
    strata = {
        "native": [s for s in tune if not s["dotnet"]],
        ".NET": [s for s in tune if s["dotnet"]],
        "packed": [s for s in tune if s["packed"]],
        "not packed": [s for s in tune if not s["packed"]],
        "DLL": [s for s in tune if s.get("is_dll")],
        "not DLL": [s for s in tune if not s.get("is_dll")],
    }
    families = Counter(s["family"] for s in tune)
    years = Counter(s["year"] for s in tune)
    missed = [s for s in tune if s["score"] < SUSPICIOUS]
    fired_missed: Counter = Counter()
    fired_detected: Counter = Counter()
    for s in tune:
        target = fired_missed if s["score"] < SUSPICIOUS else fired_detected
        for key in {normalize(reason) for _, reason in s["breakdown"]}:
            target[key] += 1
    signals = sorted(
        ({"signal": k, "in_missed": fired_missed[k], "in_detected": fired_detected[k]}
         for k in set(fired_missed) | set(fired_detected)),
        key=lambda s: (-s["in_missed"], -s["in_detected"], s["signal"]))  # ties: by name, every run

    # A few prolific families can dominate a corpus: the mean of per-family
    # rates weighs each labelled family once (held-out part, 3+ samples).
    by_family: dict[str, list[dict]] = defaultdict(list)
    for s in parts["holdout"]:
        if s["family"] != "unknown":
            by_family[s["family"]].append(s)
    per_family = [sum(s["score"] >= SUSPICIOUS for s in g) / len(g)
                  for g in by_family.values() if len(g) >= 3]

    return {
        "counts": joined["counts"],
        "samples": len(all_s),
        "holdout_fraction": holdout_fraction,
        "detection": {name: _detection(group, failed[name]) for name, group in parts.items()},
        "family_balanced_holdout": {
            "rate": round(sum(per_family) / len(per_family), 4) if per_family else None,
            "families": len(per_family),
            "unlabelled_samples": sum(s["family"] == "unknown" for s in parts["holdout"])},
        "tuning_strata": {name: _detection(group) for name, group in strata.items() if group},
        "tuning_families": [{"family": f, **_detection([s for s in tune if s["family"] == f])}
                            for f, _ in sorted(families.items(), key=lambda kv: (-kv[1], kv[0]))[:25]],
        "tuning_years": [{"year": y, **_detection([s for s in tune if s["year"] == y])}
                         for y in sorted(years)],
        "tuning_score_histogram": [{"bin": f"{lo}-{hi}" if hi < 10**6 else f"{lo}+",
                                    "samples": sum(lo <= s["score"] <= hi for s in tune)}
                                   for lo, hi in SCORE_BINS],
        "tuning_signals": signals[:40],
        "tuning_missed": len(missed),
        "tuning_detected": len(tune) - len(missed),
        "tuning_worst_misses": [
            {"sha256": s["sha256"], "family": s["family"], "score": s["score"],
             "dotnet": s["dotnet"], "packed": s["packed"],
             "top": sorted(({"points": p, "reason": _clip(t)} for p, t in s["breakdown"]),
                           key=lambda e: -e["points"])[:5]}
            for s in sorted(missed, key=lambda s: (s["score"], s["sha256"]))[:30]],
        "yara_ran": {"yes": sum(bool(s.get("yara")) for s in all_s),
                     "no": sum(not s.get("yara") for s in all_s)},
    }


def threshold_table(malware: list[dict], benign_rows: list[dict]) -> list[dict]:
    """Detection vs false-positive rate at each score threshold."""
    benign: dict[str, int] = {}
    for r in benign_rows:
        if "error" not in r and not r.get("excluded"):
            benign.setdefault(r["sha256"], r["score"])
    held = [s for s in malware if s["split"] == "holdout"]
    table = []
    for t in THRESHOLDS:
        table.append({
            "threshold": t,
            "malware_all": rate(sum(s["score"] >= t for s in malware), len(malware)),
            "malware_holdout": rate(sum(s["score"] >= t for s in held), len(held)),
            "benign": rate(sum(v >= t for v in benign.values()), len(benign)),
        })
    return table


def pairing_notes(engine: dict, other: dict, malware: list[dict], benign_rows: list[dict]) -> list[str]:
    """Why a benign sweep may not describe the same rules as this recall run."""
    notes = []
    if other.get("code_sha256") != engine.get("code_sha256"):
        notes.append("The benign sweep was scored by different engine code "
                      f"({str(other.get('code_sha256'))[:12]} vs {str(engine.get('code_sha256'))[:12]}).")
    benign_yara = {bool(r.get("yara")) for r in benign_rows if "error" not in r and "yara" in r}
    malware_yara = {bool(s.get("yara")) for s in malware}
    if not benign_yara:
        notes.append("The benign sweep does not record whether YARA ran.")
    elif benign_yara != malware_yara:
        notes.append(f"YARA ran in {sorted(benign_yara)} of the benign rows but "
                     f"{sorted(malware_yara)} of the malware rows.")
    return notes


def to_markdown(summary: dict) -> str:
    d = summary["detection"]
    lines = [
        "# Recall sweep",
        "",
        f"- Samples scored: **{summary['samples']}** "
        f"({', '.join(f'{k}: {v}' for k, v in sorted(summary['counts'].items())) or 'nothing skipped'})",
        f"- Held-out part: {summary['holdout_fraction']:.0%} of samples, by hash. Quote the "
        "held-out row; every table below it comes from the tuning part only.",
    ]
    if summary.get("not_triaged"):
        lines.append("- Not triaged (left out while listing the corpus): "
                     + ", ".join(f"{k} {n}" for k, n in summary["not_triaged"].items()))
    elif summary.get("not_triaged") is None:
        lines.append("- Not triaged: not recorded (no engine.json from the run, or one that predates it)")
    if summary["counts"].get("in manifest, not in the corpus"):
        lines.append("- A manifest hash with no row is missing from the corpus, was left out "
                     "before triage, or belongs to a sample lost before its hash was read.")
    lines += [
        "",
        "| part | SUSPICIOUS or worse | HIGH_RISK | counting unscored PEs as misses |",
        "|---|---|---|---|",
    ]
    for part in ("holdout", "tune", "all"):
        itt = d[part].get("intent_to_triage")
        lines.append(f"| {part} | {fmt(d[part]['suspicious_or_worse'])} | {fmt(d[part]['high_risk'])} "
                     f"| {fmt(itt) if itt else 'no failures'} |")
    lines.append("")
    fb = summary["family_balanced_holdout"]
    if fb["rate"] is not None:
        lines += [f"- Family-balanced, held-out: {fb['rate']:.1%} (mean over {fb['families']} "
                  f"labelled families with 3+ held-out samples; {fb['unlabelled_samples']} unlabelled "
                  "held-out samples left out)"]
    for part in ("holdout", "all"):
        if "suspicious_or_worse_if_signatures_valid" in d[part]:
            lines += [f"- {part}: {d[part]['signed']} samples carry an Authenticode signature, which "
                      "triage_bytes cannot verify (scored as unverified). Had every one been valid, "
                      f"SUSPICIOUS or worse would be {fmt(d[part]['suspicious_or_worse_if_signatures_valid'])}; "
                      "a tampered or revoked one would score higher instead."]
    if summary["yara_ran"]["no"]:
        lines += [f"- YARA did not run on {summary['yara_ran']['no']} of {summary['samples']} samples "
                  "(disabled, or yara-python missing): those scores lack the rule weights."]
    lines += ["", "## Tuning part: by kind", "", "| stratum | SUSPICIOUS or worse | HIGH_RISK |",
              "|---|---|---|"]
    for name, det in summary["tuning_strata"].items():
        lines.append(f"| {name} | {fmt(det['suspicious_or_worse'])} | {fmt(det['high_risk'])} |")
    lines += ["", "## Tuning part: by family (largest 25)", "",
              "| family | SUSPICIOUS or worse | HIGH_RISK |", "|---|---|---|"]
    for f in summary["tuning_families"]:
        lines.append(f"| {f['family']} | {fmt(f['suspicious_or_worse'])} | {fmt(f['high_risk'])} |")
    if len(summary["tuning_years"]) > 1:
        lines += ["", "## Tuning part: by first-seen year", "", "| year | SUSPICIOUS or worse |",
                  "|---|---|"]
        for y in summary["tuning_years"]:
            lines.append(f"| {y['year']} | {fmt(y['suspicious_or_worse'])} |")
    lines += ["", "## Tuning part: score distribution", "", "| score | samples |", "|---|---:|"]
    lines += [f"| {b['bin']} | {b['samples']} |" for b in summary["tuning_score_histogram"]]
    if summary.get("thresholds"):
        lines += ["", "## Threshold table (with a benign sweep)", "",
                  "| score ≥ | malware, held-out | malware, all | benign flagged |", "|---:|---|---|---|"]
        for t in summary["thresholds"]:
            lines.append(f"| {t['threshold']} | {fmt(t['malware_holdout'])} | {fmt(t['malware_all'])} | "
                         f"{fmt(t['benign'])} |")
        for note in summary.get("pairing_notes", []):
            lines += ["", f"> {note} Rerun one side so both columns describe the same rules."]
    lines += ["", f"## Tuning part: signals in missed ({summary['tuning_missed']}) vs detected "
              f"({summary['tuning_detected']}) samples", "",
              "| signal | in missed | in detected |", "|---|---:|---:|"]
    lines += [f"| {s['signal']} | {s['in_missed']} | {s['in_detected']} |" for s in summary["tuning_signals"]]
    lines += ["", "## Tuning part: lowest-scoring misses", ""]
    for m in summary["tuning_worst_misses"]:
        top = "; ".join(f"{e['points']:+d} {e['reason'][:50]}" for e in m["top"]) or "no signal"
        kind = ".NET" if m["dotnet"] else "native"
        lines.append(f"- **{m['score']}** {m['family']} ({kind}{', packed' if m['packed'] else ''}) "
                     f"`{m['sha256'][:16]}` — {top}")
    return "\n".join(lines) + "\n"


# --- safety net ----------------------------------------------------------

def _onedrive_roots() -> list[str]:
    """Folders OneDrive syncs: its environment variables and, on Windows, every
    account folder and SharePoint/Teams library it has mounted."""
    roots = [os.environ.get(v) for v in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")]
    if sys.platform == "win32":
        try:
            import winreg

            base = r"Software\Microsoft\OneDrive\Accounts"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as accounts:
                for i in range(winreg.QueryInfoKey(accounts)[0]):
                    name = winreg.EnumKey(accounts, i)
                    with winreg.OpenKey(accounts, name) as account:
                        try:
                            roots.append(winreg.QueryValueEx(account, "UserFolder")[0])
                        except OSError:
                            pass
                    try:
                        with winreg.OpenKey(accounts, rf"{name}\ScopeIdToMountPointPathCache") as mounts:
                            for j in range(winreg.QueryInfoKey(mounts)[1]):
                                roots.append(winreg.EnumValue(mounts, j)[1])
                    except OSError:
                        pass
        except OSError:
            pass
    return [r for r in roots if isinstance(r, str) and r]


def _mount_type(path: Path, mounts: str | None = None) -> str | None:
    """Filesystem type of the mount holding `path` (Linux), or None."""
    if mounts is None:
        try:
            mounts = Path("/proc/self/mounts").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    target, best, fstype = path.as_posix(), -1, None
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        # spaces and other separators in mount points are octal escapes (\040)
        point = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[1])
        prefix = point.rstrip("/") + "/"
        # later lines win a tie: they are mounted over the earlier ones
        if (target == point or target.startswith(prefix)) and len(point) >= best:
            best, fstype = len(point), fields[2]
    return fstype


def _device_type(device: int, mountinfo: str | None = None) -> str | None:
    """Filesystem type of the mount whose device number is `device` (Linux
    mountinfo), or None. Unlike a path match it holds for folder names that
    are not UTF-8 and for mounts hidden under later ones."""
    if mountinfo is None:
        try:
            mountinfo = Path("/proc/self/mountinfo").read_bytes().decode("utf-8", "replace")
        except OSError:
            return None
    wanted = f"{os.major(device)}:{os.minor(device)}"
    for line in mountinfo.splitlines():
        fields, _, after = line.partition(" - ")
        fields, after = fields.split(), after.split()
        if len(fields) >= 3 and fields[2] == wanted and after:
            return after[0]
    return None


def _is_remote(path: Path) -> bool:
    """A network share, or a VM shared folder mapped as a drive or mounted."""
    anchor = path.anchor
    if anchor.startswith(("\\\\", "//")):
        return True
    if sys.platform == "win32" and anchor:
        try:
            import ctypes

            return ctypes.windll.kernel32.GetDriveTypeW(anchor) == 4  # DRIVE_REMOTE
        except Exception:
            return False
    try:
        fstype = _device_type(os.stat(path).st_dev)
    except (OSError, AttributeError):
        fstype = None
    # btrfs subvolumes and the like report a device the table does not list
    return (fstype or _mount_type(path)) in REMOTE_FS_TYPES


def _is_synced(path: Path) -> bool:
    """True under a cloud-synced folder or on a remote drive (a safety net,
    not a substitute for the lab rules in BENCHMARK.md)."""
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):  # a symlink loop (3.10-3.12 raise RuntimeError)
        resolved = Path(os.path.abspath(path))
    if _is_remote(resolved):
        return True
    for root in _onedrive_roots():
        try:
            resolved.relative_to(Path(root).resolve())
            return True
        except (ValueError, OSError):
            pass
    parts = [p.lower() for p in resolved.parts]
    if len(parts) > 1 and parts[1] in ("my drive", "shared drives"):  # Google Drive's G: drive
        return True
    for part in parts:
        if (part in SYNCED_FOLDERS or part.startswith(("onedrive - ", "onedrive-", "dropbox (",
                                                       "googledrive-"))
                or part in ("mobile documents", "cloudstorage", "thinclient_drives")):
            return True
    return False


def _refuse_synced(path: Path) -> None:
    if _is_synced(path):
        raise SystemExit(f"refusing to read a malware corpus from a synced or remote folder ({path}): "
                         "keep samples on the isolated analysis VM's own disk")


# --- entry point ---------------------------------------------------------

def _load_rows(path: str | Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", help="folder of samples (files or password-protected ZIPs)")
    ap.add_argument("--manifest", help="CSV with a sha256 column (+ family, first_seen, ...)")
    ap.add_argument("--password", default="infected", help="ZIP password (default: infected)")
    ap.add_argument("--out", default="recall_results", help="output folder")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--no-yara", action="store_true", help="skip the YARA stage")
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds per sample")
    ap.add_argument("--max-mb", type=float, default=64.0, help="skip samples larger than this")
    ap.add_argument("--holdout-fraction", type=float, default=None,
                    help="share of samples (by hash) kept out of tuning (default 0.3; "
                         "--report reuses the run's value)")
    ap.add_argument("--benign", metavar="JSONL", help="benign sweep results for the threshold table")
    ap.add_argument("--engine", metavar="DIR", help="import gokdogan from this directory")
    ap.add_argument("--report", metavar="JSONL", help="only re-summarise an earlier results.jsonl")
    args = ap.parse_args(argv)
    if args.holdout_fraction is not None and not 0 < args.holdout_fraction < 1:
        ap.error("--holdout-fraction must be between 0 and 1 (e.g. 0.3)")
    if args.jobs < 1 or args.timeout <= 0 or args.max_mb <= 0:
        ap.error("--jobs, --timeout and --max-mb must be positive")
    if args.benign and not Path(args.benign).is_file():
        ap.error(f"--benign {args.benign}: no such file")
    if args.engine:
        sys.path.insert(0, os.path.abspath(args.engine))

    out = Path(args.out)
    if args.report:
        rows = _load_rows(args.report)
        sidecar = Path(args.report).with_name("engine.json")
        engine = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar.exists() else {}
        recorded = engine.get("args") or {}
        fraction = recorded.get("holdout_fraction") or 0.3
        if args.holdout_fraction is not None and args.holdout_fraction != fraction:
            print(f"warning: the run split at {fraction}; re-splitting at {args.holdout_fraction} "
                  "moves samples between the tuning and held-out parts", file=sys.stderr)
            fraction = args.holdout_fraction
        manifest_path = args.manifest
        if not manifest_path:
            beside = Path(args.report).with_name("manifest.csv")
            if beside.exists():
                manifest_path = str(beside)
            elif recorded.get("manifest"):
                if not Path(recorded["manifest"]).exists():
                    ap.error(f"the run used the manifest {recorded['manifest']}, which is not here: "
                             "pass --manifest")
                manifest_path = recorded["manifest"]
        manifest = load_manifest(manifest_path)
        out.mkdir(parents=True, exist_ok=True)
    else:
        if not args.corpus or not Path(args.corpus).is_dir():
            ap.error("--corpus must be an existing folder (or use --report)")
        corpus = Path(args.corpus)
        _refuse_synced(corpus)
        fraction = args.holdout_fraction or 0.3
        manifest = load_manifest(args.manifest)  # fail before hours of triage, not after
        import gokdogan

        try:
            from gokdogan.engine import triage_bytes  # noqa: F401  (0.6.0 and later)
        except ModuleNotFoundError as exc:  # a dependency, e.g. dnfile in an old lab snapshot
            ap.error(f"cannot load the engine: {exc}; run `pip install -e .` from the repository")
        except ImportError:
            ap.error(f"gokdogan {gokdogan.__version__} has no triage_bytes(); use 0.6.0 or later")
        engine = {"version": gokdogan.__version__, "path": os.path.dirname(gokdogan.__file__),
                  "code_sha256": _code_hash(Path(gokdogan.__file__).parent),
                  "args": dict(vars(args), holdout_fraction=fraction)}
        if args.engine and not os.path.abspath(engine["path"]).lower().startswith(
                os.path.abspath(args.engine).lower()):
            ap.error(f"--engine {args.engine} requested but gokdogan came from {engine['path']}")
        max_bytes = int(args.max_mb * 1024 * 1024)
        items, skipped, unreadable = collect(corpus, max_bytes)
        if aes_members(items):
            try:
                import pyzipper  # noqa: F401
            except ImportError:
                ap.error("the corpus holds AES-encrypted ZIPs: pip install pyzipper")
        # what was left out before triage leaves the lab too, and --report shows it
        engine["not_triaged"] = dict(sorted(skipped.items()))
        engine["unreadable_zips"] = [os.path.relpath(p, corpus) for p in unreadable[:100]]
        out.mkdir(parents=True, exist_ok=True)
        (out / "engine.json").write_text(json.dumps(engine, indent=1), encoding="utf-8")
        if args.manifest:  # hashes only; lets --report run anywhere later
            shutil.copyfile(args.manifest, out / "manifest.csv")
        print(f"engine: gokdogan {engine['version']} (code {engine['code_sha256'][:12]}); "
              "samples are read into memory and never executed", file=sys.stderr)
        if skipped:
            print("skipped: " + ", ".join(f"{k} {v}" for k, v in skipped.items()), file=sys.stderr)
        for path in unreadable[:10]:
            print(f"  unreadable zip: {path}", file=sys.stderr)
        print(f"triaging {len(items)} samples with {worker_count(args.jobs, len(items))} workers",
              file=sys.stderr)
        rows = run(items, args.jobs, not args.no_yara, out / "results.jsonl", args.timeout,
                   worker=_triage_sample, extra=(args.password.encode(), max_bytes))

    summary = summarize(rows, manifest, fraction)
    summary["not_triaged"] = engine.get("not_triaged")  # None: an older run did not record it
    summary["engine"] = engine
    if not args.report and not args.no_yara and summary["yara_ran"]["no"]:
        print(f"warning: YARA did not run on {summary['yara_ran']['no']} samples "
              "(is yara-python installed?)", file=sys.stderr)
    if args.benign:
        benign_rows = _load_rows(args.benign)
        joined = samples(rows, manifest, fraction)["samples"]
        summary["thresholds"] = threshold_table(joined, benign_rows)
        benign_engine = Path(args.benign).with_name("engine.json")
        other = json.loads(benign_engine.read_text(encoding="utf-8")) if benign_engine.exists() else {}
        summary["pairing_notes"] = pairing_notes(engine, other, joined, benign_rows)
    (out / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    (out / "summary.md").write_text(to_markdown(summary), encoding="utf-8")
    held = summary["detection"]["holdout"]["suspicious_or_worse"]
    print(f"{summary['samples']} samples; held-out SUSPICIOUS or worse: {fmt(held)} "
          f"({out / 'summary.md'})", file=sys.stderr)
    exit_past_stuck_workers()
    return 0


if __name__ == "__main__":
    sys.exit(main())
