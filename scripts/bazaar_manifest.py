"""Build a recall manifest from MalwareBazaar's CSV export (metadata only).

MalwareBazaar publishes one ZIP of samples per day (the "daily batches",
password "infected") and a CSV of every sample's hash, first-seen time, file
type and family label. This script reads that CSV and writes the manifest
recall_sweep.py expects, for the days whose batches make up the corpus:
Windows EXE and DLL files only, at most --per-family samples of each family
and at most --unlabelled samples without a family. It reads no sample and
downloads nothing.

    python scripts/bazaar_manifest.py --csv full.csv.zip \
        --days 2026-09-25 2026-06-10 2026-01-15 2025-09-20 --out ~/corpus/manifest.csv
    # a few PE files in the batches are over the sweep's default 64 MB
    python scripts/recall_sweep.py --corpus ~/corpus --manifest ~/corpus/manifest.csv \
        --max-mb 128 --jobs 2 --out recall_results

Which samples a cap keeps is a fixed function of their hashes, so the same
export always gives the same manifest, but not their order: recall_sweep
holds out the samples with the lowest hashes, and a cap that kept those
would put every capped family in the held-out part.

Family labels come from MalwareBazaar's "signature" field and are noisy
(spellings are merged: "Vidar" and "vidar" are one family); say so when you
report a family-balanced rate.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import datetime
import hashlib
import io
import itertools
import re
import sys
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

PE_TYPES = ("exe", "dll")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Column names differ between export versions; the first one present wins.
_COLUMNS = {
    "sha256": ("sha256_hash", "sha256"),
    "first_seen": ("first_seen_utc", "first_seen"),
    "file_type": ("file_type_guess", "file_type"),
    "family": ("signature",),
}
_NO_FAMILY = {"", "n/a", "none", "null", "unknown"}
_UPDATED = re.compile(r"last updated:\s*(\d{4}-\d{2}-\d{2})[ t](\d{2}:\d{2}:\d{2})", re.IGNORECASE)


@contextlib.contextmanager
def _lines(path: Path) -> Iterator[Iterable[str]]:
    """The CSV's lines, read as they are needed (the full export is large); a
    .zip export holds the CSV as its only .csv member."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist() if n.lower().endswith(".csv")]
            if len(names) != 1:
                raise SystemExit(f"{path}: expected one .csv inside, found {names or 'none'}")
            with z.open(names[0]) as raw:
                yield io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace", newline="")
    else:
        with path.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
            yield fh


class Export:
    """The rows of an export, and what its banner says about it.

    The export starts with '#' comment lines; the last of them that names
    columns is the header (or the first plain line, if none does). Fields
    are quoted and separated by ", "."""

    def __init__(self, lines: Iterable[str]):
        self._lines = iter(lines)
        self.updated: datetime.datetime | None = None   # the banner's "Last updated", UTC
        self.malformed = 0
        header, self._first = None, None
        for line in self._lines:
            if not line.strip():
                continue
            if not line.startswith("#"):
                self._first = line
                break
            if "sha256" in line.lower():
                header = line.lstrip("#").strip()
            elif (m := _UPDATED.search(line)):
                self.updated = datetime.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}")
        if header is None:
            if self._first is None:
                raise SystemExit("the export is empty")
            header, self._first = self._first, None
        names = [n.strip().strip('"').lower()
                 for n in next(csv.reader([header], skipinitialspace=True))]
        self._index = {}
        for key, choices in _COLUMNS.items():
            found = next((names.index(c) for c in choices if c in names), None)
            if found is None:
                raise SystemExit(f"the export has no {' or '.join(choices)} column "
                                 f"(found: {', '.join(names)})")
            self._index[key] = found

    def rows(self) -> Iterator[dict]:
        body = itertools.chain([self._first] if self._first is not None else [], self._lines)
        width = max(self._index.values())
        for fields in csv.reader(body, skipinitialspace=True):
            if len(fields) > width:
                yield {key: fields[i].strip() for key, i in self._index.items()}
            elif fields and not fields[0].lstrip().startswith("#"):
                self.malformed += 1


def read_export(lines: Iterable[str]) -> Iterator[dict]:
    """Rows of the export as dicts with sha256, first_seen, file_type, family."""
    return Export(lines).rows()


def _family_key(family: str) -> str:
    """One key per family however it is spelt ("" for none)."""
    if family.strip().lower() in _NO_FAMILY:
        return ""
    return re.sub(r"[\s_.-]+", "", family).casefold()


def _cap_order(sha: str) -> bytes:
    """A fixed order that is independent of the hash's own value (see the docstring)."""
    return hashlib.sha256(b"gokdogan manifest cap:" + sha.encode()).digest()


def select(rows: Iterable[dict], days: set[str], types: tuple[str, ...], per_family: int,
           unlabelled: int) -> tuple[list[dict], Counter]:
    """The manifest rows, and a count of every row read that was left out, by reason."""
    left_out: Counter = Counter()
    seen: set[str] = set()
    by_family: dict[str, dict[str, dict]] = defaultdict(dict)
    spellings: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        sha = row["sha256"].lower()
        if not _SHA256.match(sha):
            left_out["no valid sha256"] += 1
        elif sha in seen:
            left_out["sha256 listed twice (first row kept)"] += 1
        elif row["first_seen"][:10] not in days:
            left_out["first seen on another day"] += 1
        elif row["file_type"].lower() not in types:
            left_out["not " + "/".join(types).upper()] += 1
        else:
            key = _family_key(row["family"])
            if key:
                spellings[key][row["family"].strip()] += 1
            by_family[key][sha] = dict(row, sha256=sha)
        seen.add(sha)
    chosen = []
    for key, samples in sorted(by_family.items()):
        # the most common spelling names the family (ties: the first in sort order)
        name = min(spellings[key].items(), key=lambda kv: (-kv[1], kv[0]))[0] if key else ""
        cap = per_family if key else unlabelled
        keep = sorted(samples, key=_cap_order)[:cap]
        if len(samples) > len(keep):
            left_out["over the cap of its family" if key else "over the cap for unlabelled"] += \
                len(samples) - len(keep)
        chosen += [dict(samples[sha], family=name) for sha in keep]
    return chosen, left_out


def write_manifest(rows: list[dict], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["sha256", "family", "first_seen", "file_type", "source"])
        for r in sorted(rows, key=lambda r: r["sha256"]):
            writer.writerow([r["sha256"], r["family"], r["first_seen"], r["file_type"].lower(),
                             "MalwareBazaar"])


def _day(text: str) -> str:
    try:
        return datetime.date.fromisoformat(text).isoformat()
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a YYYY-MM-DD date: {text}") from None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv", required=True, type=Path,
                    help="MalwareBazaar CSV export (a .csv, or the .zip it comes in)")
    ap.add_argument("--days", nargs="+", required=True, type=_day, metavar="YYYY-MM-DD",
                    help="the days of the daily batches in the corpus (first seen, UTC)")
    ap.add_argument("--out", required=True, type=Path, help="manifest to write")
    ap.add_argument("--types", nargs="+", default=list(PE_TYPES),
                    help="file types to keep (default: exe dll; MalwareBazaar also types "
                         "some PE files xll, sys or com)")
    ap.add_argument("--per-family", type=int, default=20, help="samples kept per family (default 20)")
    ap.add_argument("--unlabelled", type=int, default=100,
                    help="samples kept without a family label (default 100)")
    args = ap.parse_args(argv)
    if args.per_family < 1 or args.unlabelled < 0:
        ap.error("--per-family must be at least 1 and --unlabelled at least 0")
    if not args.csv.is_file():
        ap.error(f"--csv {args.csv}: no such file")
    if args.out.is_dir():
        ap.error(f"--out {args.out} is a folder; give the manifest's file name")

    with _lines(args.csv) as lines:
        export = Export(lines)
        chosen, left_out = select(export.rows(), set(args.days),
                                  tuple(t.lower() for t in args.types), args.per_family, args.unlabelled)
    if export.malformed:
        left_out["malformed row"] += export.malformed
    write_manifest(chosen, args.out)
    per_day = Counter(r["first_seen"][:10] for r in chosen)
    families = {r["family"] for r in chosen if r["family"]}
    total = len(chosen) + sum(left_out.values())
    print(f"{total} rows read; manifest {args.out}: {len(chosen)} samples, "
          f"{len(families)} families, {sum(not r['family'] for r in chosen)} unlabelled", file=sys.stderr)
    for day in sorted(set(args.days)):
        print(f"  {day}: {per_day.get(day, 0)} samples", file=sys.stderr)
    print("left out: " + (", ".join(f"{k} {n}" for k, n in sorted(left_out.items())) or "nothing"),
          file=sys.stderr)
    status = 0
    latest = max(args.days)
    if export.updated is not None and export.updated < datetime.datetime.fromisoformat(latest) \
            + datetime.timedelta(days=1):
        print(f"warning: the export was made {export.updated} UTC, before {latest} was over: "
              "that day's list is incomplete; download the export again", file=sys.stderr)
        status = 1
    empty = sorted(d for d in set(args.days) if not per_day.get(d))
    if empty:
        print(f"error: nothing selected for {', '.join(empty)}: check the days against the "
              "export (first seen, UTC)", file=sys.stderr)
        status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
