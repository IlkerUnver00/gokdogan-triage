#!/usr/bin/env python3
"""Build the rate card (gokdogan/ratecard.py) from sweep rows.

    python scripts/rate_card.py \\
        --malware sweep_results/recall_r1c --manifest benchmarks/malwarebazaar-r1/manifest.csv \\
        --malware-label "MalwareBazaar daily batches 2025-09-20, 2026-01-15, 2026-06-10, 2026-09-25" \\
        --benign sweep_results/tune_M sweep_results/holdout_M \\
        --benign-label "installed software on one Windows 11 machine" \\
        --built 2026-11-02 --out gokdogan/data/ratecard.json

Every run must be finished (summary.json) and come from the same engine
code (engine.json), and every row must carry signal IDs: rows from older
engines or sweep scripts are refused rather than mapped from their reason
text. Malware counts are manifest samples that were scored; benign files
are counted once per distinct content.

A signed file counts in both signed strata where the rules allow: a
signed malware sample as the lab scored it (signature unverified) and as
scored had its signature been valid (``signals_if_valid``); a validly
signed benign file as scored and as scored had its signature not been
checked (``signals_if_unverified``). A valid signature over a padded
certificate table earns no credit, so such a file counts as unvouched only.
Lines that state what the signature check found get no cells: their rates
would follow from how the twins are made.

The card names no file, path or product: it records how many families or
product folders a rate rests on and the largest one's share of it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from benign_sweep import HIGH_RISK, SUSPICIOUS  # noqa: E402
from recall_sweep import load_manifest, pairing_notes, rate, samples  # noqa: E402

from gokdogan.ratecard import SCHEMA, SIDES, STRATA, is_verification_signal, stratum  # noqa: E402

MIN_N = 30
PADDED = "signature.valid-padded"


def _rows(run: Path) -> list[dict]:
    if not (run / "summary.json").exists():
        raise SystemExit(f"{run}: no summary.json, so the sweep has not finished; build from finished runs only")
    rows = []
    for number, line in enumerate((run / "results.jsonl").read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError as exc:
                raise SystemExit(f"{run / 'results.jsonl'}:{number}: not a JSON row ({exc})") from None
    return rows


def _engine(run: Path) -> dict:
    try:
        return json.loads((run / "engine.json").read_text(encoding="utf-8"))
    except OSError:
        raise SystemExit(f"{run}: no engine.json, so its engine code is unknown") from None


def _is_program(row: dict) -> bool:
    return not row.get("is_dll") and (row.get("features") or {}).get("subsystem") in ("GUI", "console")


# Folders that hold many vendors' products: the product is one level down.
_SHARED = ("common files", "windowsapps")


def _product(path: str) -> str:
    """The folder that names a benign file's product: C:\\Program Files\\<vendor>,
    with Program Files (x86) folded in and shared folders split by vendor."""
    parts = path.replace("/", "\\").lower().split("\\")
    if len(parts) > 1 and parts[1] == "program files (x86)":
        parts[1] = "program files"
    depth = 3
    while depth < len(parts) and parts[depth - 1] in _SHARED:
        depth += 1
    return "\\".join(parts[:depth])


def unique_benign(rows: list[dict]) -> list[dict]:
    """benign_sweep.summarize's unit: excluded and failed rows out, one file
    per content, the first by path."""
    unique: dict[str, dict] = {}
    for row in sorted(rows, key=lambda r: r.get("path", "")):
        if not row.get("excluded") and "error" not in row:
            unique.setdefault(row["sha256"], row)
    return list(unique.values())


def observations(malware: list[dict], benign: list[dict]) -> list[dict]:
    """One record per (file, stratum): which signals fired, its score, its group."""
    obs = []
    for s in malware:
        family = s.get("family") or "unknown"
        group = family if family != "unknown" else f"?{s['sha256']}"   # unlabelled: its own group
        base = dict(side="malware", program=_is_program(s), group=group)
        if s.get("signed"):
            obs.append(dict(base, stratum="signed-unvouched", signals=set(s["signals"]), score=s["score"]))
            if PADDED not in s["signals_if_valid"]:
                obs.append(dict(base, stratum="signed-vouched", signals=set(s["signals_if_valid"]),
                                score=s["score_if_valid"]))
        else:
            obs.append(dict(base, stratum="unsigned", signals=set(s["signals"]), score=s["score"]))
    for r in benign:
        signals = set(r["signals"])
        credited = r.get("signature") == "valid" and PADDED not in signals
        base = dict(side="benign", program=_is_program(r), group=_product(r.get("path", "")))
        name = stratum(bool(r.get("signed")), r.get("signature"), credited)
        obs.append(dict(base, stratum=name, signals=signals, score=r["score"]))
        if name == "signed-vouched":
            obs.append(dict(base, stratum="signed-unvouched", signals=set(r["signals_if_unverified"]),
                            score=r["score_if_unverified"]))
    return obs


def _cell(group: list[dict], fired) -> dict | None:
    if not group:
        return None
    hits = [o for o in group if fired(o)]
    cell = rate(len(hits), len(group))
    groups = Counter(o["group"] for o in hits)
    cell["groups"] = len(groups)
    cell["top_share"] = round(max(groups.values()) / len(hits), 3) if hits else None
    return cell


def _concentration(group: list[dict]) -> float | None:
    """The largest family's or product folder's share of a population: a rule
    whose hits are that concentrated says nothing the population did not."""
    counts = Counter(o["group"] for o in group)
    return round(max(counts.values()) / len(group), 3) if group else None


def build(obs: list[dict]) -> tuple[dict, dict, dict]:
    by: dict[tuple[str, str], list[dict]] = {}
    for o in obs:
        by.setdefault((o["stratum"], o["side"]), []).append(o)

    def programs(name, side):
        return [o for o in by.get((name, side), []) if o["program"]]

    signals: dict[str, dict] = {}
    for sig in sorted({s for o in obs for s in o["signals"]}):
        if is_verification_signal(sig):
            signals[sig] = {"verification": True, "strata": {}}
            continue
        strata = {}
        for name in STRATA:
            cells = {side: _cell(by.get((name, side), []), lambda o, sig=sig: sig in o["signals"])
                     for side in SIDES}
            if not any(cells.values()):
                continue
            cells["programs"] = {side: _cell(programs(name, side), lambda o, sig=sig: sig in o["signals"])
                                 for side in SIDES}
            strata[name] = cells
        signals[sig] = {"strata": strata}
    sizes = {name: {side: len(by.get((name, side), [])) for side in SIDES}
             | {"programs": {side: len(programs(name, side)) for side in SIDES},
                "top_share": {side: _concentration(by.get((name, side), [])) for side in SIDES},
                "programs_top_share": {side: _concentration(programs(name, side)) for side in SIDES}}
             for name in STRATA}
    bands = {name: {side: {"suspicious_or_worse": _cell(by.get((name, side), []),
                                                        lambda o: o["score"] >= SUSPICIOUS),
                           "high_risk": _cell(by.get((name, side), []), lambda o: o["score"] >= HIGH_RISK)}
                    for side in SIDES}
             for name in STRATA}
    return signals, sizes, bands


def _max_mb(engines: list[dict]) -> float | None:
    caps = {(e.get("args") or {}).get("max_mb") for e in engines}
    return max(caps) if None not in caps and caps else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--malware", nargs="+", required=True, type=Path, help="recall_sweep run folders")
    ap.add_argument("--manifest", required=True, help="the corpus manifest the recall runs used")
    ap.add_argument("--malware-label", required=True)
    ap.add_argument("--benign", nargs="+", required=True, type=Path, help="benign_sweep run folders")
    ap.add_argument("--benign-label", required=True)
    ap.add_argument("--built", required=True, help="YYYY-MM-DD the card is built")
    ap.add_argument("--min-n", type=int, default=MIN_N,
                    help="smallest population a rate is shown as measured for (default 30)")
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)

    engines = {run: _engine(run) for run in [*args.malware, *args.benign]}
    codes = {e.get("code_sha256") for e in engines.values()}
    if len(codes) != 1:
        listing = ", ".join(f"{run.name}={str(e.get('code_sha256'))[:12]}" for run, e in engines.items())
        ap.error(f"the runs come from different engine code ({listing}): a card describes one engine")
    engine = next(iter(engines.values()))

    manifest = load_manifest(args.manifest)
    m_rows = [row for run in args.malware for row in _rows(run)]
    joined = samples(m_rows, manifest, 0.3)
    malware = joined["samples"]
    benign = unique_benign([row for run in args.benign for row in _rows(run)])
    lacking = sum(r.get("signals") is None or (r.get("signed") and r.get("signals_if_valid") is None)
                  for r in malware)
    lacking += sum(r.get("signals") is None
                   or (r.get("signed") and r.get("signature") == "valid" and r.get("signals_if_unverified") is None)
                   for r in benign)
    if lacking:
        ap.error(f"{lacking} rows carry no signal IDs or no signed twin: sweep again with the engine and "
                 "sweep scripts that write them (0.8.0 or later)")
    notes = pairing_notes(engine, engine, malware, benign)
    if notes:
        ap.error(" ".join(notes))

    signals, sizes, bands = build(observations(malware, benign))
    families = {s.get("family") for s in malware} - {None, "unknown"}
    card = {
        "schema": SCHEMA,
        "engine": {"version": engine.get("version"), "code_sha256": engine.get("code_sha256")},
        "built": args.built,
        "min_n": args.min_n,
        "populations": {
            "malware": {"label": args.malware_label, "samples": len(malware), "families": len(families),
                        "unlabelled": sum((s.get("family") or "unknown") == "unknown" for s in malware),
                        "not_scored": len(joined["failures"]),
                        "max_mb": _max_mb([engines[r] for r in args.malware]),
                        "manifest_sha256": hashlib.sha256(Path(args.manifest).read_bytes()).hexdigest(),
                        "runs": [run.name for run in args.malware]},
            "benign": {"label": args.benign_label, "files": len(benign),
                       "max_mb": _max_mb([engines[r] for r in args.benign]),
                       "runs": [run.name for run in args.benign]},
        },
        "strata": sizes,
        "bands": bands,
        "signals": signals,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(card, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{args.out}: {len(signals)} signals; malware {len(malware)} samples, benign {len(benign)} files "
          f"(code {engine.get('code_sha256', '')[:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
