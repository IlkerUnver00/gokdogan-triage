"""The rate card: how often each scoring rule fired, measured.

For every signal ID (signals.py) the card holds how many labelled malware
samples and how many benign files it fired on, with 95% intervals, in
strata of files scored by the same rules:

- ``unsigned``: no embedded signature and no catalog entry;
- ``signed-vouched``: an embedded signature that verified as valid;
- ``signed-unvouched``: an embedded signature that did not verify (or could
  not be checked, as in the lab and off Windows);
- ``catalog``: no embedded signature, valid through a Windows catalog.

The card is built by scripts/rate_card.py from a recall run and a benign
sweep of the same engine code, and describes that code only: when the
running engine's code differs, ``describes_this_engine`` says so and every
report that shows the rates says it too. The rates are firing rates, not
probabilities: how common malware is where the file came from is not
something the card knows.
"""

from __future__ import annotations

import hashlib
import json
import sys
from functools import lru_cache
from pathlib import Path

from .models import TriageReport

DATA_DIR = Path(__file__).parent / "data"
CARD_PATH = DATA_DIR / "ratecard.json"
# A frozen build (PyInstaller) keeps its modules inside an archive, so it
# cannot hash its own code: the build writes the digest here instead.
CODE_STAMP = DATA_DIR / "engine_code_sha256.txt"
SCHEMA = "gokdogan.ratecard/1"
STRATA = ("unsigned", "signed-vouched", "signed-unvouched", "catalog")
SIDES = ("malware", "benign")
# Lines that state what the signature check found. In the lab every signed
# sample is "unverified" and its twin is assumed "valid", so their rates are
# set by how the card is built, not measured.
VERIFICATION_SIGNALS = ("signature.", "anomaly.signature-")


def is_verification_signal(signal: str) -> bool:
    return signal.startswith(VERIFICATION_SIGNALS)


def stratum(signed: bool, status: str | None, credited: bool | None = None) -> str:
    """The card stratum of a file: signed is a certificate table present,
    status the verification result, credited whether the scorer granted the
    valid-signature credit (a valid signature over padding does not earn it)."""
    vouched = status == "valid" if credited is None else credited
    if signed:
        return "signed-vouched" if vouched else "signed-unvouched"
    return "catalog" if vouched else "unsigned"


def report_stratum(report: TriageReport) -> str:
    from .verdict import _credited
    status = report.signature.status if report.signature else None
    return stratum(report.file.is_signed, status, _credited(report))


def code_hash(package_dir: Path | None = None) -> str | None:
    """SHA-256 over the engine's source and rule files, line endings folded:
    the digest the sweeps record, so a card and the engine running it can be
    matched. None in a frozen build that carries no stamp."""
    if package_dir is None and getattr(sys, "frozen", False):
        try:
            return CODE_STAMP.read_text(encoding="ascii").strip() or None
        except OSError:
            return None
    package_dir = package_dir or Path(__file__).parent
    digest = hashlib.sha256()
    for f in sorted(package_dir.rglob("*")):
        if f.suffix in (".py", ".yar", ".yara"):
            digest.update(f.relative_to(package_dir).as_posix().encode())
            digest.update(f.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()


def _valid_card(card) -> bool:
    if not (isinstance(card, dict) and card.get("schema") == SCHEMA):
        return False
    if not (isinstance(card.get("engine"), dict) and isinstance(card["engine"].get("code_sha256"), str)):
        return False
    if not (isinstance(card.get("strata"), dict) and isinstance(card.get("signals"), dict)):
        return False
    if not isinstance(card.get("min_n"), int):
        return False
    cells = [c for entry in card["signals"].values() if isinstance(entry, dict)
             for s in (entry.get("strata") or {}).values() if isinstance(s, dict)
             for c in [*(s.get(side) for side in SIDES),
                       *((s.get("programs") or {}).get(side) for side in SIDES)]]
    return all(c is None or (isinstance(c, dict) and {"k", "n", "rate", "ci95"} <= set(c)) for c in cells)


@lru_cache(maxsize=4)
def load_card(path: Path = CARD_PATH) -> dict | None:
    """The card, or None when none ships, it cannot be read, or its shape is
    not one the reports can show."""
    try:
        card = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return card if _valid_card(card) else None


@lru_cache(maxsize=4)
def describes_this_engine(card_code: str) -> bool | None:
    """True or False, or None when this build cannot tell (frozen, no stamp)."""
    mine = code_hash()
    return None if mine is None else card_code == mine


def _zero(n: int) -> dict | None:
    """A rule the card never saw fire: 0 of the stratum's n."""
    if not n:
        return None
    from_n = 1.96 * 1.96
    return {"k": 0, "n": n, "rate": 0.0, "ci95": [0.0, round(from_n / (n + from_n), 4)],
            "groups": 0, "top_share": None}


def lookup(card: dict, signal: str, stratum_name: str, program: bool,
           describes: bool | None = True) -> dict | None:
    """The cells for one breakdown line:
    {"malware", "benign": cell|None, "programs": bool, "fallback": bool,
     "population": the stratum's sizes and shares for the cells used},
    {"verification": True} for a signature-check line, or None."""
    if is_verification_signal(signal):
        return {"verification": True}
    sizes = card.get("strata", {}).get(stratum_name) or {}
    sub_sizes = sizes.get("programs") or {}
    minimum = card.get("min_n", 30)
    # A side the stratum holds no file of (malware in the catalog stratum) does
    # not stand in the way of comparing programs with programs.
    measured = [side for side in SIDES if (sizes.get(side) or 0) > 0]
    use_programs = program and bool(measured) and all((sub_sizes.get(side) or 0) >= minimum for side in measured)
    population = {"n": {side: (sub_sizes if use_programs else sizes).get(side) or 0 for side in SIDES},
                  "top_share": (sizes.get("programs_top_share") if use_programs else sizes.get("top_share")) or {}}
    entry = card.get("signals", {}).get(signal)
    cells = (entry or {}).get("strata", {}).get(stratum_name)
    if cells is None:
        if not describes or not any(population["n"].values()):
            return None
        # This engine wrote the card and the rule fired on none of these files.
        found = {side: _zero(population["n"][side]) for side in SIDES}
    else:
        found = (cells.get("programs") or {}) if use_programs else cells
        found = {side: found.get(side) for side in SIDES}
    return dict(found, programs=use_programs, fallback=program and not use_programs, population=population)


def format_cell(cell: dict | None, minimum: int = 0) -> str:
    """'10.7% (37/347)'; for a rule that never fired '0/549 (<0.7%)', since 0
    of a few hundred is not zero; with an interval when n is small."""
    if not cell or not cell.get("n"):
        return "not measured"
    if cell["n"] < minimum:
        lo, hi = cell["ci95"]
        return f"too few measured ({cell['k']}/{cell['n']}, {lo:.0%}-{hi:.0%})"
    if cell["k"] == 0:
        return f"0/{cell['n']:,} (<{cell['ci95'][1]:.1%})"
    return f"{cell['rate']:.1%} ({cell['k']}/{cell['n']:,})"


def _concentrated(cell: dict | None, population_share: float | None) -> bool:
    """Most of a rule's hits are one family or product, clearly more than the
    population it was measured on already is."""
    share = (cell or {}).get("top_share") or 0
    return (cell or {}).get("k", 0) >= 3 and share >= 0.5 and share >= (population_share or 0) + 0.2


_UNITS = {"family": ("family", "families"), "product": ("product folder", "product folders")}


def _enough(cell: dict | None, minimum: int) -> bool:
    return bool(cell) and cell.get("n", 0) >= minimum


def line_note(rates: dict | None, points: int = 1, minimum: int = 30) -> str | None:
    """The measured line printed under a breakdown entry, or None."""
    if not rates:
        return None
    if rates.get("verification"):
        return "what the signature check found: set by how the card is built, not measured"
    malware, benign = rates.get("malware"), rates.get("benign")
    text = f"malware {format_cell(malware, minimum)}; benign {format_cell(benign, minimum)}"
    if rates.get("programs"):
        text += " (programs)"
    elif rates.get("fallback"):
        text += " (all files: too few programs measured)"
    shares = (rates.get("population") or {}).get("top_share") or {}
    flags = []
    # Only where both sides were measured enough and the intervals part, and
    # only for a line that adds points: a credit is meant to fire on benign files.
    if points > 0 and _enough(malware, minimum) and _enough(benign, minimum) and benign["k"] \
            and benign["ci95"][0] >= malware["ci95"][1]:
        flags.append("fires more often on benign files")
    for side, cell, unit in (("malware", malware, "family"), ("benign", benign, "product")):
        if not _enough(cell, minimum):
            continue
        if _concentrated(cell, shares.get(side)):
            flags.append(f"{cell['top_share']:.0%} of its {side} hits are one {unit}")
        elif cell.get("k", 0) >= 3 and 0 < cell.get("groups", 0) <= 3:
            word = _UNITS[unit][cell["groups"] > 1]
            flags.append(f"its {side} hits come from {cell['groups']} {word}")
    return text + "".join(f" [{f}]" for f in flags)


def card_note(rates: dict) -> str:
    """The line that says what the rates are and what they are not."""
    card = rates["card"]
    text = (f"Rate card for {rates['stratum']} files, gokdogan {card.get('engine_version')}, "
            f"built {card.get('built')}: how often each line fired on malware and on benign "
            f"software. Not a probability.")
    share = ((rates.get("population") or {}).get("top_share") or {}).get("benign")
    if share and share >= 0.5:
        text += f" {share:.0%} of the benign files of this kind come from one product folder."
    benign_max = card.get("benign_max_mb")
    if benign_max and rates.get("file_size", 0) > benign_max * 1024 * 1024:
        text += f" No benign file over {benign_max:g} MB was measured; this one is larger."
    if card.get("describes_this_engine") is None:
        text += " Whether the card matches this build is unknown."
    elif not card["describes_this_engine"]:
        text += " The card was built for other engine code: treat the rates as approximate."
    return text


def margin(report: TriageReport, suspicious: int, high_risk: int) -> str:
    """How far the score sits from the thresholds around it, and what holds it."""
    score = report.score
    signals = [e.signal for e in report.score_breakdown]
    total = sum(e.points for e in report.score_breakdown if not e.signal.startswith("floor."))
    if any(s.startswith("floor.") for s in signals):
        return f"held at SUSPICIOUS by a floor: the lines alone sum to {total}"
    if score >= high_risk:
        text = f"{score - high_risk} points above the HIGH_RISK line"
    elif score >= suspicious:
        text = f"{score - suspicious} points above the SUSPICIOUS line, {high_risk - score} short of HIGH_RISK"
    elif total < 0:
        text = f"{suspicious - total} points short of SUSPICIOUS (the lines sum to {total}; the score stops at 0)"
    else:
        text = f"{suspicious - score} points short of SUSPICIOUS"
    if "cap.packing" in signals:
        text += "; packing evidence is capped, so more of it adds nothing"
    return text


def rates_for(report: TriageReport, card: dict | None = None) -> dict | None:
    """Every breakdown line of a scored report with the card's cells for it,
    or None when no card ships (or it cannot be applied to this report)."""
    card = card if card is not None else load_card()
    if card is None:
        return None
    try:
        name = report_stratum(report)
        describes = describes_this_engine(card["engine"]["code_sha256"])
        program = report.file.is_program
        lines = [{"signal": e.signal, "points": e.points,
                  "rates": lookup(card, e.signal, name, program, describes) if e.signal else None}
                 for e in report.score_breakdown]
        population = next((line["rates"]["population"] for line in lines
                           if line["rates"] and "population" in line["rates"]),
                          {"top_share": (card["strata"].get(name) or {}).get("top_share") or {}})
        return {
            "card": {"engine_version": card["engine"].get("version"), "describes_this_engine": describes,
                     "built": card.get("built"),
                     "benign_max_mb": ((card.get("populations") or {}).get("benign") or {}).get("max_mb")},
            "min_n": card["min_n"],
            "stratum": name,
            "population": population,
            "file_size": report.file.size,
            "lines": lines,
        }
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
