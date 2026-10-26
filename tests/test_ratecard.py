"""The rate card: built from sweep rows, looked up per breakdown line."""

import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import rate_card  # noqa: E402
from archetypes import ARCHETYPES  # noqa: E402

from gokdogan import ratecard  # noqa: E402
from gokdogan.verdict import score_report  # noqa: E402

CODE = "c0de" * 16


def _scored(name):
    factory, _verdict = ARCHETYPES[name]
    report = factory()
    score_report(report)
    return report


def test_strata_follow_how_the_scorer_treated_the_file():
    assert ratecard.stratum(False, None) == "unsigned"
    assert ratecard.stratum(False, "valid") == "catalog"
    assert ratecard.stratum(True, "valid") == "signed-vouched"
    for status in ("unverified", "expired", "untrusted", "tampered", "revoked", "unavailable"):
        assert ratecard.stratum(True, status) == "signed-unvouched"
    # a valid signature over a padded certificate table earns no credit
    assert ratecard.stratum(True, "valid", credited=False) == "signed-unvouched"
    assert ratecard.report_stratum(_scored("padded_signed_dll")) == "signed-unvouched"


def test_the_card_and_the_sweeps_hash_the_engine_the_same_way():
    from benign_sweep import _code_hash
    assert ratecard.code_hash() == _code_hash(ROOT / "gokdogan")


def test_a_frozen_build_reads_its_stamp_instead_of_hashing_an_archive(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(ratecard, "CODE_STAMP", tmp_path / "stamp.txt")
    assert ratecard.code_hash() is None                      # no stamp: unknown, not "other code"
    (tmp_path / "stamp.txt").write_text("ab" * 32 + "\n", encoding="ascii")
    assert ratecard.code_hash() == "ab" * 32


# --- building ----------------------------------------------------------------------------------

def _sha(i: int) -> str:
    return f"{i:064x}"


def _malware(i, signals, *, signed=False, if_valid=None, score=40):
    row = dict(path=f"day.zip/{_sha(i)}", sha256=_sha(i), score=score, verdict="SUSPICIOUS", yara=True,
               signed=signed, signature="unverified" if signed else "unsigned", is_dll=False,
               breakdown=[[10, s] for s in signals], signals=list(signals), features={"subsystem": "GUI"})
    if signed:
        row.update(score_if_valid=max(0, score - 15), signals_if_valid=list(if_valid or []),
                   breakdown_if_valid=[[10, s] for s in if_valid or []])
    return row


def _benign(i, signals, *, path, signed=False, signature=None, unverified=None, score=0, **extra):
    row = dict(path=path, sha256=_sha(i), score=score, verdict="LIKELY_CLEAN", yara=True, signed=signed,
               signature=signature, is_dll=True, breakdown=[[2, s] for s in signals], signals=list(signals),
               features={"subsystem": "GUI"}, **extra)
    if signed and signature == "valid":
        row.update(signals_if_unverified=list(unverified or []), score_if_unverified=score + 15)
    return row


def _run(folder: Path, rows, code=CODE, finished=True):
    folder.mkdir(parents=True)
    (folder / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (folder / "engine.json").write_text(json.dumps({"version": "0.8.0", "code_sha256": code,
                                                    "args": {"max_mb": 12.0}}), encoding="utf-8")
    if finished:
        (folder / "summary.json").write_text("{}", encoding="utf-8")
    return folder


def _card(tmp_path, malware_rows, benign_rows, families, benign_code=CODE, finished=True):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text("sha256,family,first_seen\n" + "".join(
        f"{r['sha256']},{families.get(r['sha256'], '')},2026-09-25\n" for r in malware_rows), encoding="utf-8")
    out = tmp_path / "card.json"
    rate_card.main(["--malware", str(_run(tmp_path / "recall", malware_rows)), "--manifest", str(manifest),
                    "--malware-label", "test corpus",
                    "--benign", str(_run(tmp_path / "benign", benign_rows, benign_code, finished)),
                    "--benign-label", "test machine", "--built", "2026-10-26", "--min-n", "2",
                    "--out", str(out)])
    return json.loads(out.read_text(encoding="utf-8")), out


def test_the_card_counts_each_stratum_and_names_no_file(tmp_path):
    malware = [_malware(1, ["capability.network.imports", "anomaly.no-import-table"]),
               _malware(2, ["capability.network.imports"]),
               _malware(3, []),
               # signed: as the lab scored it, and as a valid signature would have
               _malware(4, ["packing.packer-heuristic", "signature.unverified"], signed=True,
                        if_valid=["signature.valid"]),
               # a valid signature over padding earns nothing: no vouched twin
               _malware(5, ["anomaly.cert-table-padding"], signed=True,
                        if_valid=["anomaly.cert-table-padding", "signature.valid-padded"])]
    benign = [_benign(10, ["anomaly.no-import-table"], path=r"C:\Program Files\Acme\a.dll"),
              _benign(11, [], path=r"C:\Program Files (x86)\Acme\b.dll"),
              _benign(10, ["anomaly.no-import-table"], path=r"C:\Program Files\Zeta\copy.dll"),  # same bytes
              _benign(12, ["anomaly.no-import-table"], path=r"C:\Program Files\Acme\x.dll", excluded=True),
              _benign(13, ["signature.valid"], path=r"C:\Windows\System32\k.dll", signed=True,
                      signature="valid", unverified=["packing.packer-heuristic", "signature.unverified"]),
              _benign(14, [], path=r"C:\Windows\System32\cat.dll", signature="valid"),
              _benign(15, ["signature.valid-padded"], path=r"C:\Program Files\Common Files\Apple\p.dll",
                      signed=True, signature="valid", unverified=["signature.unverified"])]
    card, out = _card(tmp_path, malware, benign, {_sha(1): "AgentTesla", _sha(2): "AgentTesla"})

    assert card["schema"] == ratecard.SCHEMA and card["engine"]["code_sha256"] == CODE
    assert card["populations"]["benign"]["max_mb"] == 12.0
    sizes = card["strata"]
    assert (sizes["unsigned"]["malware"], sizes["unsigned"]["benign"]) == (3, 2)
    assert (sizes["signed-vouched"]["malware"], sizes["signed-vouched"]["benign"]) == (1, 1)
    # the lab's two signed samples; the vouched benign file's twin and the padded file
    assert (sizes["signed-unvouched"]["malware"], sizes["signed-unvouched"]["benign"]) == (2, 2)
    assert sizes["catalog"]["benign"] == 1
    # two of the three unsigned samples are one family; both unsigned benign files one vendor
    assert sizes["unsigned"]["top_share"] == {"malware": 0.667, "benign": 1.0}

    net = card["signals"]["capability.network.imports"]["strata"]["unsigned"]
    assert (net["malware"]["k"], net["malware"]["n"]) == (2, 3)
    assert net["malware"]["groups"] == 1 and net["malware"]["top_share"] == 1.0
    nit = card["signals"]["anomaly.no-import-table"]["strata"]["unsigned"]
    assert (nit["benign"]["k"], nit["benign"]["n"]) == (1, 2)          # the copy and the excluded file left out
    packer = card["signals"]["packing.packer-heuristic"]["strata"]
    assert (packer["signed-unvouched"]["malware"]["k"], packer["signed-unvouched"]["benign"]["k"]) == (1, 1)
    assert packer["signed-vouched"]["malware"]["k"] == 0
    # what the signature check found is set by the twins, so it gets no cells at all
    for sig in ("signature.valid", "signature.unverified", "signature.valid-padded"):
        assert card["signals"][sig] == {"verification": True, "strata": {}}

    text = out.read_text(encoding="utf-8").lower()
    for leak in ("acme", "zeta", "apple", "program files", "system32", "day.zip"):
        assert leak not in text


def test_shared_folders_are_split_by_vendor_and_x86_folded():
    assert rate_card._product(r"C:\Program Files (x86)\Acme\a.dll") == r"c:\program files\acme"
    assert rate_card._product(r"C:\Program Files\Common Files\Apple\b.dll") == \
        r"c:\program files\common files\apple"
    assert rate_card._product(r"C:\Program Files\WindowsApps\Pkg_1.0\c.dll") == \
        r"c:\program files\windowsapps\pkg_1.0"


def test_a_card_describes_one_engine(tmp_path):
    with pytest.raises(SystemExit):
        _card(tmp_path, [_malware(1, [])], [_benign(10, [], path="C:/x.dll")], {}, benign_code="f" * 64)


def test_rows_without_signal_ids_are_refused(tmp_path):
    old = _malware(1, ["capability.network.imports"])
    del old["signals"]
    with pytest.raises(SystemExit):
        _card(tmp_path, [old], [_benign(10, [], path="C:/x.dll")], {})


def test_a_vouched_benign_file_without_its_twin_is_refused(tmp_path):
    row = _benign(13, [], path="C:/k.dll", signed=True, signature="valid")
    del row["signals_if_unverified"]
    with pytest.raises(SystemExit):
        _card(tmp_path, [_malware(1, [])], [row], {})


def test_an_unfinished_sweep_is_refused(tmp_path):
    with pytest.raises(SystemExit):
        _card(tmp_path, [_malware(1, [])], [_benign(10, [], path="C:/x.dll")], {}, finished=False)


# --- reading ------------------------------------------------------------------------------------

def _c(k, n, groups=4, top=0.3):
    from recall_sweep import wilson
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": k / n, "ci95": [lo, hi], "groups": groups, "top_share": top}


def _toy_card(program_n=80, signals=None):
    return {"schema": ratecard.SCHEMA, "min_n": 30, "built": "2026-10-26",
            "engine": {"version": "0.8.0", "code_sha256": CODE},
            "populations": {"benign": {"max_mb": 12.0}},
            "strata": {"unsigned": {"malware": 300, "benign": 500, "programs": {"malware": 250, "benign": program_n},
                                    "top_share": {"malware": 0.05, "benign": 0.3},
                                    "programs_top_share": {"malware": 0.05, "benign": 0.6}}},
            "signals": signals if signals is not None else {"capability.network.imports": {"strata": {"unsigned": {
                "malware": _c(50, 300), "benign": _c(5, 500),
                "programs": {"malware": _c(45, 250), "benign": _c(2, program_n)}}}}}}


def test_a_program_is_compared_with_programs_when_both_sides_measured_enough():
    card = _toy_card(program_n=80)
    hit = ratecard.lookup(card, "capability.network.imports", "unsigned", program=True)
    assert hit["programs"] and not hit["fallback"]
    assert hit["population"]["top_share"]["benign"] == 0.6          # the programs' own concentration
    assert not ratecard.lookup(card, "capability.network.imports", "unsigned", program=False)["programs"]
    few = ratecard.lookup(_toy_card(program_n=12), "capability.network.imports", "unsigned", program=True)
    assert not few["programs"] and few["fallback"]
    assert "(all files: too few programs measured)" in ratecard.line_note(few)
    # the catalog stratum holds no malware: its programs are still compared with programs
    card["strata"]["catalog"] = {"malware": 0, "benign": 800, "programs": {"malware": 0, "benign": 100},
                                 "top_share": {}, "programs_top_share": {}}
    card["signals"]["capability.network.imports"]["strata"]["catalog"] = {
        "malware": None, "benign": _c(80, 800), "programs": {"malware": None, "benign": _c(10, 100)}}
    catalog = ratecard.lookup(card, "capability.network.imports", "catalog", program=True)
    assert catalog["programs"] and catalog["benign"]["n"] == 100


def test_a_rule_this_engine_never_saw_fire_reads_zero_of_n():
    card = _toy_card()
    zero = ratecard.lookup(card, "anomaly.never-fired", "unsigned", program=False, describes=True)
    assert (zero["malware"]["k"], zero["malware"]["n"], zero["benign"]["n"]) == (0, 300, 500)
    assert ratecard.line_note(zero).startswith("malware 0/300 (<1.3%); benign 0/500")
    # for other engine code, absence says nothing
    assert ratecard.lookup(card, "anomaly.never-fired", "unsigned", program=False, describes=False) is None


def test_small_populations_are_shown_as_such_and_raise_no_flag():
    note = ratecard.line_note({"malware": _c(40, 98), "benign": _c(1, 2)}, points=10, minimum=30)
    assert "benign too few measured (1/2," in note and "[" not in note


def test_fires_more_often_on_benign_needs_the_intervals_to_part():
    overlapping = {"malware": _c(2, 68), "benign": _c(46, 1271)}
    assert "more often on benign" not in ratecard.line_note(overlapping, points=15)
    parted = {"malware": _c(3, 300), "benign": _c(200, 1000)}
    assert "fires more often on benign files" in ratecard.line_note(parted, points=6)
    # a credit is meant to fire on benign files
    assert "more often on benign" not in ratecard.line_note(parted, points=-15)


def test_concentration_is_judged_against_the_population_measured():
    cell = _c(10, 100, groups=1, top=0.9)
    note = ratecard.line_note({"malware": cell, "benign": cell,
                               "population": {"top_share": {"malware": 0.2, "benign": 0.3}}})
    assert "one family" in note and "one product" in note
    note = ratecard.line_note({"malware": cell, "benign": cell,
                               "population": {"top_share": {"malware": 0.2, "benign": 0.95}}})
    assert "one family" in note and "one product" not in note
    few = _c(45, 300, groups=3, top=0.34)
    assert "its malware hits come from 3 families" in ratecard.line_note({"malware": few, "benign": _c(1, 500)})


def test_signature_check_lines_say_they_are_not_measured():
    rates = ratecard.lookup(_toy_card(), "signature.valid", "unsigned", program=False)
    assert rates == {"verification": True}
    assert "not measured" in ratecard.line_note(rates)


def test_the_margin_says_what_holds_the_score():
    from gokdogan.models import ScoreEntry
    from gokdogan.verdict import HIGH_RISK_THRESHOLD as H
    from gokdogan.verdict import SUSPICIOUS_THRESHOLD as S
    assert ratecard.margin(_scored("stealer"), S, H).endswith("above the HIGH_RISK line")
    assert "packing evidence is capped" in ratecard.margin(_scored("packed_loader"), S, H)
    report = _scored("stealer")
    report.score_breakdown = [ScoreEntry(4, "a", "capability.x.imports"), ScoreEntry(-15, "b", "signature.valid")]
    report.score = 0
    assert "the lines sum to -11; the score stops at 0" in ratecard.margin(report, S, H)
    report.score_breakdown = [ScoreEntry(12, "a", "packing.file-entropy"),
                              ScoreEntry(18, "c", "floor.unreadable-program")]
    report.score = S
    assert ratecard.margin(report, S, H) == "held at SUSPICIOUS by a floor: the lines alone sum to 12"


def test_a_malformed_card_is_not_loaded_and_never_breaks_a_report(tmp_path):
    good = _toy_card()
    for i, broken in enumerate(({**good, "engine": None}, {**good, "min_n": None}, {**good, "signals": []},
                                {**good, "signals": {"x": {"strata": {"unsigned": {"malware": {"n": 9}}}}}})):
        path = tmp_path / f"card{i}.json"
        path.write_text(json.dumps(broken), encoding="utf-8")
        assert ratecard.load_card(path) is None
    assert ratecard.rates_for(_scored("stealer"), {**good, "strata": None}) is None


def test_without_a_card_nothing_is_shown(tmp_path):
    assert ratecard.load_card(tmp_path / "missing.json") is None
    (tmp_path / "other.json").write_text('{"schema": "something else"}', encoding="utf-8")
    assert ratecard.load_card(tmp_path / "other.json") is None


def _card_for(report):
    first = report.score_breakdown[0].signal
    return _toy_card(signals={first: _toy_card()["signals"]["capability.network.imports"]}), first


def test_reports_show_the_measured_rates_when_a_card_ships(monkeypatch):
    from gokdogan.html_report import render_html
    from gokdogan.report import render_console, render_json

    report = _scored("stealer")
    card, first = _card_for(report)
    monkeypatch.setattr(ratecard, "load_card", lambda: card)

    buf = io.StringIO()
    render_console(report, buf)
    text = buf.getvalue()
    assert "Not a probability." in text and "other engine code" in text
    assert "malware 16.7% (50/300)" in text or "malware 18.0% (45/250)" in text
    data = json.loads(render_json(report))
    assert data["rate_card"]["stratum"] == "unsigned" and data["rate_card"]["lines"][0]["signal"] == first
    html = render_html(report)
    assert "<th>measured</th>" in html and "Not a probability." in html


def test_the_web_json_endpoint_carries_the_card_too(monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from gokdogan import web

    notepad = Path(r"C:\Windows\System32\notepad.exe")
    if not notepad.exists():
        pytest.skip("needs a Windows system binary")
    report = _scored("stealer")
    card, _first = _card_for(report)
    for name in ratecard.STRATA:
        card["strata"][name] = card["strata"]["unsigned"]
    monkeypatch.setattr(ratecard, "load_card", lambda: card)
    r = TestClient(web.app).post("/api/triage", files={"file": ("n.exe", notepad.read_bytes())})
    assert r.status_code == 200 and "rate_card" in r.json()


def test_reports_are_unchanged_without_a_card(monkeypatch):
    from gokdogan.html_report import render_html
    from gokdogan.report import render_console, render_json

    monkeypatch.setattr(ratecard, "load_card", lambda: None)
    report = _scored("stealer")
    buf = io.StringIO()
    render_console(report, buf)
    assert "Rate card" not in buf.getvalue()
    assert "rate_card" not in json.loads(render_json(report))
    assert "measured" not in render_html(report)
