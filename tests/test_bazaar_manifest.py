"""Building a recall manifest from MalwareBazaar's CSV export (metadata only)."""

import hashlib
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import bazaar_manifest as bm  # noqa: E402
import recall_sweep as rs  # noqa: E402

HEADER = ('# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name",'
          '"file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"')


def _sha(n) -> str:
    return hashlib.sha256(str(n).encode()).hexdigest()


def _line(when, sha, ftype, family, name="f.bin"):
    fields = [when, sha, "m", "s", "r", name, ftype, "application/x-dosexec", family,
              "n/a", "n/a", "n/a", "n/a", "n/a"]
    return ", ".join('"' + f.replace('"', '""') + '"' for f in fields)


def _export(lines, updated="2026-09-27 13:34:05", eol="\n"):
    banner = ["#" * 64, "# MalwareBazaar full malware samples dump (CSV)",
              f"# Last updated: {updated} UTC", "#", HEADER]
    return eol.join(banner + lines + [f"# Number of entries: {len(lines)}"]) + eol


def _rows(text):
    return list(bm.read_export(text.splitlines(keepends=True)))


def test_the_export_format_is_read_with_its_commented_header():
    rows = _rows(_export([_line("2026-09-25 10:00:00", _sha(1), "exe", "AgentTesla",
                                name='invoice, "final".exe')], eol="\r\n"))
    assert rows == [{"sha256": _sha(1), "first_seen": "2026-09-25 10:00:00", "file_type": "exe",
                     "family": "AgentTesla"}]                     # the footer line is not a row
    plain = ('sha256,first_seen,file_type,signature\n'
             f'{_sha(2)},2026-01-02 03:04:05,dll,"Remcos, variant"\n')
    assert _rows(plain)[0]["family"] == "Remcos, variant"      # a comma inside a quoted field
    with pytest.raises(SystemExit, match="no signature"):
        _rows("sha256,first_seen,file_type\n")


def test_a_byte_order_mark_and_a_zipped_export_are_read(tmp_path):
    text = _export([_line("2026-09-25 01:00:00", _sha(1), "exe", "Lumma")])
    for path, data in ((tmp_path / "bom.csv", b"\xef\xbb\xbf" + text.encode()),
                       (tmp_path / "plain.csv", text.encode())):
        path.write_bytes(data)
        with bm._lines(path) as lines:
            assert [r["sha256"] for r in bm.read_export(lines)] == [_sha(1)]
    with zipfile.ZipFile(tmp_path / "full.csv.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("full.csv", text)
    with bm._lines(tmp_path / "full.csv.zip") as lines:
        assert [r["family"] for r in bm.read_export(lines)] == ["Lumma"]


def _select(lines, days=("2026-09-25",), per_family=20, unlabelled=3):
    return bm.select(iter(_rows(_export(lines))), set(days), ("exe", "dll"), per_family, unlabelled)


def test_selection_keeps_pe_files_of_the_chosen_days_capped_by_family():
    lines = ([_line("2026-09-25 01:00:00", _sha(i), "exe", "AgentTesla") for i in range(30)]
             + [_line("2026-09-25 02:00:00", _sha(100), "dll", "Remcos"),
                _line("2026-09-25 03:00:00", _sha(101), "docx", "Emotet"),     # not a PE
                _line("2026-09-24 23:59:59", _sha(102), "exe", "Remcos"),      # another day
                _line("2026-09-25 04:00:00", "not-a-hash", "exe", "Remcos"),
                _line("2026-09-25 05:00:00", _sha(100), "exe", "Remcos")]      # listed twice
             + [_line("2026-06-10 05:00:00", _sha(200 + i), "exe", "n/a") for i in range(5)])
    chosen, left_out = _select(lines, days=("2026-09-25", "2026-06-10"))
    families = [r["family"] for r in chosen]
    assert families.count("AgentTesla") == 20 and families.count("Remcos") == 1
    assert families.count("") == 3                                    # "n/a" is no family
    assert left_out == {"over the cap of its family": 10, "over the cap for unlabelled": 2,
                        "not EXE/DLL": 1, "first seen on another day": 1, "no valid sha256": 1,
                        "sha256 listed twice (first row kept)": 1}
    again, _ = _select(list(reversed(lines)), days=("2026-09-25", "2026-06-10"))
    assert sorted(r["sha256"] for r in again) == sorted(r["sha256"] for r in chosen)  # same every time


def test_a_capped_family_is_split_like_the_rest_of_the_corpus():
    # recall_sweep holds out the lowest hashes: a cap that kept those would
    # send every capped family to the held-out part and none to tuning
    lines = [_line("2026-09-25 01:00:00", _sha(i), "exe", "AgentTesla") for i in range(400)]
    chosen, _ = _select(lines, per_family=100)
    held = sum(rs.split_of(r["sha256"], 0.3) == "holdout" for r in chosen)
    assert 15 <= held <= 45


def test_spellings_of_one_family_share_one_cap_and_one_name():
    lines = ([_line("2026-09-25 01:00:00", _sha(i), "exe", "Vidar") for i in range(15)]
             + [_line("2026-09-25 01:00:00", _sha(100 + i), "exe", "vidar") for i in range(10)]
             + [_line("2026-09-25 01:00:00", _sha(200), "exe", "Agent Tesla"),
                _line("2026-09-25 01:00:00", _sha(201), "exe", "AgentTesla"),
                _line("2026-09-25 01:00:00", _sha(202), "exe", "AgentTesla")])
    chosen, left_out = _select(lines)
    assert {r["family"] for r in chosen} == {"Vidar", "AgentTesla"}   # the commonest spelling
    assert sum(r["family"] == "Vidar" for r in chosen) == 20
    assert left_out == {"over the cap of its family": 5}


def test_the_manifest_is_what_the_recall_sweep_reads(tmp_path):
    export = tmp_path / "full.csv.zip"
    with zipfile.ZipFile(export, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("full.csv", _export([_line("2026-09-25 01:00:00", _sha(1), "exe", "Lumma"),
                                        _line("2026-09-25 01:00:00", _sha(2).upper(), "EXE", "n/a")]))
    out = tmp_path / "corpus" / "manifest.csv"
    assert bm.main(["--csv", str(export), "--days", "2026-09-25", "--out", str(out)]) == 0
    manifest = rs.load_manifest(str(out))
    assert manifest[_sha(1)]["family"] == "Lumma" and manifest[_sha(1)]["source"] == "MalwareBazaar"
    assert manifest[_sha(2)]["family"] == ""               # the sweep calls it "unknown"
    assert rs._year(manifest[_sha(1)]["first_seen"]) == "2026"


def test_bad_arguments_empty_days_and_an_early_export_are_reported(tmp_path, capsys):
    export = tmp_path / "e.csv"
    export.write_text(_export([_line("2026-09-25 01:00:00", _sha(1), "exe", "Lumma")]), encoding="utf-8")
    out = str(tmp_path / "m.csv")
    for bad in (["--days", "25.09.2026"], ["--days", "2026-02-30"]):
        with pytest.raises(SystemExit):
            bm.main(["--csv", str(export), "--out", out, *bad])
    with pytest.raises(SystemExit):
        bm.main(["--csv", str(tmp_path / "missing.csv"), "--days", "2026-09-25", "--out", out])
    # one requested day selects nothing: an error even though the other day did
    assert bm.main(["--csv", str(export), "--days", "2026-09-25", "2026-09-24", "--out", out]) == 1
    assert "nothing selected for 2026-09-24" in capsys.readouterr().err
    # the export was made before the requested day ended: its list is incomplete
    early = tmp_path / "early.csv"
    early.write_text(_export([_line("2026-09-25 01:00:00", _sha(1), "exe", "Lumma")],
                             updated="2026-09-25 18:00:00"), encoding="utf-8")
    assert bm.main(["--csv", str(early), "--days", "2026-09-25", "--out", out]) == 1
    assert "before 2026-09-25 was over" in capsys.readouterr().err
