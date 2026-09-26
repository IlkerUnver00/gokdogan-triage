"""The recall benchmark's bookkeeping: splits, intervals, readers and the guard."""

import hashlib
import json
import sys
import warnings
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import benign_sweep  # noqa: E402
import recall_sweep as rs  # noqa: E402


def test_wilson_interval_brackets_the_rate():
    lo, hi = rs.wilson(59, 2694)
    assert lo < 59 / 2694 < hi
    assert rs.wilson(0, 0) == (0.0, 1.0)   # no data, no information
    assert rs.wilson(0, 10)[0] == 0.0


def test_split_is_a_stable_function_of_the_hash():
    hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(2000)]
    splits = [rs.split_of(h, 0.3) for h in hashes]
    assert splits == [rs.split_of(h, 0.3) for h in hashes]
    assert 0.26 < splits.count("holdout") / len(splits) < 0.34
    assert rs.split_of("0" * 64, 0.3) == "holdout"
    assert rs.split_of("f" * 64, 0.3) == "tune"


def _row(score, signed=False, severe=False, sha=None, split=None, reasons=()):
    breakdown = [[18, "capability: process-injection"]] if severe else [[8, "capability: network"]]
    breakdown += [[1, r] for r in reasons]
    row = {"path": sha or "p", "sha256": sha or "0" * 64, "score": score, "signed": signed,
           "breakdown": breakdown, "dotnet": False, "packed": False, "yara": True}
    if split:
        row["split"] = split
    return row


def test_signature_bound_follows_the_verdict_rules():
    assert rs._score_if_signature_valid(_row(40)) == 40                      # unsigned: unchanged
    assert rs._score_if_signature_valid(_row(40, signed=True)) == 25         # -15
    assert rs._score_if_signature_valid(_row(36, signed=True, severe=True)) == 30  # sev-3 floor
    assert rs._score_if_signature_valid(_row(20, signed=True, severe=True)) == 5   # floor needs >= 30


def _zip(path, members, compression=zipfile.ZIP_DEFLATED):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # duplicate member names warn
        with zipfile.ZipFile(path, "w", compression=compression) as z:
            for name, data in members:
                z.writestr(name, data)


def test_samples_are_read_from_files_and_zip_members(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"raw bytes")
    _zip(tmp_path / "b.zip", [("inner.bin", b"zipped bytes")])
    items, skipped, unreadable = rs.collect(tmp_path, max_bytes=1024)
    assert not skipped and not unreadable
    assert [rs.read_sample(i, b"infected", 1024) for i in items] == [b"raw bytes", b"zipped bytes"]


def test_repeated_member_names_are_each_read(tmp_path):
    _zip(tmp_path / "dup.zip", [("sample.bin", b"first"), ("sample.bin", b"second")])
    items, _, _ = rs.collect(tmp_path, max_bytes=1024)
    assert len(set(items)) == 2
    assert [rs.read_sample(i, b"infected", 1024) for i in items] == [b"first", b"second"]


def test_reads_are_bounded_whatever_the_archive_declares(tmp_path):
    _zip(tmp_path / "big.zip", [("zeros.bin", bytes(2_000_000))])
    item = f"{tmp_path / 'big.zip'}::0::zeros.bin"
    with pytest.raises(ValueError, match="larger than"):
        rs.read_sample(item, b"infected", 1_000)


def test_unboundable_compression_is_skipped(tmp_path):
    _zip(tmp_path / "bz.zip", [("x.bin", b"x" * 100)], compression=zipfile.ZIP_BZIP2)
    items, skipped, _ = rs.collect(tmp_path, max_bytes=1024)
    assert items == [] and skipped["unsupported ZIP compression (bzip2/LZMA)"] == 1


def test_a_malformed_archive_is_skipped_not_fatal(tmp_path):
    (tmp_path / "broken.zip").write_bytes(b"PK\x03\x04 not really a zip")
    (tmp_path / "ok.bin").write_bytes(b"ok")
    items, skipped, unreadable = rs.collect(tmp_path, max_bytes=1024)
    assert len(items) == 1 and skipped["unreadable zip"] == 1 and unreadable


def test_manifest_header_and_dates_are_normalised(tmp_path):
    manifest = tmp_path / "m.csv"
    manifest.write_text("SHA256, Family, First_Seen\n" + "A" * 64 + ", AgentTesla, 3/14/2025\n",
                        encoding="utf-8")
    loaded = rs.load_manifest(str(manifest))
    assert loaded["a" * 64]["family"] == "AgentTesla"
    assert rs._year(loaded["a" * 64]["first_seen"]) == "2025"
    assert rs._year(" 2019-05-01") == "2019" and rs._year("") == "unknown"


def test_samples_join_the_manifest_and_count_what_was_left_out():
    a, b, c, d = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
    rows = [
        _row(40, sha=a), _row(40, sha=a),                     # duplicate
        _row(10, sha=b),                                      # not in manifest
        {"path": "x", "sha256": d, "error": "not a PE (no MZ header)", "not_pe": True},
        {"path": "y", "error": "timeout after 120s", "failure": "timeout"},
    ]
    manifest = {a: {"family": "AgentTesla", "first_seen": "2025-03-01"}, c: {}, d: {}}
    joined = rs.samples(rows, manifest, 0.3)
    assert [s["family"] for s in joined["samples"]] == ["AgentTesla"]
    assert joined["counts"] == {"duplicate": 1, "not in manifest": 1, "not a PE (no MZ header)": 1,
                                "timeout or worker died": 1, "in manifest, not in the corpus": 1}
    assert len(joined["failures"]) == 1


def test_pes_the_engine_could_not_score_count_as_misses():
    rows = [_row(40, sha="0" * 64), _row(50, sha="1" * 64),
            {"path": "c", "sha256": "2" * 64, "error": "RecursionError", "crashed": True},
            {"path": "p", "sha256": "3" * 64, "error": "MZ file the PE parser rejects", "unparsed": True}]
    det = rs.summarize(rows, {}, 0.3)["detection"]["all"]
    assert det["suspicious_or_worse"]["rate"] == 1.0
    assert det["intent_to_triage"] == rs.rate(2, 4)


def test_analysis_tables_come_from_the_tuning_part_only():
    held, tune = "0" * 64, "f" * 64          # split_of: "0..." is held out, "f..." tuning
    rows = [_row(5, sha=held, reasons=["HELD_OUT_ONLY"]), _row(5, sha=tune, reasons=["TUNING"])]
    summary = rs.summarize(rows, {}, 0.3)
    signals = {s["signal"] for s in summary["tuning_signals"]}
    assert "TUNING" in signals and "HELD_OUT_ONLY" not in signals
    assert [m["sha256"] for m in summary["tuning_worst_misses"]] == [tune]


def test_family_balanced_rate_leaves_unlabelled_samples_out():
    held = [f"{i:02x}" + "0" * 62 for i in range(12)]   # all in the held-out part
    rows = [_row(40 if i < 3 else 0, sha=h) for i, h in enumerate(held)]
    manifest = {h: {"family": "Big" if i < 3 else ("Small" if i < 6 else "")} for i, h in enumerate(held)}
    fb = rs.summarize(rows, manifest, 0.3)["family_balanced_holdout"]
    assert fb == {"rate": 0.5, "families": 2, "unlabelled_samples": 6}


def test_threshold_table_counts_each_benign_file_once():
    malware = [{"score": s, "split": "holdout"} for s in (5, 35, 70)]
    benign = [{"sha256": "a", "score": 40}, {"sha256": "a", "score": 40}, {"sha256": "b", "score": 0},
              {"sha256": "c", "score": 50, "excluded": "same bytes"}]
    at30 = next(t for t in rs.threshold_table(malware, benign) if t["threshold"] == 30)
    assert at30["malware_holdout"]["k"] == 2 and at30["benign"] == rs.rate(1, 2)


def test_pairing_notes_catch_different_rules():
    malware = [{"yara": False}]
    notes = rs.pairing_notes({"code_sha256": "x"}, {"code_sha256": "y"}, malware,
                             [{"sha256": "a", "score": 0, "yara": True}])
    assert len(notes) == 2


def test_report_reuses_the_runs_split_and_manifest(tmp_path):
    rows = [_row(40, sha=f"{i:02x}" + "0" * 62) for i in range(10)]
    (tmp_path / "results.jsonl").write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    (tmp_path / "engine.json").write_text(json.dumps(
        {"code_sha256": "x", "args": {"holdout_fraction": 0.02, "manifest": "D:/gone/manifest.csv"}}),
        encoding="utf-8")
    (tmp_path / "manifest.csv").write_text("sha256,family\n", encoding="utf-8")
    rs.main(["--report", str(tmp_path / "results.jsonl"), "--out", str(tmp_path / "out")])
    summary = json.loads((tmp_path / "out" / "summary.json").read_text(encoding="utf-8"))
    assert summary["holdout_fraction"] == 0.02


def test_synced_folders_are_refused(tmp_path, monkeypatch):
    synced = tmp_path / "OneDrive" / "corpus"
    synced.mkdir(parents=True)
    assert rs._is_synced(synced)
    lookalike = tmp_path / "C--Users-x-OneDrive-Desktop" / "corpus"   # a name, not the folder
    lookalike.mkdir(parents=True)
    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        monkeypatch.delenv(var, raising=False)
    assert not rs._is_synced(lookalike)
    monkeypatch.setenv("OneDrive", str(tmp_path / "C--Users-x-OneDrive-Desktop"))
    assert rs._is_synced(lookalike)
    assert rs._is_synced(Path("G:/My Drive/corpus")) and rs._is_synced(Path("//server/share/corpus"))
    with pytest.raises(SystemExit):
        rs._refuse_synced(synced)


def test_worker_pool_finishes_on_repeated_paths_without_false_failures(tmp_path):
    # Missing files fail fast, which used to expose a race that recorded
    # healthy items as "worker died"; a repeated path used to hang the loop.
    paths = [str(tmp_path / f"missing{i}.exe") for i in range(60)] + [str(tmp_path / "missing0.exe")]
    rows = benign_sweep.run(paths, jobs=2, use_yara=False, out_jsonl=tmp_path / "r.jsonl")
    assert len(rows) == 60
    assert not [r for r in rows if r.get("failure")]
