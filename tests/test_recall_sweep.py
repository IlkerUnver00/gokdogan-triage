"""The recall benchmark's bookkeeping: splits, intervals, readers and the guard."""

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import warnings
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import _sweep_workers as sw  # noqa: E402
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
    assert rs._is_synced(tmp_path / "thinclient_drives" / "C" / "corpus")   # xrdp drive redirection
    with pytest.raises(SystemExit):
        rs._refuse_synced(synced)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows drive letters and UNC paths")
def test_google_drive_and_unc_paths_are_refused():
    assert rs._is_synced(Path("G:/My Drive/corpus")) and rs._is_synced(Path("//server/share/corpus"))


MOUNTS = """\
/dev/sda2 / ext4 rw,relatime 0 0
proc /proc proc rw,nosuid 0 0
C:\\134 /mnt/c 9p rw,aname=drvfs 0 0
//host/share /mnt/lab\\040share cifs rw 0 0
xrdp-chansrv /home/test/thinclient_drives fuse.xrdp-chansrv rw,nosuid 0 0
/dev/sdb1 /mnt/c/local ext4 rw 0 0
"""


def test_mount_table_names_the_filesystem_holding_a_path():
    def fstype(p):
        return rs._mount_type(Path(p), MOUNTS)
    assert fstype("/home/test/corpus") == "ext4"
    assert fstype("/mnt/c/Users/x/corpus") == "9p"                 # the host's drive in WSL
    assert fstype("/mnt/lab share/corpus") == "cifs"               # octal-escaped mount point
    assert fstype("/home/test/thinclient_drives/C/corpus") == "fuse.xrdp-chansrv"
    assert fstype("/mnt/c/local/corpus") == "ext4"                 # the deepest mount wins
    assert fstype("/mnt/cx") == "ext4"                             # /mnt/c is not a prefix of /mnt/cx
    assert {"9p", "cifs", "fuse.xrdp-chansrv"} <= rs.REMOTE_FS_TYPES


MOUNTINFO = """\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
90 22 0:61 / /mnt/c rw,noatime - 9p C:\\134 rw,aname=drvfs
91 22 0:62 /share /home/test/corpus/incoming-\\351 rw master:3 - virtiofs hostshare rw
"""


@pytest.mark.skipif(not hasattr(os, "makedev"), reason="device numbers are POSIX")
def test_mountinfo_names_the_filesystem_of_a_device():
    assert rs._device_type(os.makedev(8, 2), MOUNTINFO) == "ext4"
    assert rs._device_type(os.makedev(0, 61), MOUNTINFO) == "9p"
    assert rs._device_type(os.makedev(0, 62), MOUNTINFO) == "virtiofs"   # whatever the path spells
    assert rs._device_type(os.makedev(0, 99), MOUNTINFO) is None


@pytest.mark.skipif(sys.platform == "win32", reason="Linux reads the mount table")
def test_host_shares_mounted_in_a_linux_vm_are_refused(tmp_path, monkeypatch):
    (tmp_path / "corpus").mkdir()
    monkeypatch.setattr(rs, "_device_type", lambda device, mountinfo=None: "virtiofs")
    assert rs._is_synced(tmp_path / "corpus")
    monkeypatch.setattr(rs, "_device_type", lambda device, mountinfo=None: None)   # not listed:
    monkeypatch.setattr(rs, "_mount_type", lambda path, mounts=None: "9p")         # by path
    assert rs._is_synced(tmp_path / "corpus")
    monkeypatch.setattr(rs, "_mount_type", lambda path, mounts=None: "ext4")
    assert not rs._is_synced(tmp_path / "corpus")


def test_worker_pool_finishes_on_repeated_paths_without_false_failures(tmp_path):
    # Missing files fail fast, which used to expose a race that recorded
    # healthy items as "worker died"; a repeated path used to hang the loop.
    paths = [str(tmp_path / f"missing{i}.exe") for i in range(60)] + [str(tmp_path / "missing0.exe")]
    rows = benign_sweep.run(paths, jobs=2, use_yara=False, out_jsonl=tmp_path / "r.jsonl")
    assert len(rows) == 60
    assert not [r for r in rows if r.get("failure")]


def _within(seconds: int, call):
    """call(), failing rather than hanging if a regression in run() waits for ever."""
    if hasattr(signal, "SIGALRM"):   # POSIX: the alarm interrupts run() in this thread
        def expire(*_):
            raise TimeoutError(f"run() did not return within {seconds}s")
        previous = signal.signal(signal.SIGALRM, expire)
        signal.alarm(seconds)
        try:
            return call()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
    # Windows has no alarm; its workers are spawned, so a thread cannot upset a fork
    outcome: list = []

    def target():
        try:
            outcome.append((True, call()))
        except BaseException as exc:
            outcome.append((False, exc))

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    if not outcome:
        pytest.fail(f"run() did not return within {seconds}s")
    ok, value = outcome[0]
    if not ok:
        raise value
    return value


def _run(tmp_path, names, worker, **kw):
    items = [str(tmp_path / n) for n in names]
    started = time.monotonic()
    rows = _within(120, lambda: benign_sweep.run(items, use_yara=False, out_jsonl=tmp_path / "r.jsonl",
                                                 worker=worker, **kw))
    by_name = {Path(r["path"]).name: r for r in rows}
    assert len(rows) == len(names) == len(by_name)                 # each item exactly once
    lines = (tmp_path / "r.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(names)
    return by_name, time.monotonic() - started


def test_a_worker_that_dies_as_it_starts_is_a_failure_not_a_hang(tmp_path):
    # The start notice used to sit in a queue buffer that died with the
    # worker, and the sweep then waited for that item forever.
    names = [f"ok{i}" for i in range(6)] + ["die1", "die2"]
    rows, seconds = _run(tmp_path, names, sw.behaves_as_named, jobs=2, timeout=60)
    assert seconds < 45
    assert rows["die1"]["failure"] == "worker" and rows["die1"]["error"] == "worker died on this file"
    assert not [n for n in names if n.startswith("ok") and "error" in rows[n]]


def test_a_timed_out_item_keeps_the_hash_its_worker_reported(tmp_path):
    # Without its hash a timed-out sample could be neither split into the
    # held-out part nor matched to the manifest.
    rows, _ = _run(tmp_path, ["ok1", "slow1", "ok2", "ok3"], sw.behaves_as_named, jobs=2, timeout=3)
    slow = rows["slow1"]
    assert slow["failure"] == "timeout" and slow["error"] == "timeout after 3s"
    assert slow["sha256"] == hashlib.sha256(str(tmp_path / "slow1").encode()).hexdigest()
    assert all("error" not in rows[n] for n in ("ok1", "ok2", "ok3"))


def test_workers_are_replaced_after_their_share_without_losing_items(tmp_path):
    n = 2 * benign_sweep._TASKS_PER_WORKER + 5
    rows, _ = _run(tmp_path, [f"ok{i}" for i in range(n)], sw.behaves_as_named, jobs=1)
    assert not [r for r in rows.values() if "error" in r]
    assert len({r["process"] for r in rows.values()}) == 3


def test_an_item_lost_before_it_started_is_tried_again(tmp_path):
    rows, _ = _run(tmp_path, ["a", "b"], sw.dies_once_before_starting, jobs=1)
    assert all("error" not in r for r in rows.values())
    rows, _ = _run(tmp_path, ["late1"], sw.behaves_as_named, jobs=1)      # lost every time
    assert rows["late1"]["error"] == "worker died before starting this file"


def test_a_worker_that_dies_after_reading_the_hash_keeps_it(tmp_path):
    rows, _ = _run(tmp_path, ["ok1", "hashdie1"], sw.behaves_as_named, jobs=1)
    dead = rows["hashdie1"]
    sha = hashlib.sha256(str(tmp_path / "hashdie1").encode()).hexdigest()
    assert dead["failure"] == "worker" and dead["sha256"] == sha
    # ... so the recall summary splits it and counts it as a miss
    summary = rs.summarize([dead], {}, 0.3)
    assert summary["detection"][rs.split_of(sha, 0.3)]["intent_to_triage"] == rs.rate(0, 1)


def test_a_timeout_before_the_worker_started_is_a_timeout_tried_once(tmp_path):
    rows, _ = _run(tmp_path, ["sleepy1"], sw.behaves_as_named, jobs=1, timeout=2)
    assert rows["sleepy1"]["error"] == "timeout after 2s" and rows["sleepy1"]["failure"] == "timeout"
    attempts = tmp_path / "sleepy1.attempts"
    assert (attempts.read_text() if attempts.exists() else "") in ("", "x")


def test_a_worker_that_returns_no_row_is_an_error_at_once(tmp_path):
    rows, seconds = _run(tmp_path, ["none1", "ok1"], sw.behaves_as_named, jobs=1, timeout=60)
    assert rows["none1"]["error"] == "the worker returned NoneType, not a row" and seconds < 30
    assert "error" not in rows["ok1"]


def _process_gone(pid: int, within: float) -> bool:
    deadline = time.monotonic() + within
    if sys.platform == "win32":   # os.kill(pid, 0) would terminate it on Windows
        import _winapi
        try:
            handle = _winapi.OpenProcess(0x00100000, False, pid)   # SYNCHRONIZE
        except OSError:
            return True
        try:
            return _winapi.WaitForSingleObject(handle, int(within * 1000)) == 0
        finally:
            _winapi.CloseHandle(handle)
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        try:   # exited but not yet reaped by its new parent
            if Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "Z":
                return True
        except (OSError, IndexError):
            pass
        time.sleep(0.2)
    return False


def test_a_worker_on_a_hanging_file_exits_when_the_sweep_dies(tmp_path):
    # The timeout lives in the sweep process: if that is killed (by the OOM
    # killer, say), a worker stuck in a file must not run on for ever.
    here = Path(__file__).resolve().parent
    item, out = tmp_path / "hangpid1", tmp_path / "r.jsonl"
    script = tmp_path / "sweep.py"
    script.write_text(
        "import sys\n"
        f"sys.path[:0] = [{str(here)!r}, {str(here.parent / 'scripts')!r}]\n"
        "from pathlib import Path\n"
        "import _sweep_workers, benign_sweep\n"
        "if __name__ == '__main__':\n"
        f"    benign_sweep.run([{str(item)!r}], 1, False, Path({str(out)!r}),\n"
        "                     timeout=600, worker=_sweep_workers.behaves_as_named)\n",
        encoding="utf-8")
    sweep = subprocess.Popen([sys.executable, str(script)])
    pidfile = Path(str(item) + ".pid")
    try:
        deadline = time.monotonic() + 60
        while not pidfile.exists() and time.monotonic() < deadline and sweep.poll() is None:
            time.sleep(0.1)
        assert pidfile.exists(), "the worker never started"
        time.sleep(0.2)
    finally:
        sweep.kill()
        sweep.wait()
    worker = int(pidfile.read_text())
    assert _process_gone(worker, within=15), "the worker outlived the sweep"


def test_jobs_must_be_positive(tmp_path):
    with pytest.raises(ValueError):
        benign_sweep.run(["x"], jobs=0, use_yara=False, out_jsonl=tmp_path / "r.jsonl")


def test_failed_samples_with_a_hash_are_split_and_matched(tmp_path):
    held, tune = "0" * 64, "f" * 64                   # split_of: held out, tuning
    rows = [_row(40, sha=tune),
            {"path": "a.zip::0::x", "sha256": held, "error": "timeout after 120s", "failure": "timeout"}]
    summary = rs.summarize(rows, {held: {"family": "X"}, tune: {}}, 0.3)
    assert summary["detection"]["holdout"]["intent_to_triage"] == rs.rate(0, 1)
    assert summary["counts"]["in manifest, not in the corpus"] == 0


def test_zip_member_items_survive_colons_in_folder_and_member_names():
    assert rs._member("/lab::2025/set.ZIP::3::dir/a::b.exe") == ("/lab::2025/set.ZIP", 3, "dir/a::b.exe")
    assert rs._member("/lab::2025/sample.exe") is None


def test_what_was_left_out_before_triage_reaches_the_summary(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    _zip(corpus / "bz.zip", [("x.bin", b"x" * 100)], compression=zipfile.ZIP_BZIP2)
    _zip(corpus / "ok.zip", [("note.txt", b"not a PE")])
    rs.main(["--corpus", str(corpus), "--out", str(tmp_path / "out"), "--no-yara", "--jobs", "1"])
    summary = json.loads((tmp_path / "out" / "summary.json").read_text(encoding="utf-8"))
    assert summary["not_triaged"] == {"unsupported ZIP compression (bzip2/LZMA)": 1}
    assert "Not triaged" in (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")
    rs.main(["--report", str(tmp_path / "out" / "results.jsonl"), "--out", str(tmp_path / "again")])
    again = json.loads((tmp_path / "again" / "summary.json").read_text(encoding="utf-8"))
    assert again["not_triaged"] == summary["not_triaged"]


def test_code_hash_ignores_line_endings(tmp_path):
    lf, crlf = tmp_path / "lf", tmp_path / "crlf"
    for root, eol in ((lf, b"\n"), (crlf, b"\r\n")):
        (root / "rules").mkdir(parents=True)
        (root / "engine.py").write_bytes(eol.join([b"x = 1", b"y = 2", b""]))
        (root / "rules" / "a.yar").write_bytes(eol.join([b"rule a { condition: true }", b""]))
    assert benign_sweep._code_hash(lf) == benign_sweep._code_hash(crlf)
    (crlf / "engine.py").write_bytes(b"x = 1\r\ny = 3\r\n")
    assert benign_sweep._code_hash(lf) != benign_sweep._code_hash(crlf)


def test_mounts_inside_the_corpus_are_checked_where_they_start(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"
    (corpus / "share" / "deeper").mkdir(parents=True)
    (corpus / "share" / "deeper" / "a.bin").write_bytes(b"x")
    (corpus / "mounted.bin").write_bytes(b"x")
    real_stat = os.stat
    other = {"share": 1, "deeper": 1, "a.bin": 1, "mounted.bin": 2}   # device offsets

    def stat(path, *args, **kwargs):
        st = real_stat(path, *args, **kwargs)
        offset = other.get(Path(path).name)
        if not offset:
            return st
        fields = list(st[:10])
        fields[2] += offset
        return os.stat_result(fields)

    checked = []
    monkeypatch.setattr(os, "stat", stat)
    monkeypatch.setattr(rs, "_refuse_synced", checked.append)
    items, _, _ = rs.collect(corpus, max_bytes=1024)
    assert len(items) == 2
    # once per filesystem, where it starts: a mounted folder, and a file mounted on its own
    assert checked == [Path(str(corpus / "mounted.bin")), Path(str(corpus / "share"))]


needs_permissions = pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="POSIX permissions, as a user they bind")


@needs_permissions
def test_unreadable_folders_are_counted_and_an_unreadable_corpus_is_refused(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "locked").mkdir(parents=True)
    (corpus / "locked" / "a.bin").write_bytes(b"x")
    (corpus / "own.bin").write_bytes(b"x")
    (corpus / "locked").chmod(0)
    try:
        items, skipped, _ = rs.collect(corpus, max_bytes=1024)
        assert len(items) == 1 and skipped == {"unreadable folder": 1}
        corpus.chmod(0)
        with pytest.raises(SystemExit, match="cannot list the corpus folder"):
            rs.collect(corpus, max_bytes=1024)
    finally:
        corpus.chmod(0o755)
        (corpus / "locked").chmod(0o755)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows feature")
def test_junctions_are_linked_folders_on_windows(tmp_path):
    import _winapi

    store = tmp_path / "store"
    store.mkdir()
    (store / "a.bin").write_bytes(b"x")
    synced = tmp_path / "OneDrive"
    synced.mkdir()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "own.bin").write_bytes(b"x")
    _winapi.CreateJunction(str(store), str(corpus / "local"))
    items, skipped, _ = rs.collect(corpus, max_bytes=1024)
    assert len(items) == 1 and skipped == {"linked folder (not followed)": 1}
    _winapi.CreateJunction(str(synced), str(corpus / "cloud"))
    with pytest.raises(SystemExit):
        rs.collect(corpus, max_bytes=1024)


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links need privileges on Windows")
def test_linked_folders_are_counted_and_loops_are_unreadable(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    (store / "a.bin").write_bytes(b"x")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "2024").symlink_to(store, target_is_directory=True)
    (corpus / "loop").symlink_to(corpus / "loop")
    items, skipped, _ = rs.collect(corpus, max_bytes=1024)
    assert items == []
    assert skipped == {"linked folder (not followed)": 1, "unreadable file": 1}
    synced = tmp_path / "OneDrive"
    synced.mkdir()
    (corpus / "cloud").symlink_to(synced, target_is_directory=True)
    with pytest.raises(SystemExit):
        rs.collect(corpus, max_bytes=1024)


def _vendored_pe():
    """pip's Windows launcher stub: a benign PE present wherever pip is."""
    try:
        import pip
    except ImportError:
        return None
    exe = Path(pip.__file__).parent / "_vendor" / "distlib" / "t64.exe"
    return exe if exe.is_file() else None


LAUNCHER = _vendored_pe()


@pytest.mark.skipif(LAUNCHER is None, reason="pip's vendored launcher (a benign PE) not found")
def test_a_real_pe_goes_through_the_recall_run_with_yara_when_installed(tmp_path):
    # On Linux every other test that triages a PE needs Windows' own files:
    # this is the one that checks the engine, and YARA, where the lab runs.
    try:
        import yara  # noqa: F401
        use_yara = True
    except ImportError:
        use_yara = False
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    _zip(corpus / "launcher.zip", [("t64.exe", LAUNCHER.read_bytes())])
    out = tmp_path / "out"
    rs.main(["--corpus", str(corpus), "--out", str(out), "--jobs", "1"]
            + ([] if use_yara else ["--no-yara"]))
    rows = [json.loads(line) for line in (out / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1 and "error" not in rows[0]
    assert rows[0]["sha256"] == hashlib.sha256(LAUNCHER.read_bytes()).hexdigest()
    assert rows[0]["yara"] is use_yara and rows[0]["verdict"] in ("LIKELY_CLEAN", "SUSPICIOUS", "HIGH_RISK")


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links need privileges on Windows")
def test_a_link_out_to_a_synced_folder_is_refused(tmp_path):
    synced = tmp_path / "OneDrive"
    synced.mkdir()
    (synced / "sample.bin").write_bytes(b"x")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "sample.bin").symlink_to(synced / "sample.bin")
    with pytest.raises(SystemExit):
        rs.collect(corpus, max_bytes=1024)
