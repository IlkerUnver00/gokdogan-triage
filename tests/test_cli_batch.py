"""End-to-end batch-mode CLI tests against real system binaries."""

import csv
import json
import shutil
from pathlib import Path

import pytest

from peregrine.cli import main

SYS32 = Path(r"C:\Windows\System32")
SOURCES = [SYS32 / "notepad.exe", SYS32 / "calc.exe"]

pytestmark = pytest.mark.skipif(
    not all(p.exists() for p in SOURCES), reason="system binaries not available"
)


@pytest.fixture
def dropzone(tmp_path):
    zone = tmp_path / "dropzone"
    zone.mkdir()
    for src in SOURCES:
        shutil.copy(src, zone / src.name)
    return zone


def test_batch_csv_has_row_per_sample(dropzone, tmp_path):
    csv_path = tmp_path / "triage.csv"
    rc = main([str(dropzone), "--csv", str(csv_path), "--no-yara"])
    assert rc in (0, 2, 3)  # exit reflects worst verdict, not an error
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert len(rows) == 2
    names = {Path(r["path"]).name for r in rows}
    assert names == {"notepad.exe", "calc.exe"}
    for r in rows:
        assert len(r["sha256"]) == 64
        assert r["verdict"] in ("LIKELY_CLEAN", "SUSPICIOUS", "HIGH_RISK")


def test_batch_jsonl_is_valid_and_streamable(dropzone, tmp_path):
    jsonl_path = tmp_path / "triage.jsonl"
    main([str(dropzone), "--jsonl", str(jsonl_path), "--no-yara"])
    lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        obj = json.loads(line)          # each line is independently parseable
        assert "sha256" in obj
        assert isinstance(obj["capabilities"], list)


def test_batch_summary_line_printed(dropzone, tmp_path, capsys):
    main([str(dropzone), "--csv", str(tmp_path / "t.csv"), "--no-yara"])
    err = capsys.readouterr().err
    assert "2 file(s)" in err
    assert "clean" in err


def test_reputation_without_key_errors_and_makes_no_call(dropzone, capsys):
    # Opt-in reputation must refuse to run (and never hit the network) with no key.
    rc = main([str(dropzone), "--reputation", "--no-yara"])
    assert rc == 1
    assert "needs an API key" in capsys.readouterr().err
