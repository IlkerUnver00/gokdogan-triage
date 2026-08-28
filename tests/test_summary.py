import csv
import io
import json

from gokdogan.models import (
    AttackTechnique,
    Capability,
    ConfigBlob,
    DecodedString,
    FileInfo,
    PackerInfo,
    RichHeader,
    TriageReport,
    Verdict,
    YaraHit,
)
from gokdogan.summary import FIELDS, csv_string, summary_row, write_csv, write_jsonl


def _report():
    fi = FileInfo(
        path="evil.exe", size=4096, md5="0" * 32, sha1="0" * 40, sha256="a" * 64,
        imphash="i" * 32, ssdeep="3:abc:d", tlsh=None, file_type="PE32 executable (GUI) x86",
        compile_timestamp=None, compile_timestamp_anomaly=None, is_dll=False,
        is_driver=False, is_signed=False, entry_point=0x1000, entry_section=".text",
    )
    return TriageReport(
        file=fi,
        rich=RichHeader(hash="r" * 32, xor_key="0x1"),
        packer=PackerInfo(detected=True, names=["UPX"]),
        anomalies=["overlay big", "no import table"],
        decoded_strings=[DecodedString("<embedded PE, 200 bytes>", "base64", "embedded-pe", 0)],
        config_blobs=[ConfigBlob(".data", 0x2000, 4096, 7.9)],
        capabilities=[
            Capability("process-injection", "", 3, [], attack=["T1055"]),
            Capability("network", "", 2, [], attack=["T1071"]),
        ],
        attack=[
            AttackTechnique("T1055", "Process Injection", "Defense Evasion", ["process-injection"]),
            AttackTechnique("T1071", "Application Layer Protocol", "Command and Control", ["network"]),
        ],
        yara=[YaraHit(rule="Injection_API_Cluster")],
        score=88, verdict=Verdict.HIGH_RISK,
    )


def test_summary_row_fields():
    row = summary_row(_report())
    assert row["sha256"] == "a" * 64
    assert row["verdict"] == "HIGH_RISK"
    assert row["score"] == 88
    assert row["packer"] == "UPX"
    assert row["rich_hash"] == "r" * 32
    assert row["capabilities"] == ["process-injection", "network"]
    assert row["attack"] == ["T1055", "T1071"]
    assert row["yara"] == ["Injection_API_Cluster"]
    assert row["embedded_pe"] is True
    assert row["config_blobs"] == 1
    assert row["anomalies"] == 2


def test_csv_flattens_lists_and_bools():
    text = csv_string([summary_row(_report())])
    reader = list(csv.DictReader(io.StringIO(text)))
    assert len(reader) == 1
    row = reader[0]
    # header matches declared field order
    assert list(row.keys()) == FIELDS
    assert row["capabilities"] == "process-injection; network"
    assert row["attack"] == "T1055; T1071"
    assert row["embedded_pe"] == "yes"


def test_write_csv_and_jsonl(tmp_path):
    rows = [summary_row(_report())]
    csv_path = tmp_path / "out.csv"
    jsonl_path = tmp_path / "out.jsonl"
    write_csv(rows, csv_path)
    write_jsonl(rows, jsonl_path)

    csv_rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert csv_rows[0]["verdict"] == "HIGH_RISK"

    lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    # JSONL keeps list fields as arrays, not joined strings
    assert obj["capabilities"] == ["process-injection", "network"]
    assert obj["embedded_pe"] is True
