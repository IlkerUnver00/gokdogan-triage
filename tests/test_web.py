from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from gokdogan.web import app  # noqa: E402

client = TestClient(app)

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
has_notepad = pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")


def test_index_serves_upload_form():
    r = client.get("/")
    assert r.status_code == 200
    assert "gokdogan" in r.text
    assert "<form" in r.text


def test_rejects_non_pe():
    r = client.post("/triage", files={"file": ("x.bin", b"not a pe", "application/octet-stream")})
    assert r.status_code == 400


@has_notepad
def test_triage_html_upload():
    with open(NOTEPAD, "rb") as fh:
        r = client.post("/triage", files={"file": ("notepad.exe", fh, "application/octet-stream")})
    assert r.status_code == 200
    assert "notepad.exe" in r.text
    assert "Verdict rationale" in r.text or "LIKELY CLEAN" in r.text


@has_notepad
def test_triage_json_api():
    with open(NOTEPAD, "rb") as fh:
        r = client.post("/api/triage", files={"file": ("notepad.exe", fh, "application/octet-stream")})
    assert r.status_code == 200
    body = r.json()
    assert body["file"]["sha256"]
    assert body["verdict"] in ("LIKELY_CLEAN", "SUSPICIOUS", "HIGH_RISK")


def test_rejects_oversized_upload(monkeypatch):
    import gokdogan.web as web
    monkeypatch.setattr(web, "MAX_UPLOAD_BYTES", 1024)  # shrink the cap for the test
    big = b"MZ" + b"\x00" * 4096
    r = client.post("/triage", files={"file": ("big.exe", big, "application/octet-stream")})
    assert r.status_code == 413
