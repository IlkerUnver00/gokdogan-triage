"""Upload-and-triage web service (optional).

A tiny FastAPI app: drop a PE in the browser, get the full HTML report back;
or POST to ``/api/triage`` for the JSON. Triage is static — the uploaded
sample is written to a temp file, parsed, and deleted; it is **never
executed** and no network call is made — so accepting untrusted uploads is
safe. Requires the ``web`` extra:

    pip install -e ".[web]"
    uvicorn gokdogan.web:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import os
import tempfile

from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from . import __version__
from .engine import NotAPEError, triage
from .html_report import render_html

app = FastAPI(title="gokdogan", version=__version__)

# Largest upload accepted. PEs are rarely over a few tens of MB; the cap keeps
# a hostile client from pushing the process into swap with a huge body.
MAX_UPLOAD_BYTES = 64 * 1024 * 1024

_INDEX = """<!doctype html><html><head><meta charset="utf-8">
<title>gokdogan</title><style>
body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:60px auto;padding:0 20px;
background:#0f141a;color:#e7ebf0}
h1{font-family:ui-monospace,monospace}
.card{background:#151b22;border:1px solid #28313c;border-radius:12px;padding:28px;margin-top:20px}
input[type=file]{margin:14px 0}
button{background:#2c6d9e;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:15px;cursor:pointer}
.muted{color:#8b95a1;font-size:14px}
</style></head><body>
<h1>🦅 gokdogan</h1>
<p class="muted">Static PE malware triage. The sample is analyzed without being executed.</p>
<div class="card">
<form action="/triage" method="post" enctype="multipart/form-data">
<label>Choose a Windows executable (.exe / .dll):</label><br>
<input type="file" name="file" required><br>
<button type="submit">Triage</button>
</form>
</div>
<p class="muted">API: <code>POST /api/triage</code> (multipart file) returns JSON.</p>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _INDEX


async def _read_limited(file: UploadFile) -> bytes | None:
    """Read an upload in chunks; return None as soon as it exceeds the cap."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _triage_upload(data: bytes, filename: str = "upload"):
    """Write the upload to a temp file, triage it, and clean up.

    The report's path is set back to the uploaded filename so the output
    shows the real name rather than a throwaway temp path.
    """
    fd, path = tempfile.mkstemp(suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        report = triage(path)
        report.file.path = filename or "upload"
        return report
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


@app.post("/triage", response_class=HTMLResponse)
async def triage_html(file: UploadFile = File(...)):
    data = await _read_limited(file)
    if data is None:
        return HTMLResponse(f"<p>File too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).</p>",
                            status_code=413)
    try:
        report = _triage_upload(data, file.filename or "upload")
    except NotAPEError as exc:
        return HTMLResponse(f"<p>Not a valid PE file: {exc}</p>", status_code=400)
    return render_html(report)


@app.post("/api/triage")
async def triage_json(file: UploadFile = File(...)):
    data = await _read_limited(file)
    if data is None:
        return JSONResponse({"error": f"file too large (limit {MAX_UPLOAD_BYTES} bytes)"}, status_code=413)
    try:
        report = _triage_upload(data, file.filename or "upload")
    except NotAPEError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(report.to_dict())
