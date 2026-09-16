"""Build a harmless demo file that LOOKS malicious, so you can watch gokdogan work.

It takes a clean Windows binary (notepad.exe by default) and appends a set of
suspicious-looking *bytes* after it: an XOR-encoded C2 URL, injection API
names, a ransomware command, a Discord webhook, a Run-key path and a fake
second-stage PE in the overlay. Nothing here is executable malware -- it is
notepad plus inert trailing data, and gokdogan never runs samples anyway.
Delete the output file when you are done.

    python examples/make_demo_sample.py          # -> demo_suspicious.exe
    gokdogan demo_suspicious.exe
    gokdogan demo_suspicious.exe --html report.html
"""

from __future__ import annotations

import argparse
from pathlib import Path

DEFAULT_HOST = r"C:\Windows\System32\notepad.exe"


def _xor(text: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in text)


def build(host: Path, out: Path) -> None:
    data = bytearray(host.read_bytes())

    # 1) C2 URL hidden behind a single-byte XOR key -> exercises decoded.py.
    #    Isolated by non-printable padding so it decodes as its own string.
    data += b"\xff" * 8 + _xor(b"http://45.77.10.9:8443/panel/gate.php", 0x5A) + b"\xff" * 8

    # 2) A Discord webhook, also XOR-encoded -> exercises extractors.py.
    data += b"\xff" * 8 + _xor(b"https://discord.com/api/webhooks/998877/SeCrEt-token_AbCdEf", 0x5A) + b"\xff" * 8

    # 3) Plain suspicious strings -> command / registry / anti-recovery signals.
    data += b"\x00cmd.exe /c vssadmin delete shadows /all /quiet\x00"
    data += b"\x00SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    data += b"\x00VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"

    # 4) A fake second-stage PE in the overlay -> exercises overlay.py (dropper).
    data += b"MZ" + b"\x90" * 4000 + b"This program cannot be run in DOS mode"

    out.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="clean PE to base the demo on (default: notepad.exe)")
    parser.add_argument("-o", "--out", default="demo_suspicious.exe",
                        help="output path (default: demo_suspicious.exe)")
    args = parser.parse_args()

    host = Path(args.host)
    if not host.is_file():
        parser.error(f"host binary not found: {host}")
    out = Path(args.out)
    build(host, out)
    print(f"wrote {out} ({out.stat().st_size:,} bytes) -- triage it with:  gokdogan {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
