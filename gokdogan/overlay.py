"""Overlay analysis.

An *overlay* is data appended after the last section — outside the mapped
image. Legitimately it carries the Authenticode signature or an installer's
payload; maliciously it is where droppers stash a second-stage executable
or an encrypted blob that the stub reads at runtime. gokdogan already flags
an oversized overlay as an anomaly; this module looks *inside* it: magic-byte
file-type guess, entropy, and whether it contains an embedded PE.
"""

from __future__ import annotations

import pefile

from .entropy import shannon_entropy
from .models import OverlayInfo

# Leading magic bytes -> human file-type label.
_MAGICS: list[tuple[bytes, str]] = [
    (b"MZ", "PE/DOS executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "gzip"),
    (b"MSCF", "CAB archive"),
    (b"ITSF", "CHM help"),
    (b"%PDF", "PDF"),
    (b"\x89PNG", "PNG image"),
    (b"BM", "BMP image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x30\x82", "DER/PKCS certificate"),
]

_DOS_STUB = b"This program cannot be run in DOS mode"


def _type_guess(chunk: bytes) -> str:
    for magic, label in _MAGICS:
        if chunk.startswith(magic):
            return label
    return "unknown"


def analyze_overlay(pe: pefile.PE, data: bytes) -> OverlayInfo | None:
    """Return an OverlayInfo, or None if the file has no overlay."""
    try:
        offset = pe.get_overlay_data_start_offset()
    except Exception:  # pragma: no cover - defensive
        offset = None
    if offset is None or offset >= len(data):
        return None

    overlay = data[offset:]
    size = len(overlay)
    if size == 0:
        return None

    # The security directory blob legitimately lives in the overlay.
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    is_signature = size <= max(security_dir.Size, 0) + 16

    contains_pe = overlay[:2] == b"MZ" or _DOS_STUB in overlay[:4096]

    return OverlayInfo(
        offset=offset,
        size=size,
        pct=round(100 * size / len(data), 1),
        entropy=round(shannon_entropy(overlay), 3),
        type_guess=_type_guess(overlay),
        contains_pe=contains_pe,
        is_signature=is_signature,
    )


def overlay_anomalies(info: OverlayInfo | None) -> list[str]:
    if info is None or info.is_signature:
        return []
    notes: list[str] = []
    if info.contains_pe:
        notes.append(f"overlay contains an embedded executable ({info.size} bytes)")
    elif info.type_guess != "unknown":
        notes.append(f"overlay is a {info.type_guess} ({info.size} bytes, {info.pct}% of file)")
    elif info.entropy >= 7.2:
        notes.append(f"high-entropy overlay ({info.size} bytes, entropy {info.entropy:.2f})")
    return notes
