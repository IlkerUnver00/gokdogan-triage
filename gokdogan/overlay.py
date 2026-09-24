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
from .loader import data_directory
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


# Below this many unauthenticated bytes the certificate table is left alone:
# stray alignment bytes from real signers (a lone 0x5c after a driver's DER
# blob, say) are not a payload, and flagging them costs the signature credit.
MIN_HIDDEN_BYTES = 16

_WIN_CERT_REVISION_2_0 = 0x0200
_WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


def _ber_end(blob: bytes, pos: int = 0, depth: int = 0) -> int | None:
    """Offset just past the BER TLV at pos, following indefinite lengths.

    Returns None when the encoding is malformed or nests absurdly deep, so a
    header rewritten to indefinite length (30 80 ... 00 00) cannot hide what
    comes after the real end of the signature.
    """
    if depth > 64 or pos + 2 > len(blob):
        return None
    tag = blob[pos]
    pos += 1
    if tag & 0x1F == 0x1F:                      # high-tag-number form
        while pos < len(blob) and blob[pos] & 0x80:
            pos += 1
        pos += 1
    if pos >= len(blob):
        return None
    first = blob[pos]
    pos += 1
    if first == 0x80:                           # indefinite length: constructed only
        if not tag & 0x20:
            return None
        while pos + 2 <= len(blob):
            if blob[pos] == 0 and blob[pos + 1] == 0:
                return pos + 2
            child_end = _ber_end(blob, pos, depth + 1)
            if child_end is None:
                return None
            pos = child_end
        return None
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(blob):
            return None
        length = int.from_bytes(blob[pos:pos + n], "big")
        pos += n
    end = pos + length
    return end if end <= len(blob) else None


def _unexplained(slack: bytes) -> int:
    """Bytes of slack that could carry data.

    Zero fill never can, and up to 7 zero bytes of 8-byte alignment at the end
    are normal, so neither is counted.
    """
    if not any(slack):
        return 0
    zeros = len(slack) - len(slack.rstrip(bytes(1)))
    return len(slack) - min(zeros, 7)


def _cert_table_slack(table: bytes) -> int:
    """Bytes in a WIN_CERTIFICATE table that are not the Authenticode signature.

    WinVerifyTrust does not hash the certificate table, so data placed in it
    keeps the signature "valid": the CVE-2013-3900 trick behind the 3CX DLL.
    Only the first revision-2.0 PKCS_SIGNED_DATA entry is the signature, and
    only up to the real end of its (DER or BER) blob. Everything else counts:
    bytes after that blob, every other entry in full, and a trailing tail.
    """
    hidden = 0
    pos = 0
    signature_seen = False
    while pos + 8 <= len(table):
        length = int.from_bytes(table[pos:pos + 4], "little")
        revision = int.from_bytes(table[pos + 4:pos + 6], "little")
        cert_type = int.from_bytes(table[pos + 6:pos + 8], "little")
        if length < 8 or pos + length > len(table):
            break
        end = min(pos + ((length + 7) & ~7), len(table))
        body = table[pos + 8:pos + length]
        if (not signature_seen and revision == _WIN_CERT_REVISION_2_0
                and cert_type == _WIN_CERT_TYPE_PKCS_SIGNED_DATA):
            signature_seen = True
            blob_end = _ber_end(body)
            if blob_end is None:
                hidden += _unexplained(table[pos + 8:end])
            else:
                hidden += _unexplained(table[pos + 8 + blob_end:end])
        else:
            hidden += _unexplained(table[pos + 8:end])
        pos = end
    return hidden + _unexplained(table[pos:])


def cert_table_padding(pe: pefile.PE, data: bytes) -> int:
    """Count bytes in the Authenticode certificate table that are not the signature."""
    security_dir = data_directory(pe, "IMAGE_DIRECTORY_ENTRY_SECURITY")
    if security_dir is None:
        return 0
    # The security directory's VirtualAddress is a file offset, not an RVA.
    start, size = security_dir.VirtualAddress, security_dir.Size
    if not start or not size or start + size > len(data):
        return 0
    return _cert_table_slack(data[start:start + size])


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
    security_dir = data_directory(pe, "IMAGE_DIRECTORY_ENTRY_SECURITY")
    signature_size = security_dir.Size if security_dir is not None else 0
    is_signature = size <= max(signature_size, 0) + 16

    contains_pe = overlay[:2] == b"MZ" or _DOS_STUB in overlay[:4096]

    return OverlayInfo(
        offset=offset,
        size=size,
        pct=round(100 * size / len(data), 1),
        entropy=round(shannon_entropy(overlay), 3),
        type_guess=_type_guess(overlay),
        contains_pe=contains_pe,
        is_signature=is_signature,
        cert_padding=cert_table_padding(pe, data),
    )


def overlay_anomalies(info: OverlayInfo | None) -> list[str]:
    if info is None:
        return []
    notes: list[str] = []
    if info.cert_padding >= MIN_HIDDEN_BYTES:
        notes.append(f"{info.cert_padding} bytes of unauthenticated data in the "
                     "Authenticode certificate table (CVE-2013-3900)")
    if info.is_signature:
        return notes
    if info.contains_pe:
        notes.append(f"overlay contains an embedded executable ({info.size} bytes)")
    elif info.type_guess != "unknown":
        notes.append(f"overlay is a {info.type_guess} ({info.size} bytes, {info.pct}% of file)")
    elif info.entropy >= 7.2:
        notes.append(f"high-entropy overlay ({info.size} bytes, entropy {info.entropy:.2f})")
    return notes
