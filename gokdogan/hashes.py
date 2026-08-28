"""Extra clustering hashes: authentihash and impfuzzy.

- **authentihash** is the SHA-256 an Authenticode signature is computed over:
  the whole file *except* the optional-header checksum, the certificate-table
  data-directory entry, and the certificate table (overlay signature) itself.
  Two builds that differ only in their signature share it — useful for
  matching re-signed variants and unsigned/signed pairs of the same binary.

- **impfuzzy** applies ssdeep to the normalized import list, so samples with
  *similar* (not identical) import tables cluster together where the crisp
  imphash would not.
"""

from __future__ import annotations

import hashlib

from .fuzzy import ssdeep_hash


def authentihash(pe, data: bytes) -> str | None:
    """SHA-256 authentihash (signature-independent PE hash)."""
    try:
        opt_offset = pe.OPTIONAL_HEADER.get_file_offset()
        is_pe32_plus = pe.OPTIONAL_HEADER.Magic == 0x20B
        checksum_offset = opt_offset + 64          # CheckSum field
        data_dir_offset = opt_offset + (112 if is_pe32_plus else 96)
        cert_entry_offset = data_dir_offset + 4 * 8  # DATA_DIRECTORY[4] = SECURITY

        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        cert_offset = security.VirtualAddress       # file offset for the cert table
        cert_size = security.Size
    except Exception:  # pragma: no cover - defensive
        return None

    h = hashlib.sha256()
    # 1) start .. checksum
    h.update(data[:checksum_offset])
    # 2) after checksum .. cert-table directory entry
    h.update(data[checksum_offset + 4:cert_entry_offset])
    if cert_offset and cert_size:
        # 3) after cert entry .. start of cert table
        h.update(data[cert_entry_offset + 8:cert_offset])
        # 4) anything after the cert table (usually nothing)
        h.update(data[cert_offset + cert_size:])
    else:
        # unsigned: cert entry is zero anyway; hash the rest of the file
        h.update(data[cert_entry_offset + 8:])
    return h.hexdigest()


def impfuzzy(imports: dict[str, list[str]]) -> str | None:
    """ssdeep hash of the normalized import list (JPCERT impfuzzy style)."""
    if not imports:
        return None
    parts: list[str] = []
    for dll in sorted(imports):
        base = dll.rsplit(".", 1)[0].lower()
        for func in imports[dll]:
            parts.append(f"{base}.{func.lower()}")
    if not parts:
        return None
    return ssdeep_hash(",".join(parts).encode())
