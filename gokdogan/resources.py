"""Resource (.rsrc) walker.

Droppers and packers love the resource directory: it is a natural place
to stash a second-stage executable or an encrypted configuration blob,
because resources are opaque to most quick looks and don't disturb the
import table. This walker enumerates every resource, hashes it, measures
its entropy, and flags the two things that matter for triage:

  * an **embedded PE** — a whole executable carried as a resource, the
    classic dropper shape;
  * a **high-entropy blob** — a compressed/encrypted payload waiting to be
    unpacked at runtime.

Every level of the walk is defensively wrapped: malware frequently mangles
the resource tree, and a triage tool must survive a corrupt directory and
report what it *could* read rather than crashing.
"""

from __future__ import annotations

import hashlib

import pefile

from .entropy import HIGH_ENTROPY, shannon_entropy
from .models import ResourceInfo

# Cap the number of resource leaves we walk, so a pathological or hostile
# resource tree can't turn triage into a hang.
_MAX_RESOURCES = 4096

# Resources whose *declared* type is inert (icons, strings, version info)
# but which nonetheless carry an executable are a strong dropper tell.
_INERT_TYPES = {
    "RT_ICON", "RT_GROUP_ICON", "RT_CURSOR", "RT_GROUP_CURSOR",
    "RT_BITMAP", "RT_STRING", "RT_VERSION", "RT_MANIFEST",
}

# Types that are *legitimately* compressed, so high entropy is expected and
# must not be treated as a packed-payload signal. Modern high-resolution
# icons and cursors embed PNG/compressed image data (~7.9 bits/byte).
_COMPRESSED_OK_TYPES = {
    "RT_ICON", "RT_GROUP_ICON", "RT_CURSOR", "RT_GROUP_CURSOR",
    "RT_BITMAP", "RT_ANIICON", "RT_ANICURSOR",
}

# Media formats that are compressed by design. A resource that is one is
# expected to be near-random whatever type it is filed under: MFC and Office
# store hundreds of PNGs under a custom "PNG" type, not RT_ICON. Archives
# (ZIP, CAB, gzip, 7z, ...) stay flagged: a compressed second stage is what a
# dropper carries, and only 5 of 2,888 benign binaries swept carry one.
_RIFF_FORMS = (b"WAVE", b"AVI ", b"ACON", b"WEBP", b"RMID")


def _is_compressed_media(data: bytes) -> bool:
    """True for a resource with the header of a compressed image, sound or font.

    The checks go a little past the magic (the PNG header chunk, the RIFF
    size and form, the JPEG end marker). They only raise the bar: a forged
    header still passes, much as filing a blob under RT_BITMAP always did.
    """
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return data[8:16] == b"\x00\x00\x00\x0dIHDR"
    if data.startswith(b"RIFF"):
        size = int.from_bytes(data[4:8], "little")
        return data[8:12] in _RIFF_FORMS and len(data) - 16 <= size + 8 <= len(data)
    if data.startswith(b"\xff\xd8\xff"):
        return data.rstrip(b"\x00").endswith(b"\xff\xd9")
    if data.startswith(b"ID3"):
        return data[3:4] in (b"\x02", b"\x03", b"\x04")
    return data.startswith((b"GIF87a", b"GIF89a", b"OggS\x00", b"wOFF", b"wOF2"))

_DOS_STUB_MARKER = b"This program cannot be run in DOS mode"


def _type_name(type_entry) -> str:
    if getattr(type_entry, "name", None) is not None:
        return str(type_entry.name)
    return pefile.RESOURCE_TYPE.get(type_entry.id, f"type {type_entry.id}")


def _res_name(res_entry) -> str:
    if getattr(res_entry, "name", None) is not None:
        return str(res_entry.name)
    return str(res_entry.id)


def _looks_like_pe(data: bytes) -> bool:
    """True if the buffer begins with a valid-enough PE (MZ + PE header)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    return 0 < e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"


def _classify_resource(type_name: str, data: bytes, entropy: float) -> list[str]:
    flags: list[str] = []
    embedded = _looks_like_pe(data)
    if embedded:
        flags.append("embedded PE executable")
    elif _DOS_STUB_MARKER in data:
        # A PE not anchored at offset 0 (prefixed / concatenated).
        flags.append("contains an embedded executable (DOS stub found)")
    # High entropy is only a signal where it's unexpected; compressed image
    # resources (PNG icons) are legitimately near-random.
    if (entropy >= HIGH_ENTROPY and type_name not in _COMPRESSED_OK_TYPES
            and not _is_compressed_media(data)):
        flags.append(f"high entropy {entropy:.2f} (packed/encrypted)")
    # Type mismatch = a declared-inert resource that actually carries a PE.
    if embedded and type_name in _INERT_TYPES:
        flags.append(f"content/type mismatch (declared {type_name})")
    return flags


def walk_resources(pe: pefile.PE) -> list[ResourceInfo]:
    """Enumerate resources, returning one ResourceInfo per leaf."""
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return []

    results: list[ResourceInfo] = []
    for type_entry in getattr(root, "entries", []):
        if len(results) >= _MAX_RESOURCES:
            break
        try:
            type_name = _type_name(type_entry)
            for res_entry in getattr(type_entry.directory, "entries", []):
                name = _res_name(res_entry)
                for lang in getattr(res_entry.directory, "entries", []):
                    if len(results) >= _MAX_RESOURCES:
                        break
                    info = _read_leaf(pe, type_name, name, lang)
                    if info is not None:
                        results.append(info)
        except Exception:
            # A corrupt subtree shouldn't sink the rest of the walk.
            continue
    return results


def _read_leaf(pe: pefile.PE, type_name: str, name: str, lang) -> ResourceInfo | None:
    try:
        struct = lang.data.struct
        size = struct.Size
        offset = struct.OffsetToData
        data = pe.get_data(offset, size)
    except Exception:
        return None

    language = f"{getattr(lang.data, 'lang', 0)}/{getattr(lang.data, 'sublang', 0)}"
    entropy = round(shannon_entropy(data), 3)
    flags = _classify_resource(type_name, data, entropy)
    return ResourceInfo(
        type=type_name,
        name=name,
        language=language,
        size=size,
        entropy=entropy,
        sha256=hashlib.sha256(data).hexdigest(),
        flags=flags,
    )


def resource_anomalies(resources: list[ResourceInfo]) -> list[str]:
    """Structural notes to fold into the report's anomaly list."""
    embedded = [(r, f) for r in resources for f in r.flags
                if f.startswith("embedded PE") or f.startswith("contains an embedded")]
    packed = [(r, f) for r in resources for f in r.flags if f.startswith("high entropy")]
    # One note per kind, not per resource: forty encrypted resources are one
    # fact about the file, and scoring them forty times buried real signals.
    return [_one_note(hits, label) for hits, label in
            ((embedded, "carry an embedded executable"),
             (packed, "are high-entropy (packed/encrypted)")) if hits]


def _one_note(hits: list, label: str) -> str:
    if len(hits) == 1:
        r, flag = hits[0]
        return f"resource {r.type}/{r.name}: {flag}"
    examples = ", ".join(f"{r.type}/{r.name}" for r, _ in hits[:3])
    more = f", +{len(hits) - 3} more" if len(hits) > 3 else ""
    return f"{len(hits)} resources {label}: {examples}{more}"
