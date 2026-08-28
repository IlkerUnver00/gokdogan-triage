"""Config-blob spotting: high-entropy islands inside calm sections.

Malware that stores an encrypted configuration or a staged payload often
drops it as a contiguous blob inside an ordinary writable data section
(``.data``). The section as a whole looks normal — mostly low-entropy
strings and tables — but a localized region spikes to near-random. That
*entropy island* is where the encrypted config/payload lives.

This module slides a window across each writable, non-executable section
and reports islands that stand out from a calm host. Sections that are
uniformly high-entropy are left to the packer/section analysis; ``.rsrc``
is left to the resource walker; read-only ``.rdata`` is skipped because it
legitimately carries high-entropy certificate/constant data (verified to
false-positive on stock signed system binaries otherwise). The goal is to
say "there is something encrypted hiding at this offset" without
decrypting it.
"""

from __future__ import annotations

from .entropy import shannon_entropy
from .models import ConfigBlob

# A 512-byte window is the smallest that measures entropy stably: 256 bytes
# is too few samples over 256 symbols, so even truly-random data averages
# ~7.17 bits and would slip under any sane threshold. At 512 bytes random
# data sits at ~7.5+, so 7.4 cleanly separates encrypted/compressed blobs
# from structured data.
_WINDOW = 512
_STEP = 256            # overlap for position resolution
_ISLAND_ENTROPY = 7.4
_CALM_SECTION = 6.5    # only look in sections that are calm overall
_MIN_ISLAND = 1024     # below this, clean .data spikes creep in
_MAX_ISLANDS = 16

# Sections handled elsewhere or expected to be high-entropy.
_SKIP_SECTIONS = {".rsrc", ".reloc"}


def _section_name(section) -> str:
    return section.Name.rstrip(b"\x00").decode("latin-1", errors="replace")


def _islands(data: bytes) -> list[tuple[int, int, float]]:
    """Return (start, size, entropy) for each high-entropy island in data."""
    run_start: int | None = None
    islands: list[tuple[int, int, float]] = []

    def close(run_end: int) -> None:
        assert run_start is not None
        size = run_end - run_start
        if size >= _MIN_ISLAND:
            islands.append((run_start, size, round(shannon_entropy(data[run_start:run_end]), 3)))

    for off in range(0, len(data) - _WINDOW + 1, _STEP):
        hot = shannon_entropy(data[off:off + _WINDOW]) >= _ISLAND_ENTROPY
        if hot and run_start is None:
            run_start = off
        elif not hot and run_start is not None:
            close(off)
            run_start = None
    if run_start is not None:
        close(len(data))
    return islands


def find_config_blobs(pe) -> list[ConfigBlob]:
    """Locate encrypted-config-like entropy islands in calm data sections."""
    blobs: list[ConfigBlob] = []
    for section in getattr(pe, "sections", []):
        if len(blobs) >= _MAX_ISLANDS:
            break
        name = _section_name(section)
        if name.lower() in _SKIP_SECTIONS:
            continue
        # Executable sections are the packer's domain, not a config store.
        if section.Characteristics & 0x20000000:
            continue
        # Only writable sections: an in-place-decrypted config lives in
        # writable memory, whereas read-only .rdata legitimately holds
        # high-entropy certificate/constant data that we must not flag.
        if not section.Characteristics & 0x80000000:
            continue
        try:
            data = section.get_data()
        except Exception:
            continue
        if len(data) < _MIN_ISLAND:
            continue
        # Only a *calm* host makes an island stand out; a uniformly random
        # section is packing, already covered by section/packer analysis.
        if shannon_entropy(data) >= _CALM_SECTION:
            continue
        base = section.PointerToRawData
        for start, size, entropy in _islands(data):
            blobs.append(ConfigBlob(section=name, file_offset=base + start,
                                    size=size, entropy=entropy))
            if len(blobs) >= _MAX_ISLANDS:
                break
    return blobs
