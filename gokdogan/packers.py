"""Packer / protector detection.

Two complementary signals:
  1. Known packer section names (fast, precise, easily stripped).
  2. Structural heuristics (entropy, import count, unpacking-target
     sections) that survive a renamed section table.
"""

from __future__ import annotations

from .entropy import HIGH_ENTROPY
from .models import PackerInfo, SectionInfo

# Section name (lowercase, exact) -> packer/protector family.
KNOWN_PACKER_SECTIONS: dict[str, str] = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".upx": "UPX",
    "mpress1": "MPRESS",
    "mpress2": "MPRESS",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".packed": "RLPack",
    ".rlpack": "RLPack",
    ".petite": "Petite",
    ".pec1": "PECompact",
    "pec2": "PECompact",
    ".pec2": "PECompact",
    "pebundle": "PEBundle",
    ".themida": "Themida/WinLicense",
    "themida": "Themida/WinLicense",
    ".winlice": "Themida/WinLicense",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    ".nsp0": "NsPack",
    ".nsp1": "NsPack",
    ".nsp2": "NsPack",
    "nsp0": "NsPack",
    ".neolite": "NeoLite",
    ".neolit": "NeoLite",
    ".mew": "MEW",
    ".fsg": "FSG",
    ".yp": "Y0da Protector",
    ".y0da": "Y0da Protector",
    ".boom": "The Boomerang",
    ".ccg": "CCG packer",
    ".svkp": "SVKP",
    ".taz": "PESpin",
    ".shrink1": "Shrinker",
    ".spack": "Simple Pack",
    "kkrunchy": "kkrunchy",
    ".wwpack": "WWPACK",
    "pelock": "PELock",
}


def detect_packer(sections: list[SectionInfo], import_count: int) -> PackerInfo:
    names: list[str] = []
    indicators: list[str] = []

    for s in sections:
        family = KNOWN_PACKER_SECTIONS.get(s.name.lower())
        if family and family not in names:
            names.append(family)
            indicators.append(f"section name {s.name!r} is a known {family} artifact")

    exec_sections = [s for s in sections if s.is_executable]
    hot = [s for s in exec_sections if s.entropy >= HIGH_ENTROPY]
    for s in hot:
        indicators.append(
            f"executable section {s.name!r} has entropy {s.entropy:.2f} (>= {HIGH_ENTROPY})"
        )

    unpack_targets = [s for s in sections if "zero raw size (unpacking target)" in s.flags]
    for s in unpack_targets:
        indicators.append(f"section {s.name!r} is empty on disk but mapped in memory")

    if import_count <= 10:
        indicators.append(f"tiny import table ({import_count} functions)")

    # Generic verdict: heuristics fire together strongly enough even
    # without a recognizable section name.
    heuristic_hits = bool(hot) + bool(unpack_targets) + (import_count <= 10)
    detected = bool(names) or heuristic_hits >= 2
    if detected and not names:
        names.append("unknown packer (heuristic)")

    return PackerInfo(detected=detected, names=names, indicators=indicators)
