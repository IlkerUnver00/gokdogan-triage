"""Data model for a triage report.

Every analyzer module fills a slice of TriageReport; the verdict engine
and the reporters (console / JSON) only ever consume this structure, so
analyzers stay decoupled from presentation.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    LIKELY_CLEAN = "LIKELY_CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"


@dataclass
class FileInfo:
    path: str
    size: int
    md5: str
    sha1: str
    sha256: str
    imphash: str | None
    ssdeep: str | None      # ssdeep fuzzy hash (clustering), None if unavailable
    tlsh: str | None        # TLSH fuzzy hash (clustering), None if unavailable
    file_type: str          # e.g. "PE32 executable (GUI) x86"
    compile_timestamp: str | None
    compile_timestamp_anomaly: str | None  # e.g. "timestamp in the future"
    is_dll: bool
    is_driver: bool
    is_signed: bool         # has a security directory (Authenticode blob present)
    entry_point: int
    entry_section: str | None


@dataclass
class OverlayInfo:
    offset: int
    size: int
    pct: float           # overlay as a percentage of file size
    entropy: float
    type_guess: str      # magic-byte file-type label, or "unknown"
    contains_pe: bool
    is_signature: bool   # overlay is (just) the Authenticode blob


@dataclass
class SignatureInfo:
    status: str          # valid | tampered | expired | untrusted | revoked | unsigned | invalid | unavailable
    present: bool = False   # an actual signature was found
    verified: bool | None = None  # True=valid chain, False=present-but-invalid, None=couldn't check
    signer: str = ""     # signer certificate common name
    issuer: str = ""     # issuer certificate common name
    note: str = ""


@dataclass
class RichEntry:
    prod_id: int         # @comp.id product id (tool identity)
    build: int           # tool build number (precise version)
    count: int           # object files contributed by this tool
    tool: str            # human label for prod_id


@dataclass
class RichHeader:
    hash: str            # MD5 of the decoded Rich header (toolchain fingerprint)
    xor_key: str         # stored checksum / XOR key, hex
    entries: list["RichEntry"] = field(default_factory=list)
    checksum_valid: bool | None = None  # None = could not verify


@dataclass
class SectionInfo:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    md5: str
    is_executable: bool
    is_writable: bool
    flags: list[str] = field(default_factory=list)  # e.g. ["W+X", "zero raw size"]


@dataclass
class PackerInfo:
    detected: bool
    names: list[str] = field(default_factory=list)      # e.g. ["UPX"]
    indicators: list[str] = field(default_factory=list)  # human-readable evidence


@dataclass
class ExportInfo:
    dll_name: str        # internal export directory name
    total: int
    named: int
    ordinal_only: int
    forwarders: list[str] = field(default_factory=list)  # "name -> target"
    names: list[str] = field(default_factory=list)        # exported names (capped)
    suspicious: list[str] = field(default_factory=list)   # capability keys
    name_mismatch: bool = False   # internal name != file name (masquerade hint)


@dataclass
class ResourceInfo:
    type: str            # e.g. "RT_ICON", "RT_RCDATA", or a custom type name
    name: str            # resource id or string name
    language: str        # "lang/sublang"
    size: int
    entropy: float
    sha256: str
    flags: list[str] = field(default_factory=list)  # e.g. ["embedded PE executable"]


@dataclass
class StringHit:
    category: str   # url | ipv4 | domain | email | registry | path | pdb | command | user_agent
    value: str
    offset: int
    encoding: str   # ascii | utf-16le


@dataclass
class ConfigBlob:
    section: str         # host section name
    file_offset: int     # file offset of the island
    size: int
    entropy: float


@dataclass
class DecodedString:
    value: str
    encoding: str        # e.g. "xor-0x5a", "add-0x0d", "rol-3", "base64"
    category: str | None  # classifier category (url/command/...) or "embedded-pe"
    offset: int


@dataclass
class Capability:
    name: str            # e.g. "process-injection"
    description: str
    severity: int        # 1 (info) .. 3 (high)
    evidence: list[str] = field(default_factory=list)  # APIs or strings that triggered it
    attack: list[str] = field(default_factory=list)    # MITRE ATT&CK technique ids


@dataclass
class AttackTechnique:
    """One ATT&CK technique observed, with the sources that implied it."""
    id: str              # e.g. "T1055" or "T1547.001"
    name: str            # e.g. "Process Injection"
    tactic: str          # e.g. "Defense Evasion"
    sources: list[str] = field(default_factory=list)  # capabilities / YARA rules


@dataclass
class YaraHit:
    rule: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)  # matched string identifiers


@dataclass
class Reputation:
    source: str          # "VirusTotal" | "MalwareBazaar"
    status: str          # found | not_found | error | no_key
    detections: str = ""  # e.g. "48/72" (VT malicious/total)
    family: str = ""      # e.g. "Emotet"
    first_seen: str = ""
    link: str = ""        # analyst-facing GUI URL
    note: str = ""        # error / explanation


@dataclass
class ScoreEntry:
    points: int
    reason: str


@dataclass
class TriageReport:
    file: FileInfo
    signature: "SignatureInfo | None" = None
    overlay: "OverlayInfo | None" = None
    rich: "RichHeader | None" = None
    sections: list[SectionInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    config_blobs: list[ConfigBlob] = field(default_factory=list)
    exports: "ExportInfo | None" = None
    delay_imports: list[str] = field(default_factory=list)  # delay-loaded DLL names
    overall_entropy: float = 0.0
    packer: PackerInfo = field(default_factory=lambda: PackerInfo(detected=False))
    anomalies: list[str] = field(default_factory=list)
    strings: list[StringHit] = field(default_factory=list)
    string_stats: dict[str, int] = field(default_factory=dict)
    decoded_strings: list[DecodedString] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)
    attack: list[AttackTechnique] = field(default_factory=list)
    yara: list[YaraHit] = field(default_factory=list)
    yara_error: str | None = None
    reputation: list["Reputation"] = field(default_factory=list)
    score: int = 0
    score_breakdown: list[ScoreEntry] = field(default_factory=list)
    verdict: Verdict = Verdict.LIKELY_CLEAN

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["verdict"] = self.verdict.value
        return d
