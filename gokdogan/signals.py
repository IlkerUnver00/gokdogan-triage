"""Stable signal IDs for the lines of a score breakdown.

A breakdown reason is written for a person: it carries counts, names and
values ("only 3 imported functions ...", "section '.bss': ..."). Measuring
how often each rule fires across thousands of files needs a key that names
the rule and nothing else, and stays the same from release to release while
the wording changes. The scorer gives every entry such an ID; this module
maps the free-text anomaly notes, which other stages write, onto theirs.

IDs are dotted, lower case except YARA rule names (kept as written):
``anomaly.no-import-table``, ``capability.process-injection.imports``,
``yara.Ransom_Note_Language``. Section and resource names are
attacker-controlled text inside a note, so a note is classified by its fixed
prefix and its fixed ending, never by a substring a name could carry.
"""

from __future__ import annotations

import re

from .loader import _LOW_IMPORTS, FLAG_HOT_EXEC, FLAG_UNPACK_TARGET, FLAG_WX, NOTE_EMPTY_DATA

UNKNOWN_ANOMALY = "anomaly.other"

_SECTION_FLAGS = (
    (FLAG_WX, "anomaly.section-wx"),
    # An empty executable section is where a stub unpacks code; an empty
    # data section is what compilers write for .bss. Split by the section's
    # own flags, never by its name, which the file chooses.
    (FLAG_UNPACK_TARGET, "anomaly.section-zero-raw-exec"),
    (NOTE_EMPTY_DATA, "anomaly.section-zero-raw-data"),
    (FLAG_HOT_EXEC, "anomaly.section-high-entropy-code"),
)

_PREFIXES = (
    ("entry point lies outside all sections", "anomaly.entry-outside-sections"),
    ("entry point in last section ", "anomaly.entry-last-section"),
    ("TLS callbacks present", "anomaly.tls-callbacks"),
    ("PE header checksum does not match", "anomaly.checksum-mismatch"),
    ("Rich header checksum invalid", "anomaly.rich-checksum"),
    ("overlay contains an embedded executable", "anomaly.overlay-embedded-pe"),
    ("overlay is a ", "anomaly.overlay-container"),
    ("high-entropy overlay", "anomaly.overlay-high-entropy"),
    (".NET obfuscator detected", "anomaly.dotnet-obfuscator"),
    (".NET metadata unreadable", "anomaly.dotnet-metadata-unreadable"),
    (".NET metadata has ", "anomaly.dotnet-metadata-malformed"),
)
_CERT_PADDING = re.compile(r"\d+ bytes of unauthenticated data in the Authenticode certificate table")
_SIGNATURE = re.compile(r"Authenticode signature ([a-z-]+): ")

# A resource note names one resource ("resource TYPE/NAME: <flag>") or counts
# several ("N resources <label>: <examples>"); TYPE, NAME and the examples
# are the file's own text.
_RESOURCE_ONE = (
    (re.compile(r": (embedded PE executable|contains an embedded executable \(DOS stub found\))$"),
     "anomaly.resource-embedded-pe"),
    (re.compile(r": high entropy \d+\.\d+ \(packed/encrypted\)$"), "anomaly.resource-high-entropy"),
)
_RESOURCES_MANY = re.compile(r"\d+ resources (carry an embedded executable|are high-entropy \(packed/encrypted\)): ")
_RESOURCES_LABEL = {"carry an embedded executable": "anomaly.resource-embedded-pe",
                    "are high-entropy (packed/encrypted)": "anomaly.resource-high-entropy"}

_TIMESTAMPS = {
    "compile timestamp is zero (deliberately wiped)": "timestamp.zero",
    "compile timestamp is in the future": "timestamp.future",
    "compile timestamp predates the PE era": "timestamp.predates-pe",
}


def anomaly_signal(note: str) -> str:
    """The signal ID of an anomaly note (``anomaly.other`` for an unknown one)."""
    if note == "no import table":
        return "anomaly.no-import-table"
    if _LOW_IMPORTS.fullmatch(note):
        return "anomaly.few-imports"
    if note.startswith("section "):
        for flag, signal in _SECTION_FLAGS:
            if note.endswith(": " + flag):
                return signal
        return UNKNOWN_ANOMALY
    if note.startswith("resource "):
        for pattern, signal in _RESOURCE_ONE:
            if pattern.search(note):
                return signal
        return UNKNOWN_ANOMALY
    many = _RESOURCES_MANY.match(note)
    if many:
        return _RESOURCES_LABEL[many.group(1)]
    if _CERT_PADDING.match(note):
        return "anomaly.cert-table-padding"
    status = _SIGNATURE.match(note)
    if status:
        return f"anomaly.signature-{status.group(1)}"
    for prefix, signal in _PREFIXES:
        if note.startswith(prefix):
            return signal
    return UNKNOWN_ANOMALY


def timestamp_signal(note: str) -> str:
    return _TIMESTAMPS.get(note, "timestamp.other")
