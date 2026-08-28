"""Fuzzy (similarity-preserving) hashing for sample clustering.

Cryptographic hashes change completely on a one-byte edit; fuzzy hashes
change *proportionally*, so two builds of the same malware from the same
kit score as similar. gokdogan emits two complementary schemes:

  * ssdeep — context-triggered piecewise hashing; compare score 0..100
    (100 = identical). Provided by the pure-Python ``ppdeep`` package, so
    it works everywhere with no C toolchain.
  * TLSH  — locality-sensitive hash; compare is a *distance* (0 = identical,
    higher = more different, roughly >150 = unrelated). Provided by the
    optional ``tlsh``/``py-tlsh`` package; degrades gracefully when absent.

Both are optional: without either, triage still runs and the report notes
which schemes were unavailable. Fuzzy hashes never feed the verdict —
they are an identity/clustering signal, not a maliciousness signal.
"""

from __future__ import annotations

try:
    import ppdeep  # pure-Python, ssdeep-compatible

    HAVE_SSDEEP = True
except ImportError:  # pragma: no cover
    ppdeep = None
    HAVE_SSDEEP = False

try:
    import tlsh  # needs a C++ extension; optional

    HAVE_TLSH = True
except ImportError:  # pragma: no cover
    tlsh = None
    HAVE_TLSH = False

# TLSH needs enough input with some variance or it returns a null hash.
_TLSH_MIN_BYTES = 256
_TLSH_NULL = {"", "TNULL"}


def ssdeep_hash(data: bytes) -> str | None:
    if not HAVE_SSDEEP:
        return None
    try:
        return ppdeep.hash(data)
    except Exception:  # pragma: no cover - defensive
        return None


def tlsh_hash(data: bytes) -> str | None:
    if not HAVE_TLSH or len(data) < _TLSH_MIN_BYTES:
        return None
    try:
        digest = tlsh.hash(data)
    except Exception:  # pragma: no cover - defensive
        return None
    if digest in _TLSH_NULL:
        return None
    # Older builds prefix the version with "T1"; keep whatever the lib emits.
    return digest


def compare_ssdeep(a: str | None, b: str | None) -> int | None:
    """Similarity 0..100 (100 = identical), or None if uncomparable."""
    if not (HAVE_SSDEEP and a and b):
        return None
    try:
        return int(ppdeep.compare(a, b))
    except Exception:  # pragma: no cover - defensive
        return None


def compare_tlsh(a: str | None, b: str | None) -> int | None:
    """Distance (0 = identical, higher = more different), or None."""
    if not (HAVE_TLSH and a and b) or a in _TLSH_NULL or b in _TLSH_NULL:
        return None
    try:
        return int(tlsh.diff(a, b))
    except Exception:  # pragma: no cover - defensive
        return None


def availability_note() -> str | None:
    """A one-line note about missing schemes, or None if both present."""
    missing = []
    if not HAVE_SSDEEP:
        missing.append("ssdeep (pip install ppdeep)")
    if not HAVE_TLSH:
        missing.append("TLSH (pip install py-tlsh)")
    if not missing:
        return None
    return "fuzzy hashing unavailable: " + ", ".join(missing)
