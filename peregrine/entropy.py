"""Shannon entropy helpers.

Entropy is the workhorse of packer/crypter triage: plain x86 code sits
around 5.5-6.5 bits/byte, compressed or encrypted payloads push past 7.2.
"""

from __future__ import annotations

import math
from collections import Counter

# Executable sections above this are almost certainly packed/encrypted.
HIGH_ENTROPY = 7.2
# Overall-file threshold (headers drag the average down a little).
HIGH_ENTROPY_FILE = 7.0


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def entropy_label(value: float) -> str:
    """Human-readable bucket for a section entropy value."""
    if value >= HIGH_ENTROPY:
        return "packed/encrypted"
    if value >= 6.5:
        return "compressed/high"
    if value >= 4.5:
        return "code/data"
    if value > 0.5:
        return "low"
    return "empty/padding"
