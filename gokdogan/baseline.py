"""Baseline diff — compare a sample against a known-good reference.

A common triage question is "is this the real ``svchost.exe`` or a
trojanized copy?". Given a reference known-good PE, this reports what the
sample *adds or changes*: imphash / authentihash match, sections added /
removed / modified (by content hash), the overall entropy shift, and any
capabilities the sample has that the baseline does not. A clean baseline
plus injection capabilities in the target is a loud signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import TriageReport


@dataclass
class BaselineDiff:
    same_imphash: bool
    same_authentihash: bool
    sections_added: list[str] = field(default_factory=list)
    sections_removed: list[str] = field(default_factory=list)
    sections_changed: list[str] = field(default_factory=list)
    entropy_delta: float = 0.0
    capabilities_added: list[str] = field(default_factory=list)

    @property
    def identical(self) -> bool:
        return (self.same_authentihash and not self.sections_added
                and not self.sections_removed and not self.sections_changed
                and not self.capabilities_added)


def diff_reports(target: TriageReport, baseline: TriageReport) -> BaselineDiff:
    """Diff a target report against a known-good baseline report."""
    t_sections = {s.name: s.md5 for s in target.sections}
    b_sections = {s.name: s.md5 for s in baseline.sections}

    added = sorted(set(t_sections) - set(b_sections))
    removed = sorted(set(b_sections) - set(t_sections))
    changed = sorted(name for name in (set(t_sections) & set(b_sections))
                     if t_sections[name] != b_sections[name])

    t_caps = {c.name for c in target.capabilities}
    b_caps = {c.name for c in baseline.capabilities}

    return BaselineDiff(
        same_imphash=bool(target.file.imphash) and target.file.imphash == baseline.file.imphash,
        same_authentihash=(bool(target.file.authentihash)
                           and target.file.authentihash == baseline.file.authentihash),
        sections_added=added,
        sections_removed=removed,
        sections_changed=changed,
        entropy_delta=round(target.overall_entropy - baseline.overall_entropy, 3),
        capabilities_added=sorted(t_caps - b_caps),
    )
