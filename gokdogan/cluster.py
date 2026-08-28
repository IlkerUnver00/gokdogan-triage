"""Dropzone clustering — group related samples in a batch.

Given the triage reports for a folder of samples, this links files that
almost certainly belong together: any shared exact fingerprint (imphash,
Rich-header hash, authentihash) or a high fuzzy similarity (ssdeep /
impfuzzy). It is a plain union-find over the reports, so a chain of pairwise
matches collapses into one cluster. The point is to let an analyst work a
dropzone family-by-family instead of file-by-file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .fuzzy import compare_ssdeep

_FUZZY_THRESHOLD = 60   # ssdeep/impfuzzy score at/above which two files are "related"


@dataclass
class Cluster:
    members: list[str] = field(default_factory=list)   # file paths
    bases: list[str] = field(default_factory=list)     # why they clustered


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _related(r1, r2) -> str | None:
    """Return the basis on which two reports relate, or None."""
    f1, f2 = r1.file, r2.file
    if f1.imphash and f1.imphash == f2.imphash:
        return "imphash"
    if r1.rich and r2.rich and r1.rich.hash == r2.rich.hash:
        return "rich_hash"
    if f1.authentihash and f1.authentihash == f2.authentihash:
        return "authentihash"
    score = compare_ssdeep(f1.ssdeep, f2.ssdeep)
    if score is not None and score >= _FUZZY_THRESHOLD:
        return f"ssdeep~{score}"
    imp = compare_ssdeep(f1.impfuzzy, f2.impfuzzy)
    if imp is not None and imp >= _FUZZY_THRESHOLD:
        return f"impfuzzy~{imp}"
    return None


def cluster_reports(reports: list) -> list[Cluster]:
    """Group related reports; returns clusters of size >= 2, largest first."""
    n = len(reports)
    uf = _UnionFind(n)
    bases: dict[int, set[str]] = {}

    for i in range(n):
        for j in range(i + 1, n):
            basis = _related(reports[i], reports[j])
            if basis is not None:
                uf.union(i, j)
                root = uf.find(i)
                bases.setdefault(root, set()).add(basis.split("~")[0])

    groups: dict[int, list[int]] = {}
    for idx in range(n):
        groups.setdefault(uf.find(idx), []).append(idx)

    clusters = [
        Cluster(
            members=[reports[i].file.path for i in members],
            bases=sorted(bases.get(root, set())),
        )
        for root, members in groups.items()
        if len(members) >= 2
    ]
    clusters.sort(key=lambda c: -len(c.members))
    return clusters
