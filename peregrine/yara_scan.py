"""YARA integration.

Compiles every ``*.yar`` / ``*.yara`` file under a rules directory and
runs them against the sample. yara-python is an optional dependency —
without it the engine still produces a full report, minus this section.
"""

from __future__ import annotations

from pathlib import Path

from .models import YaraHit

try:
    import yara  # type: ignore

    YARA_AVAILABLE = True
except ImportError:  # pragma: no cover
    yara = None
    YARA_AVAILABLE = False

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def scan(data: bytes, rules_dir: str | Path | None = None) -> tuple[list[YaraHit], str | None]:
    """Run YARA rules over the sample. Returns (hits, error_or_None)."""
    if not YARA_AVAILABLE:
        return [], "yara-python is not installed (pip install yara-python)"

    rules_path = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    if not rules_path.is_dir():
        return [], f"rules directory not found: {rules_path}"

    # Rule file contents are passed as source strings rather than paths:
    # yara-python's C-level file open chokes on non-ASCII paths on Windows.
    sources: dict[str, str] = {}
    for f in sorted(rules_path.rglob("*")):
        if f.suffix.lower() in (".yar", ".yara"):
            sources[f.stem] = f.read_text(encoding="utf-8", errors="replace")
    if not sources:
        return [], f"no .yar/.yara files in {rules_path}"

    try:
        compiled = yara.compile(sources=sources)
    except yara.Error as exc:
        return [], f"rule compilation failed: {exc}"

    hits: list[YaraHit] = []
    for match in compiled.match(data=data):
        identifiers = sorted({s.identifier for s in match.strings})
        hits.append(
            YaraHit(
                rule=match.rule,
                tags=list(match.tags),
                meta=dict(match.meta),
                strings=identifiers,
            )
        )
    return hits, None
