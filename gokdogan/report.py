"""Report rendering: ANSI console output and JSON export."""

from __future__ import annotations

import json
import os
import re
import sys
from typing import TextIO

from .golang import package_kind
from .models import GoInfo, TriageReport, Verdict

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_RED = "\x1b[31m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_CYAN = "\x1b[36m"

_VERDICT_STYLE = {
    Verdict.LIKELY_CLEAN: (_GREEN, "LIKELY CLEAN"),
    Verdict.SUSPICIOUS: (_YELLOW, "SUSPICIOUS"),
    Verdict.HIGH_RISK: (_RED, "HIGH RISK"),
}

_SEVERITY_MARK = {1: " . ", 2: " ! ", 3: "!!!"}

# ASCII fallbacks for the decorative Unicode we use, so redirecting output
# to a file or a legacy codepage console (e.g. Windows cp1254) degrades to
# clean ASCII instead of crashing with UnicodeEncodeError.
_ASCII_FALLBACK = {
    ord("─"): "-",
    ord("—"): "-",
    ord("≥"): ">=",
    ord("…"): "...",
}


class _SafeStream:
    """Wrap a text stream; transliterate/replace whatever it can't encode."""

    def __init__(self, stream: TextIO):
        self._stream = stream
        self._encoding = getattr(stream, "encoding", None) or "utf-8"

    def write(self, text: str) -> None:
        try:
            text.encode(self._encoding)
        except (UnicodeEncodeError, LookupError):
            text = text.translate(_ASCII_FALLBACK)
            text = text.encode(self._encoding, "replace").decode(self._encoding)
        self._stream.write(text)

    @property
    def raw(self) -> TextIO:
        return self._stream


def _use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _signature_line(report: TriageReport, c) -> str:
    sig = report.signature
    if sig is None or not sig.present:
        return "no"
    signer = f" — {sig.signer}" if sig.signer else ""
    if sig.status == "valid":
        return c(_GREEN, f"VALID{signer}")
    if sig.status in ("tampered", "revoked"):
        return c(_RED, f"{sig.status.upper()}{signer} ({sig.note})")
    if sig.status in ("expired", "untrusted", "invalid"):
        return c(_YELLOW, f"{sig.status}{signer} ({sig.note})")
    return f"present, {sig.status}{signer}"


def _more(items: list[str], shown: int, total: int | None = None) -> str:
    rest = (len(items) if total is None else total) - shown
    return ", ".join(items[:shown]) + (f", +{rest} more" if rest > 0 else "")


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _cut(text: str, n: int = 110) -> str:
    """Shortened, with control characters shown as \\xNN: Go names and paths come
    from the sample, and an escape sequence must not reach the analyst's terminal."""
    text = _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
    return text if len(text) <= n else text[:n - 1] + "…"


def go_summary(go: GoInfo) -> str:
    """One line: version, evidence and, when the function table was read, its size."""
    line = f"{go.version or 'version unknown'} ({' + '.join(go.evidence)}{', confirmed' if go.confirmed else ''})"
    if go.package_count:
        line += (f" · {go.function_count:,} functions in {go.package_count:,} packages "
                 f"({go.std_package_count} std, {go.third_party_count} third-party, "
                 f"{go.local_package_count} local)")
    return line


def go_lines(go: GoInfo) -> list[tuple[str, str | None]]:
    """The Go block of the console report: (text, style); style None is the headline."""
    out: list[tuple[str, str | None]] = [(_cut(go_summary(go), 220), None)]
    main = []
    if go.main_path:
        main.append(f"main {go.main_path}")
    if go.main_module is not None:
        main.append(f"module {go.main_module.path} {go.main_module.version}".rstrip())
    if go.dep_count:
        main.append(f"{go.dep_count} dependencies")
    if main:
        out.append((_cut(" · ".join(main)), _DIM))
    build = []
    for key in ("CGO_ENABLED", "-trimpath", "-buildmode", "-ldflags", "vcs.revision", "vcs.modified"):
        if key in go.settings:
            value = go.settings[key]
            value = value[:12] if key == "vcs.revision" else _cut(value, 80)
            build.append(f"{key}={value}")
    if build:
        out.append((_cut("build: " + " ".join(build)), _DIM))
    third = [p for p in go.packages if package_kind(p) == "third-party"]
    if third:
        out.append((_cut("third-party: " + _more(third, 6, go.third_party_count)), _DIM))
    if go.winapi:
        out.append((_cut(f"Windows API linked: {len(go.winapi)} ({_more(go.winapi, 8)})"), _DIM))
    funcs = [f for f in go.main_functions if f != "main.main" and not f.startswith("main.init")]
    if funcs:
        out.append((_cut("main.*: " + _more(funcs, 6)), _DIM))
    if go.source_paths or go.goroot:
        parts = []
        if go.source_paths:
            extra = go.source_path_count - 1
            parts.append(f"source: {go.source_paths[0]}" + (f" (+{extra} more)" if extra > 0 else ""))
        if go.goroot:
            parts.append(f"GOROOT {go.goroot}")
        out.append((_cut("; ".join(parts)), _DIM))
    if go.build_id:
        out.append((_cut(f"build ID: {go.build_id}"), _DIM))
    if go.obfuscation:
        out.append((_cut("obfuscation: " + "; ".join(go.obfuscation), 160), _YELLOW))
    out += [(_cut(f"carries: {e}"), _DIM) for e in go.embedded]
    out += [(_cut(f"note: {n}"), _DIM) for n in go.notes]
    return out


def render_console(report: TriageReport, stream: TextIO = sys.stdout) -> None:
    color = _use_color(stream)
    stream = _SafeStream(stream)

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    def header(title: str) -> None:
        stream.write(c(_BOLD + _CYAN, f"\n── {title} " + "─" * max(0, 58 - len(title))) + "\n")

    f = report.file
    stream.write(c(_BOLD, f"\ngokdogan triage report — {f.path}\n"))

    header("File")
    stream.write(f"  type       : {f.file_type}\n")
    stream.write(f"  size       : {f.size:,} bytes\n")
    stream.write(f"  sha256     : {f.sha256}\n")
    stream.write(f"  md5        : {f.md5}\n")
    stream.write(f"  imphash    : {f.imphash or '-'}\n")
    stream.write(f"  impfuzzy   : {f.impfuzzy or '-'}\n")
    stream.write(f"  rich_hash  : {report.rich.hash if report.rich else '-'}\n")
    stream.write(f"  authentihash: {f.authentihash or '-'}\n")
    stream.write(f"  ssdeep     : {f.ssdeep or '-'}\n")
    stream.write(f"  tlsh       : {f.tlsh or '-'}\n")
    if f.ssdeep is None and f.tlsh is None:
        from .fuzzy import availability_note

        note = availability_note()
        if note:
            stream.write(c(_DIM, f"               ({note})") + "\n")
    ts = f.compile_timestamp or "-"
    if f.compile_timestamp_anomaly:
        ts += c(_YELLOW, f"  [{f.compile_timestamp_anomaly}]")
    stream.write(f"  compiled   : {ts}\n")
    stream.write(f"  signed     : {_signature_line(report, c)}\n")
    stream.write(f"  entrypoint : 0x{f.entry_point:x} in {f.entry_section or '?'}\n")
    if report.dotnet is not None:
        dn = report.dotnet
        flags = f" [{', '.join(dn.flags)}]" if dn.flags else ""
        stream.write(f"  .NET       : managed assembly, CLR {dn.runtime_version}{flags}\n")
        if dn.obfuscators:
            stream.write(c(_YELLOW, f"               obfuscator: {', '.join(dn.obfuscators)}\n"))
        if dn.metadata_error:
            stream.write(c(_YELLOW, f"               metadata unreadable: {dn.metadata_error}\n"))
        else:
            called = (f", {dn.pinvoke_called} called" if dn.pinvoke_called is not None
                      else "; calls not traced, rules read the whole assembly")
            stream.write(c(_DIM, f"               metadata: {dn.member_refs} member references, "
                                 f"{dn.pinvoke_count} P/Invoke declarations{called}\n"))
            if dn.pinvoke:
                more = dn.pinvoke_count - 6
                shown = ", ".join(dn.pinvoke[:6]) + (f", +{more} more" if more > 0 else "")
                stream.write(c(_DIM, f"               P/Invoke: {shown}\n"))
    if report.go is not None:
        for line, style in go_lines(report.go):
            stream.write((c(style, f"               {line}") if style else f"  Go         : {line}") + "\n")

    header("Sections")
    stream.write(f"  {'name':<10} {'raw size':>10} {'entropy':>8}  flags\n")
    for s in report.sections:
        ent = f"{s.entropy:.2f}"
        if s.entropy >= 7.2:
            ent = c(_RED, ent)
        perms = ("X" if s.is_executable else "-") + ("W" if s.is_writable else "-")
        flags = f"[{perms}] " + ", ".join(s.flags)
        stream.write(f"  {s.name:<10} {s.raw_size:>10,} {ent:>8}  {flags.strip()}\n")
    stream.write(f"  overall file entropy: {report.overall_entropy:.2f}\n")

    ov = report.overlay
    if ov is not None and not ov.is_signature:
        header("Overlay")
        payload = ov.size if ov.payload_size is None else ov.payload_size
        beside = f", {payload:,} outside the signature" if payload != ov.size else ""
        stream.write(f"  {ov.size:,} bytes ({ov.pct}% of file) at offset 0x{ov.offset:x}{beside}, "
                     f"entropy {ov.entropy:.2f}\n")
        stream.write(f"  type: {ov.type_guess}")
        if ov.contains_pe:
            stream.write(c(_RED, "  [contains embedded executable]"))
        stream.write("\n")

    if report.rich is not None:
        header("Rich header (toolchain)")
        if report.rich.checksum_valid is True:
            status = "valid"
        elif report.rich.checksum_valid is False:
            status = c(_RED, "INVALID — forged or copied")
        else:
            status = "unverified"
        stream.write(f"  hash {report.rich.hash}  (checksum {status})\n")
        stream.write(f"  {'prod id':>8} {'build':>7} {'count':>7}  tool\n")
        for e in report.rich.entries:
            prodid = f"0x{e.prod_id:x}"
            stream.write(f"  {prodid:>8} {e.build:>7} {e.count:>7}  {e.tool}\n")

    if report.resources:
        header("Resources")
        flagged = [r for r in report.resources if r.flags]
        by_type: dict[str, int] = {}
        for r in report.resources:
            by_type[r.type] = by_type.get(r.type, 0) + 1
        summary = ", ".join(f"{t}×{n}" for t, n in sorted(by_type.items()))
        stream.write(f"  {len(report.resources)} resources: {summary}\n")
        if not flagged:
            stream.write("  nothing notable\n")
        for r in flagged:
            marker = c(_RED, "!!") if any("embedded" in f for f in r.flags) else c(_YELLOW, " !")
            stream.write(f"  [{marker}] {r.type}/{r.name} ({r.size:,} B, entropy {r.entropy:.2f})\n")
            for flag in r.flags:
                stream.write(c(_DIM, f"        {flag}") + "\n")
            stream.write(c(_DIM, f"        sha256 {r.sha256}") + "\n")

    if report.config_blobs:
        header("Config blobs (entropy islands)")
        for b in report.config_blobs:
            stream.write(c(_YELLOW, f"  ! {b.section} @ file 0x{b.file_offset:x}: "
                                    f"{b.size:,} B, entropy {b.entropy:.2f}") + "\n")
        stream.write(c(_DIM, "    localized high-entropy region — likely encrypted config/payload\n"))

    if report.exports is not None:
        header("Exports")
        e = report.exports
        name = e.dll_name or "-"
        if e.name_mismatch:
            name += c(_YELLOW, "  (internal name != file name)")
        stream.write(f"  name       : {name}\n")
        stream.write(f"  exports    : {e.total} ({e.named} named, {e.ordinal_only} ordinal-only)\n")
        if e.forwarders:
            stream.write(f"  forwarders : {len(e.forwarders)}\n")
            for fwd in e.forwarders[:5]:
                stream.write(c(_DIM, f"      {fwd}") + "\n")
        for key in e.suspicious:
            stream.write(c(_RED, f"  ! suspicious export: {key}") + "\n")

    if report.delay_imports:
        header("Delay-load imports")
        stream.write(f"  {len(report.delay_imports)} DLL(s), merged into capability analysis:\n")
        stream.write(c(_DIM, "    " + ", ".join(report.delay_imports)) + "\n")

    header("Packer")
    if report.packer.detected:
        stream.write(c(_YELLOW, f"  DETECTED: {', '.join(report.packer.names)}\n"))
    else:
        stream.write("  no packer detected\n")
    for ind in report.packer.indicators:
        stream.write(f"    - {ind}\n")

    if report.anomalies:
        header("Anomalies")
        for a in report.anomalies:
            stream.write(c(_YELLOW, f"  ! {a}\n"))

    header("Capabilities")
    if not report.capabilities:
        stream.write("  none inferred from import table\n")
    for cap in report.capabilities:
        mark = _SEVERITY_MARK[cap.severity]
        attack = f"  ({', '.join(cap.attack)})" if cap.attack else ""
        line = f"  [{mark}] {cap.name:<24} {cap.description}"
        stream.write(c(_RED if cap.severity == 3 else "", line) + c(_DIM, attack) + "\n")
        evidence = ", ".join(cap.evidence[:6])
        if len(cap.evidence) > 6:
            evidence += f", … +{len(cap.evidence) - 6} more"
        stream.write(c(_DIM, f"        {evidence}") + "\n")

    header("MITRE ATT&CK")
    if not report.attack:
        stream.write("  no techniques mapped\n")
    else:
        current_tactic = None
        for tech in report.attack:
            if tech.tactic != current_tactic:
                current_tactic = tech.tactic
                stream.write(c(_BOLD, f"  {tech.tactic}") + "\n")
            sources = ", ".join(tech.sources)
            stream.write(f"    {tech.id:<11} {tech.name}\n")
            stream.write(c(_DIM, f"                from: {sources}") + "\n")

    header("Strings of interest")
    if not report.strings:
        stream.write("  none\n")
    by_category: dict[str, list[str]] = {}
    for hit in report.strings:
        by_category.setdefault(hit.category, []).append(hit.value)
    for category, values in sorted(by_category.items()):
        total = report.string_stats.get(category, len(values))
        stream.write(f"  {category} ({total}):\n")
        for v in values[:8]:
            stream.write(c(_DIM, f"    {v[:110]}") + "\n")
        if len(values) > 8:
            stream.write(c(_DIM, f"    … +{len(values) - 8} more\n"))

    if report.decoded_strings:
        header("Recovered (encoded) strings")
        stream.write(c(_YELLOW, f"  {len(report.decoded_strings)} string(s) hidden by encoding:\n"))
        for d in report.decoded_strings[:15]:
            cat = f"[{d.category}] " if d.category else ""
            stream.write(f"  ({d.encoding:<9}) {cat}{d.value[:100]}\n")
        if len(report.decoded_strings) > 15:
            stream.write(c(_DIM, f"  … +{len(report.decoded_strings) - 15} more\n"))

    if report.config_extractions:
        header("Extracted config")
        for cfg in report.config_extractions:
            stream.write(c(_RED, f"  {cfg.family} — {cfg.key}: ") + f"{cfg.value[:120]}\n")

    header("YARA")
    if report.yara_error:
        stream.write(c(_DIM, f"  ({report.yara_error})\n"))
    elif not report.yara:
        stream.write("  no rule matches\n")
    for hit in report.yara:
        tags = f" [{', '.join(hit.tags)}]" if hit.tags else ""
        desc = hit.meta.get("description", "")
        stream.write(c(_YELLOW, f"  {hit.rule}{tags}") + (f" — {desc}" if desc else "") + "\n")

    if report.reputation:
        header("Reputation (online)")
        for rep in report.reputation:
            if rep.status == "found":
                bits = [b for b in (rep.detections, rep.family, rep.first_seen) if b]
                line = f"  {rep.source}: FOUND — {', '.join(bits)}"
                stream.write(c(_RED, line) + "\n")
                if rep.link:
                    stream.write(c(_DIM, f"      {rep.link}") + "\n")
            else:
                detail = rep.note or rep.status
                stream.write(c(_DIM, f"  {rep.source}: {rep.status} ({detail})") + "\n")

    header("Verdict")
    style, label = _VERDICT_STYLE[report.verdict]
    for entry in report.score_breakdown:
        sign = "+" if entry.points >= 0 else ""
        stream.write(f"  {sign}{entry.points:>3}  {entry.reason}\n")
    stream.write(
        c(_BOLD + style, f"\n  {label}  (score {report.score}, "
                         f"thresholds: suspicious ≥ 30, high risk ≥ 60)\n\n")
    )


def render_json(report: TriageReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_navigator_layer(report: TriageReport, name: str | None = None) -> str:
    """Serialize the report's ATT&CK techniques as a Navigator layer JSON."""
    from .attack import to_navigator_layer

    return json.dumps(to_navigator_layer(report, name), indent=2, ensure_ascii=False)
