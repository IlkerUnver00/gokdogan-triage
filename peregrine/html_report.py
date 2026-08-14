"""Self-contained HTML report.

Renders a TriageReport as a single, dependency-free HTML file (inline CSS,
no external fetches) suitable for attaching to a case or handing to a lead.
The verdict rationale — the full score breakdown — is embedded so the
reader can see *why* a sample scored the way it did.

Security note: sample-derived text (strings, paths, resource names, YARA
matches) is attacker-controlled and could contain markup. Every dynamic
value is passed through ``html.escape`` so opening the report can never
execute embedded scripts.
"""

from __future__ import annotations

from html import escape

from .models import TriageReport, Verdict

_VERDICT_CLASS = {
    Verdict.LIKELY_CLEAN: "clean",
    Verdict.SUSPICIOUS: "suspicious",
    Verdict.HIGH_RISK: "high-risk",
}
_VERDICT_LABEL = {
    Verdict.LIKELY_CLEAN: "LIKELY CLEAN",
    Verdict.SUSPICIOUS: "SUSPICIOUS",
    Verdict.HIGH_RISK: "HIGH RISK",
}
_SEV_LABEL = {1: "info", 2: "notable", 3: "high"}

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2530;--muted:#5c6773;--border:#e2e6ea;
--clean:#1a7f4b;--suspicious:#b7791f;--high:#c0362c;--accent:#205b8f;--chip:#eef1f4}
@media (prefers-color-scheme:dark){:root{--bg:#12161b;--card:#1b2129;--fg:#e6eaee;
--muted:#9aa6b2;--border:#2b333d;--clean:#4cc38a;--suspicious:#e0b341;--high:#ff6b5e;
--accent:#5aa0e0;--chip:#242c35}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px;word-break:break-all}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
margin:28px 0 10px;border-bottom:1px solid var(--border);padding-bottom:6px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:8px}
.banner{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.badge{font-weight:700;font-size:18px;padding:8px 16px;border-radius:8px;color:#fff}
.badge.clean{background:var(--clean)}.badge.suspicious{background:var(--suspicious)}
.badge.high-risk{background:var(--high)}
.score{font-size:32px;font-weight:700}.score small{font-size:13px;font-weight:400;color:var(--muted)}
.grid{display:grid;grid-template-columns:140px 1fr;gap:4px 14px;font-size:14px}
.grid dt{color:var(--muted)}.grid dd{margin:0;word-break:break-all;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600}
.num{text-align:right;font-variant-numeric:tabular-nums}
.pos{color:var(--high)}.neg{color:var(--clean)}
.chip{display:inline-block;background:var(--chip);border:1px solid var(--border);
border-radius:20px;padding:1px 9px;font-size:12px;margin:2px 3px 2px 0;white-space:nowrap}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px}
.dot.s1{background:var(--muted)}.dot.s2{background:var(--suspicious)}.dot.s3{background:var(--high)}
.muted{color:var(--muted);font-size:13px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
.bar{display:inline-block;height:8px;border-radius:4px;background:var(--accent);vertical-align:middle}
.tactic{font-weight:600;margin:10px 0 4px}
.flagline{color:var(--high)}
.foot{color:var(--muted);font-size:12px;margin-top:28px;text-align:center}
"""


def _esc(value) -> str:
    return escape(str(value))


def render_html(report: TriageReport) -> str:
    f = report.file
    vclass = _VERDICT_CLASS[report.verdict]
    parts: list[str] = []
    parts.append(f"<title>peregrine — {_esc(f.path)}</title><style>{_CSS}</style>")
    parts.append('<div class="wrap">')
    parts.append(f"<h1>{_esc(f.path)}</h1>")

    # --- verdict banner + score rationale ---------------------------
    parts.append('<div class="card banner">')
    parts.append(f'<span class="badge {vclass}">{_VERDICT_LABEL[report.verdict]}</span>')
    parts.append(f'<span class="score">{report.score}<small> / score '
                 f"(suspicious ≥ 30, high risk ≥ 60)</small></span>")
    parts.append("</div>")

    parts.append("<h2>Verdict rationale</h2>")
    if report.score_breakdown:
        rows = "".join(
            f'<tr><td class="num {"pos" if e.points >= 0 else "neg"}">'
            f'{"+" if e.points >= 0 else ""}{e.points}</td><td>{_esc(e.reason)}</td></tr>'
            for e in report.score_breakdown
        )
        parts.append(f'<div class="card"><table><tr><th class="num">pts</th>'
                     f"<th>reason</th></tr>{rows}</table></div>")
    else:
        parts.append('<div class="card muted">no scoring signals</div>')

    # --- file identity ----------------------------------------------
    ts = _esc(f.compile_timestamp or "-")
    if f.compile_timestamp_anomaly:
        ts += f' <span class="flagline">[{_esc(f.compile_timestamp_anomaly)}]</span>'
    ident = [
        ("type", _esc(f.file_type)),
        ("size", f"{f.size:,} bytes"),
        ("sha256", f'<span class="mono">{_esc(f.sha256)}</span>'),
        ("md5", f'<span class="mono">{_esc(f.md5)}</span>'),
        ("imphash", f'<span class="mono">{_esc(f.imphash or "-")}</span>'),
        ("rich_hash", f'<span class="mono">{_esc(report.rich.hash) if report.rich else "-"}</span>'),
        ("ssdeep", f'<span class="mono">{_esc(f.ssdeep or "-")}</span>'),
        ("compiled", ts),
        ("signed", "yes (blob present, unverified)" if f.is_signed else "no"),
        ("entrypoint", f'0x{f.entry_point:x} in {_esc(f.entry_section or "?")}'),
    ]
    parts.append("<h2>File</h2><div class='card'><dl class='grid'>")
    parts.append("".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in ident))
    parts.append("</dl></div>")

    parts.append(_reputation(report))
    parts.append(_capabilities(report))
    parts.append(_attack(report))
    parts.append(_sections(report))
    parts.append(_config_blobs(report))
    parts.append(_resources(report))
    parts.append(_decoded(report))
    parts.append(_strings(report))
    parts.append(_yara(report))

    parts.append('<div class="foot">Generated by peregrine — static triage, no code executed. '
                 "Verdict is a prioritization signal, not a conviction.</div>")
    parts.append("</div>")
    return "".join(parts)


def _reputation(report: TriageReport) -> str:
    if not report.reputation:
        return ""
    out = ["<h2>Reputation (online)</h2><div class='card'>"]
    for r in report.reputation:
        if r.status == "found":
            bits = " · ".join(_esc(b) for b in (r.detections, r.family, r.first_seen) if b)
            link = (f' <a class="mono" href="{_esc(r.link)}">{_esc(r.link)}</a>'
                    if r.link else "")
            out.append(f'<div><span class="dot s3"></span><b>{_esc(r.source)}</b> '
                       f'<span class="flagline">FOUND</span> — {bits}{link}</div>')
        else:
            out.append(f'<div class="muted"><b>{_esc(r.source)}</b>: {_esc(r.status)} '
                       f"({_esc(r.note or r.status)})</div>")
    out.append("</div>")
    return "".join(out)


def _capabilities(report: TriageReport) -> str:
    if not report.capabilities:
        return ""
    out = ["<h2>Capabilities</h2><div class='card'>"]
    for c in report.capabilities:
        chips = "".join(f'<span class="chip">{_esc(a)}</span>' for a in c.attack)
        evidence = _esc(", ".join(c.evidence[:6]))
        if len(c.evidence) > 6:
            evidence += f" … +{len(c.evidence) - 6} more"
        out.append(
            f'<div style="margin-bottom:10px"><span class="dot s{c.severity}"></span>'
            f'<b>{_esc(c.name)}</b> <span class="muted">({_SEV_LABEL[c.severity]})</span> '
            f"{_esc(c.description)} {chips}"
            f'<div class="muted mono">{evidence}</div></div>'
        )
    out.append("</div>")
    return "".join(out)


def _attack(report: TriageReport) -> str:
    if not report.attack:
        return ""
    out = ["<h2>MITRE ATT&amp;CK</h2><div class='card'>"]
    current = None
    for t in report.attack:
        if t.tactic != current:
            current = t.tactic
            out.append(f'<div class="tactic">{_esc(t.tactic)}</div>')
        sources = _esc(", ".join(t.sources))
        out.append(f'<div><span class="chip">{_esc(t.id)}</span> {_esc(t.name)} '
                   f'<span class="muted">— {sources}</span></div>')
    out.append("</div>")
    return "".join(out)


def _sections(report: TriageReport) -> str:
    if not report.sections:
        return ""
    rows = []
    for s in report.sections:
        perms = ("X" if s.is_executable else "-") + ("W" if s.is_writable else "-")
        width = max(2, int(s.entropy / 8 * 80))
        ent_cls = ' class="pos"' if s.entropy >= 7.2 else ""
        flags = _esc(", ".join(s.flags))
        rows.append(
            f"<tr><td class='mono'>{_esc(s.name)}</td><td class='num'>{s.raw_size:,}</td>"
            f"<td class='num'{ent_cls}>{s.entropy:.2f}</td>"
            f"<td><span class='bar' style='width:{width}px'></span></td>"
            f"<td class='mono'>{perms}</td><td class='muted'>{flags}</td></tr>"
        )
    return (f"<h2>Sections</h2><div class='card'><table>"
            f"<tr><th>name</th><th class='num'>raw</th><th class='num'>entropy</th>"
            f"<th></th><th>perms</th><th>flags</th></tr>{''.join(rows)}"
            f"<tr><td colspan='6' class='muted'>overall file entropy: "
            f"{report.overall_entropy:.2f}</td></tr></table></div>")


def _config_blobs(report: TriageReport) -> str:
    if not report.config_blobs:
        return ""
    rows = "".join(
        f"<tr><td class='mono'>{_esc(b.section)}</td><td class='mono'>0x{b.file_offset:x}</td>"
        f"<td class='num'>{b.size:,}</td><td class='num pos'>{b.entropy:.2f}</td></tr>"
        for b in report.config_blobs
    )
    return ("<h2>Config blobs (entropy islands)</h2><div class='card'>"
            "<table><tr><th>section</th><th>file offset</th><th class='num'>size</th>"
            f"<th class='num'>entropy</th></tr>{rows}</table>"
            "<div class='muted'>localized high-entropy — likely encrypted config/payload</div></div>")


def _resources(report: TriageReport) -> str:
    flagged = [r for r in report.resources if r.flags]
    if not flagged:
        return ""
    out = ["<h2>Resources of interest</h2><div class='card'>"]
    for r in flagged:
        flags = "; ".join(_esc(x) for x in r.flags)
        out.append(f"<div><b class='mono'>{_esc(r.type)}/{_esc(r.name)}</b> "
                   f"<span class='muted'>({r.size:,} B, entropy {r.entropy:.2f})</span>"
                   f"<div class='flagline'>{flags}</div>"
                   f"<div class='muted mono'>sha256 {_esc(r.sha256)}</div></div>")
    out.append("</div>")
    return "".join(out)


def _decoded(report: TriageReport) -> str:
    if not report.decoded_strings:
        return ""
    rows = "".join(
        f"<tr><td class='mono'>{_esc(d.encoding)}</td><td>{_esc(d.category or '')}</td>"
        f"<td class='mono'>{_esc(d.value[:200])}</td></tr>"
        for d in report.decoded_strings[:40]
    )
    return ("<h2>Recovered (encoded) strings</h2><div class='card'><table>"
            f"<tr><th>encoding</th><th>category</th><th>value</th></tr>{rows}</table></div>")


def _strings(report: TriageReport) -> str:
    if not report.strings:
        return ""
    by_cat: dict[str, list[str]] = {}
    for h in report.strings:
        by_cat.setdefault(h.category, []).append(h.value)
    out = ["<h2>Strings of interest</h2><div class='card'>"]
    for cat, values in sorted(by_cat.items()):
        total = report.string_stats.get(cat, len(values))
        items = "".join(f"<div class='mono'>{_esc(v[:160])}</div>" for v in values[:8])
        more = f"<div class='muted'>… +{len(values) - 8} more</div>" if len(values) > 8 else ""
        out.append(f"<div style='margin-bottom:8px'><b>{_esc(cat)}</b> "
                   f"<span class='muted'>({total})</span>{items}{more}</div>")
    out.append("</div>")
    return "".join(out)


def _yara(report: TriageReport) -> str:
    if not report.yara:
        return ""
    out = ["<h2>YARA</h2><div class='card'>"]
    for h in report.yara:
        tags = "".join(f'<span class="chip">{_esc(t)}</span>' for t in h.tags)
        desc = _esc(h.meta.get("description", ""))
        out.append(f'<div><b>{_esc(h.rule)}</b> {tags} '
                   f'<span class="muted">{desc}</span></div>')
    out.append("</div>")
    return "".join(out)
