# peregrine — Architecture Overview

**Static PE malware triage engine.** Given a Windows executable, peregrine
extracts static features — never executing the sample — and produces a
transparent, weighted verdict: `LIKELY_CLEAN`, `SUSPICIOUS`, or `HIGH_RISK`.

- **~3,300 lines** of Python across 21 focused modules
- **~1,300 lines** of tests · **114 tests** · real-binary integration suite
- Hard deps: `pefile`, `ppdeep` · optional: `yara-python`, `py-tlsh`

This document explains *how it is built and why*. For usage, see [README.md](README.md).

---

## 1. Design principles

The whole engine is organized around five decisions that keep it correct,
fast, and trustworthy for an analyst.

| Principle | What it means in the code |
|---|---|
| **Pure functions → dataclasses** | Every analyzer is a pure function over `bytes`/`pefile.PE` returning dataclasses ([`models.py`](peregrine/models.py)). Analyzers never know about each other or the output format. Adding a stage = one module + one line in [`engine.py`](peregrine/engine.py). |
| **Offline by default** | The `triage()` core never touches the network and never runs the sample. The single online feature (reputation) is opt-in, hash-only, and lives in the CLI layer — so the analysis core is safe on an air-gapped malware workstation. |
| **Auditable verdict** | The score *is* the report: every point carries a human-readable reason ([`verdict.py`](peregrine/verdict.py)). There is no hidden model an analyst can't argue with. |
| **Calibrated against false positives** | Thresholds were tuned empirically against stock signed Windows binaries, not guessed. Capability rules require a minimum number of distinct API hits; entropy islands only fire in writable sections; compressed icon resources are whitelisted. |
| **Graceful degradation** | Missing YARA, missing rules, a corrupt resource tree, an unparseable import table — each becomes a note in the report, never a crash. |

---

## 2. Pipeline

```
                          ┌──────────────────────────────────────────────┐
   sample.exe  ─────────▶ │                 engine.triage()              │
   (never run)            │                                              │
                          │  loader ─ hashes, imphash, sections,         │
                          │           anomalies, imports, delay-imports  │
                          │  rich   ─ toolchain hash + checksum          │
                          │  fuzzy  ─ ssdeep / TLSH                       │
                          │  packers ─ known names + heuristics          │
                          │  resources ─ embedded PEs, high-entropy       │
                          │  blobs  ─ encrypted-config entropy islands   │
                          │  strings_ext ─ classified IOC strings        │
                          │  decoded ─ XOR/ADD/ROL/base64/hex recovery    │
                          │  exports ─ launch-mechanism exports          │
                          │  capabilities ─ APIs+evidence → behavior tags│
                          │  attack ─ capabilities/YARA → MITRE ATT&CK    │
                          │  yara   ─ weighted rule matches              │
                          │  verdict ─ transparent weighted score        │
                          └───────────────────────┬──────────────────────┘
                                                  ▼
      console · JSON · HTML · CSV/JSONL · ATT&CK Navigator layer   (+ opt-in reputation)
```

Each stage writes one slice of a `TriageReport`; the reporters and the
verdict engine only ever read that structure. Presentation and analysis are
fully decoupled.

---

## 3. Module map (21 modules, by layer)

**Core**
- [`engine.py`](peregrine/engine.py) — orchestrator; the entire `triage()` pipeline
- [`models.py`](peregrine/models.py) — dataclasses shared by every stage
- [`loader.py`](peregrine/loader.py) — PE parsing, hashes, imphash, structural anomalies, (delay-)imports

**Identity & clustering**
- [`fuzzy.py`](peregrine/fuzzy.py) — ssdeep + optional TLSH; `--compare` similarity
- [`rich.py`](peregrine/rich.py) — Rich header hash, `@comp.id` decode, checksum-tamper detection

**Structure**
- [`entropy.py`](peregrine/entropy.py) — Shannon entropy + thresholds
- [`packers.py`](peregrine/packers.py) — known packer sections + structural heuristics
- [`blobs.py`](peregrine/blobs.py) — encrypted-config entropy islands
- [`resources.py`](peregrine/resources.py) — `.rsrc` walker: embedded PEs, high-entropy blobs

**Content**
- [`strings_ext.py`](peregrine/strings_ext.py) — ASCII/UTF-16LE extraction + IOC classification
- [`decoded.py`](peregrine/decoded.py) — FLOSS-lite: XOR/ADD/ROL/base64/hex string recovery

**Behavior & intelligence**
- [`exports.py`](peregrine/exports.py) — export table + launch-mechanism detection
- [`capabilities.py`](peregrine/capabilities.py) — API/evidence → behavior tags (capa-style)
- [`attack.py`](peregrine/attack.py) — capabilities/YARA → MITRE ATT&CK + Navigator layer
- [`yara_scan.py`](peregrine/yara_scan.py) — optional yara-python integration
- [`reputation.py`](peregrine/reputation.py) — opt-in VirusTotal / MalwareBazaar hash lookup

**Verdict & reporting**
- [`verdict.py`](peregrine/verdict.py) — transparent weighted scoring
- [`report.py`](peregrine/report.py) — ANSI console + JSON
- [`html_report.py`](peregrine/html_report.py) — self-contained, escaped, theme-aware HTML
- [`summary.py`](peregrine/summary.py) — flat per-sample rows for batch CSV/JSONL
- [`cli.py`](peregrine/cli.py) — argparse CLI, exit codes, output routing

---

## 4. Analysis surface

| Axis | Signals |
|---|---|
| **Identity / clustering** | MD5·SHA1·SHA256, imphash, Rich-header hash, ssdeep, TLSH |
| **Structure** | per-section + overall entropy, entropy islands, packer detection, W+X sections, TLS callbacks, oversized overlay, wiped/future timestamps, checksum mismatch |
| **Content** | classified IOC strings (URL/IP/domain/registry/PDB/command/UA), XOR/ADD/ROL/base64/hex-recovered strings, embedded PEs, encrypted-config blobs |
| **Behavior** | import + delay-import + export capabilities (injection, keylogging, persistence, anti-debug, anti-recovery, reflective-loading, dropper, …) with per-rule minimum hit counts |
| **Intelligence** | MITRE ATT&CK technique mapping (grouped by tactic), YARA, opt-in reputation |

---

## 5. Engineering highlights

These are the decisions that go beyond wiring a library together — the parts
worth talking through in an interview.

**Key-invariant adjacency search for encoded strings.** Brute-forcing 255
single-byte keys × anchors over a whole binary took ~2.4 s on a 800 KB DLL.
The insight: under any single-byte XOR/ADD, `encoded[i] ⊕ encoded[i-1]` is
*independent of the key*. Transforming the buffer once (XOR via a big-integer
shift, at C speed) turns key detection into a single substring search per
anchor — **2,440 ms → 133 ms**, with full coverage retained.
([`decoded.py`](peregrine/decoded.py))

**Entropy measured, not assumed.** A 256-byte window is too small to measure
randomness: truly-random data averages only ~7.17 bits there (small-sample
bias), so the threshold was silently unreachable. Measuring the distribution
led to a 512-byte window (random ≈ 7.5+) and a 7.4 cut. ([`blobs.py`](peregrine/blobs.py))

**False positives eliminated by calibration, not hand-waving.** Config-blob
detection was swept across 150 stock signed system binaries; read-only
`.rdata` legitimately carries high-entropy certificate data, so scanning was
restricted to writable sections → **0 false positives**. The same discipline
whitelists compressed PNG icons in the resource walker and requires minimum
distinct API hits before a capability fires.

**Security of the tool itself.** Malware strings can contain markup; the HTML
report passes every sample-derived value through `html.escape`, so opening a
report can never execute an embedded `<script>` — verified by test.
([`html_report.py`](peregrine/html_report.py))

**Offline core, opt-in egress.** Reputation is the only networked feature. It
is off by default, sends the SHA-256 only (never the file), refuses to run
without a key (and thus never leaks a hash by accident), and is attached in
the CLI layer so the `triage()` engine stays provably offline.
([`reputation.py`](peregrine/reputation.py))

---

## 6. Verdict model

Scoring is deliberately transparent and additive. Representative weights:

| Signal | Points |
|---|---|
| Packer detected | +15 |
| High overall entropy (≥ 7.0) | +10 |
| Each structural anomaly | +6 |
| Capability (severity 1 / 2 / 3) | +2 / +8 / +18 |
| YARA match | rule `meta.weight`, default +15 |
| Encoded IOC/payload recovered | up to +24 |
| Embedded Authenticode signature (unverified) | −8 |

Thresholds: **`SUSPICIOUS` ≥ 30**, **`HIGH_RISK` ≥ 60**. The full breakdown is
printed in every report — the analyst can see exactly why a sample scored the
way it did, and YARA rules can inject their own weight to outvote heuristics.

Pipeline-friendly exit codes: `0` clean · `2` suspicious · `3` high risk.

---

## 7. Testing

**114 tests / ~1,300 lines.** Unit tests cover each analyzer in isolation with
synthetic inputs (crafted XOR/base64 payloads, fake PE buffers, planted
entropy islands). The integration suite runs the full pipeline against real
system binaries (`notepad.exe`, `kernel32.dll`, `mmc.exe`) and asserts that
stock Microsoft binaries never score `HIGH_RISK` and never trip the
dropper / embedded-config / phantom-string false positives. Network code is
tested with injected HTTP mocks — no real external calls.

---

## 8. Tech stack

Python 3.12 · `pefile` (PE parsing) · `ppdeep` (pure-Python ssdeep) ·
optional `yara-python`, `py-tlsh` · standard-library `urllib` for reputation.
No web framework, no heavyweight dependencies — a self-contained CLI that
drops into a malware-lab workflow.

---

*peregrine performs static triage only. It never executes the sample, and its
verdict is a prioritization signal, not a definitive classification. Handle
real malware inside an isolated analysis VM.*
