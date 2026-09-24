# gokdogan — Architecture Overview

*gökdoğan* is Turkish for the **peregrine falcon** — the fastest hunter in the
sky. The package and command are the ASCII `gokdogan`.

**Static PE malware triage engine.** Given a Windows executable, gokdogan
extracts static features — never executing the sample — and produces a
transparent, weighted verdict: `LIKELY_CLEAN`, `SUSPICIOUS`, or `HIGH_RISK`.

- **~4,900 lines** of Python across 31 focused modules
- **~2,400 lines** of tests · **207 tests** · real-binary integration suite
- Hard deps: `pefile`, `ppdeep` · optional: `yara-python`, `py-tlsh`

This document explains *how it is built and why*. For usage, see [README.md](README.md).

---

## 1. Design principles

The whole engine is organized around five decisions that keep it correct,
fast, and trustworthy for an analyst.

| Principle | What it means in the code |
|---|---|
| **Pure functions → dataclasses** | Every analyzer is a pure function over `bytes`/`pefile.PE` returning dataclasses ([`models.py`](gokdogan/models.py)). Analyzers never know about each other or the output format. Adding a stage = one module + one line in [`engine.py`](gokdogan/engine.py). |
| **Offline by default** | The `triage()` core never touches the network and never runs the sample. The single online feature (reputation) is opt-in, hash-only, and lives in the CLI layer — so the analysis core is safe on an air-gapped malware workstation. |
| **Auditable verdict** | The score *is* the report: every point carries a human-readable reason ([`verdict.py`](gokdogan/verdict.py)). There is no hidden model an analyst can't argue with. |
| **Calibrated against false positives** | Thresholds were tuned empirically against stock signed Windows binaries, not guessed. Capability rules require a minimum number of distinct API hits; entropy islands only fire in writable sections; compressed icon resources are whitelisted. |
| **Graceful degradation** | Missing YARA, missing rules, a corrupt resource tree, an unparseable import table — each becomes a note in the report, never a crash. |

---

## 2. Pipeline

<p align="center">
  <img src="assets/pipeline.png" width="880"
       alt="gokdogan static pipeline: a sample flows through the triage stages to a transparent weighted verdict and multiple output formats">
</p>

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

## 3. Module map (31 modules, by layer)

**Core**
- [`engine.py`](gokdogan/engine.py) — orchestrator; the entire `triage()` pipeline
- [`models.py`](gokdogan/models.py) — dataclasses shared by every stage
- [`loader.py`](gokdogan/loader.py) — PE parsing, hashes, imphash, structural anomalies, (delay-)imports

**Identity & clustering**
- [`fuzzy.py`](gokdogan/fuzzy.py) — ssdeep + optional TLSH; `--compare` similarity
- [`rich.py`](gokdogan/rich.py) — Rich header hash, `@comp.id` decode, checksum-tamper detection
- [`hashes.py`](gokdogan/hashes.py) — authentihash (signature-independent) + impfuzzy import hash
- [`cluster.py`](gokdogan/cluster.py) — `--cluster` union-find grouping of a dropzone
- [`baseline.py`](gokdogan/baseline.py) — `--baseline` diff of a sample vs a known-good reference

**Structure**
- [`entropy.py`](gokdogan/entropy.py) — Shannon entropy + thresholds
- [`packers.py`](gokdogan/packers.py) — known packer sections + structural heuristics
- [`blobs.py`](gokdogan/blobs.py) — encrypted-config entropy islands
- [`resources.py`](gokdogan/resources.py) — `.rsrc` walker: embedded PEs, high-entropy blobs
- [`overlay.py`](gokdogan/overlay.py) — overlay content: magic-byte type, entropy, embedded PE
- [`signature.py`](gokdogan/signature.py) — Authenticode verification (WinVerifyTrust) + cert names
- [`dotnet.py`](gokdogan/dotnet.py) — managed/.NET CLR-header detection + obfuscator fingerprints

**Content**
- [`strings_ext.py`](gokdogan/strings_ext.py) — ASCII/UTF-16LE extraction + IOC classification
- [`decoded.py`](gokdogan/decoded.py) — FLOSS-lite: XOR/ADD/ROL/base64/hex string recovery
- [`stackstrings.py`](gokdogan/stackstrings.py) — pattern-based x86 stack-string recovery (no emulator)
- [`extractors.py`](gokdogan/extractors.py) — family config extraction (Discord/Telegram/stager URLs)

**Behavior & intelligence**
- [`exports.py`](gokdogan/exports.py) — export table + launch-mechanism detection
- [`capabilities.py`](gokdogan/capabilities.py) — API/evidence → behavior tags (capa-style)
- [`attack.py`](gokdogan/attack.py) — capabilities/YARA → MITRE ATT&CK + Navigator layer
- [`yara_scan.py`](gokdogan/yara_scan.py) — optional yara-python integration
- [`reputation.py`](gokdogan/reputation.py) — opt-in VirusTotal / MalwareBazaar hash lookup

**Verdict & reporting**
- [`verdict.py`](gokdogan/verdict.py) — transparent weighted scoring
- [`report.py`](gokdogan/report.py) — ANSI console + JSON
- [`html_report.py`](gokdogan/html_report.py) — self-contained, escaped, theme-aware HTML
- [`summary.py`](gokdogan/summary.py) — flat per-sample rows for batch CSV/JSONL
- [`misp.py`](gokdogan/misp.py) — MISP event export for threat-intel sharing
- [`web.py`](gokdogan/web.py) — optional FastAPI upload-and-triage service
- [`cli.py`](gokdogan/cli.py) — argparse CLI, exit codes, output routing

---

## 4. Analysis surface

<p align="center">
  <img src="assets/analysis-layers.png" width="980"
       alt="gokdogan analysis surface: five layers — identity, structure, content, behavior, intelligence — and the modules that feed each">
</p>

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
([`decoded.py`](gokdogan/decoded.py))

**Entropy measured, not assumed.** A 256-byte window is too small to measure
randomness: truly-random data averages only ~7.17 bits there (small-sample
bias), so the threshold was silently unreachable. Measuring the distribution
led to a 512-byte window (random ≈ 7.5+) and a 7.4 cut. ([`blobs.py`](gokdogan/blobs.py))

**False positives eliminated by calibration, not hand-waving.** Config-blob
detection was swept across 150 stock signed system binaries; read-only
`.rdata` legitimately carries high-entropy certificate data, so scanning was
restricted to writable sections → **0 false positives**. The same discipline
whitelists compressed PNG icons in the resource walker and requires minimum
distinct API hits before a capability fires.

**Security of the tool itself.** Malware strings can contain markup; the HTML
report passes every sample-derived value through `html.escape`, so opening a
report can never execute an embedded `<script>` — verified by test.
([`html_report.py`](gokdogan/html_report.py))

**Offline core, opt-in egress.** Reputation is the only networked feature. It
is off by default, sends the SHA-256 only (never the file), refuses to run
without a key (and thus never leaks a hash by accident), and is attached in
the CLI layer so the `triage()` engine stays provably offline.
([`reputation.py`](gokdogan/reputation.py))

---

## 6. Verdict model

<p align="center">
  <img src="assets/verdict-model.png" width="860"
       alt="gokdogan verdict model: the LIKELY_CLEAN / SUSPICIOUS / HIGH_RISK spectrum with thresholds and representative additive weights">
</p>

Scoring is deliberately transparent and additive, with two guard rails in the
last rows below. Representative weights:

| Signal | Points |
|---|---|
| Packer detected | +15 |
| High overall entropy (≥ 7.0) | +10 |
| Each structural anomaly | +6 |
| Capability (severity 1 / 2 / 3) | +2 / +8 / +18 |
| YARA match | rule `meta.weight`, default +15 |
| Encoded IOC/payload recovered | up to +24 |
| Valid Authenticode signature | −15, or 0 if the certificate table carries unauthenticated data |
| Signature present but not valid (self-signed, expired, unverified) | 0 |
| Packing signals together (packer, entropy, packer YARA, stub anomalies) | capped at 30 |

Thresholds: **`SUSPICIOUS` ≥ 30**, **`HIGH_RISK` ≥ 60**. The full breakdown is
printed in every report — the analyst can see exactly why a sample scored the
way it did, and YARA rules can inject their own weight to outvote heuristics.

Pipeline-friendly exit codes: `0` clean · `2` suspicious · `3` high risk.

---

## 7. Testing

**207 tests / ~2,400 lines.** Unit tests cover each analyzer in isolation with
synthetic inputs (crafted XOR/base64 payloads, fake PE buffers, planted
entropy islands, synthetic certificate tables). The integration suite runs the full pipeline against real system binaries
(`notepad.exe`, `kernel32.dll`) and asserts they never score `HIGH_RISK`
and never trip the dropper / embedded-config / phantom-string false
positives. Two known false positives are kept visible as `xfail`
tests: a stock `mmc.exe` and a validly signed `chrome.exe` both score
`HIGH_RISK`, because large legitimate programs import enough APIs for
several capability rules to stack. That is a calibration problem for a
measured benchmark, not something to hand-tune against two files. Network
code is tested with injected HTTP mocks — no real external calls.

---

## 8. Tech stack

Python 3.10+ · `pefile` (PE parsing) · `ppdeep` (pure-Python ssdeep) ·
optional `yara-python`, `py-tlsh` · standard-library `urllib` for reputation.
No web framework in the core (the upload service is an optional FastAPI extra),
no heavyweight dependencies — a self-contained CLI that
drops into a malware-lab workflow.

---

*gokdogan performs static triage only. It never executes the sample, and its
verdict is a prioritization signal, not a definitive classification. Handle
real malware inside an isolated analysis VM.*
