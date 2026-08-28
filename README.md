# gokdogan 🦅

[![tests](https://github.com/IlkerUnver00/gokdogan-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/IlkerUnver00/gokdogan-triage/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![ruff](https://img.shields.io/badge/lint-ruff-orange)](https://docs.astral.sh/ruff/)
[![license](https://img.shields.io/badge/license-MIT-green)](#license)

**Static PE malware triage engine.** Feed it a Windows executable; it extracts
static features — hashes, imphash, per-section entropy, packer artifacts,
classified strings, import-based capability tags, YARA matches — and produces a
transparent, weighted triage verdict: `LIKELY_CLEAN`, `SUSPICIOUS`, or `HIGH_RISK`.

**gökdoğan** is Turkish for the *peregrine falcon* — the fastest hunter in the
sky. A fitting name: triage is about speed, deciding in seconds which samples
deserve a full analyst's attention. (The package and command are the ASCII
`gokdogan`.)

> ⚠️ **Triage, not conviction.** gokdogan never executes the sample and its
> verdict is a prioritization signal, not a definitive classification. Handle
> real malware only inside an isolated analysis VM.

> 📐 **Architecture:** [ARCHITECTURE.md](ARCHITECTURE.md) (English) ·
> [MIMARI.md](MIMARI.md) (Türkçe) ·
> **[live visual page ↗](https://ilkerunver00.github.io/gokdogan-triage/)**
> ([source](docs/index.html))

## What it does

```text
            ┌────────────────────────────────────────────────┐
            │                  gokdogan                     │
 sample.exe │  ┌──────────┐  ┌─────────┐  ┌──────────────┐   │
 ──────────▶│  │ loader   │─▶│ packers │  │ strings_ext  │   │
            │  │ pefile   │  │ entropy │  │ classifier   │   │
            │  └────┬─────┘  └────┬────┘  └──────┬───────┘   │
            │       │             │              │           │
            │       ▼             ▼              ▼           │
            │  ┌──────────────────────────────────────────┐  │
            │  │ capabilities (API → behavior)  +  YARA   │  │
            │  └───────────────────┬──────────────────────┘  │
            │                      ▼                         │
            │            verdict (weighted score)            │
            └──────────────────────┬─────────────────────────┘
                                   ▼
                     console report  +  JSON export
```

| Stage | Signal | Why it matters in triage |
|---|---|---|
| **Hashing** | MD5/SHA1/SHA256 + **imphash** | imphash clusters samples by import table — different payloads built from the same builder share it |
| **Fuzzy hashing** | **ssdeep** + optional **TLSH** | similarity-preserving: two builds of the same malware score as related even when every crypto hash differs; `--compare` scores a sample against a reference |
| **Rich header** | toolchain **rich_hash** + decoded `@comp.id` entries + checksum validation | fingerprints the exact build environment (more specific than imphash); a bad checksum means a forged/copied header — an anti-clustering tell |
| **Resource walker** | enumerates `.rsrc`, hashes each leaf, flags **embedded PEs** and **high-entropy blobs** | the dropper/packer's favourite hiding spot; compressed image resources are whitelisted so clean binaries stay quiet |
| **Export table** | DLL name, named/ordinal counts, forwarders, launch-mechanism exports (`ReflectiveLoader`, `DllRegisterServer`, `ServiceMain`) | tells you how a DLL expects to be run — reflective beacon, `regsvr32` target, or service host |
| **Delay-load imports** | lazily-resolved imports, **merged into capability analysis** | APIs hidden in the delay-load table (network, injection) still light up their capability tags |
| **Entropy** | Shannon entropy per section + overall | executable code sits ~6 bits/byte; ≥7.2 means compressed/encrypted content |
| **Packer detection** | known section names (UPX, VMProtect, Themida, …) + structural heuristics | packing is the single cheapest evasion; heuristics survive renamed sections |
| **Anomalies** | W+X sections, TLS callbacks, wiped timestamps, missing imports, oversized overlay, bad checksum | things real compilers rarely produce |
| **Authenticode** | real signature **verification** via Windows `WinVerifyTrust` (offline) + signer/issuer names | distinguishes a *valid* signature from a **tampered** one (digest mismatch = modified after signing), expired, or untrusted-root — a strong trojanized-binary tell |
| **Strings** | ASCII + UTF-16LE extraction, regex classification (URL, IP, domain, registry, PDB path, shell command, user-agent) | fastest source of IOCs and intent; CA/vendor noise is filtered out |
| **Encoded strings (FLOSS-lite)** | brute-force **single-byte XOR/ADD/ROL** + **Base64/hex** recovery of hidden IOCs and embedded PEs | surfaces the C2/commands malware encodes to dodge a plain `strings` pass — via a fast key-invariant adjacency search, not code emulation |
| **Config blobs** | **entropy islands** — localized high-entropy regions inside calm writable sections | spots an encrypted config/staged payload hiding in `.data` without decrypting it; read-only `.rdata` cert data is excluded so clean binaries stay quiet |
| **Capabilities** | import table → behavior tags (`process-injection`, `keylogging`, `anti-recovery`, …), capa-style with per-rule minimum hit counts | tells the analyst *what it could do* without running it |
| **ATT&CK mapping** | capabilities + YARA rules → MITRE ATT&CK techniques, grouped by tactic in kill-chain order | speaks the language of detections, reports, and threat intel |
| **YARA** | bundled + user-supplied rules; `meta.weight` feeds the score directly, `meta.attack` feeds the ATT&CK summary | drop your team's rules in and they participate in the verdict |
| **Verdict** | transparent weighted score with a printed breakdown | every point has a reason — the analyst can argue with it |
| **Reporting** | ANSI console, JSON, **self-contained HTML** (verdict rationale embedded), CSV/JSONL batch, ATT&CK Navigator layer | one engine, many outputs — terminal for triage, HTML for the case file, CSV for the dropzone, JSON for the pipeline |
| **Reputation** (opt-in) | VirusTotal + MalwareBazaar **hash-only** lookup, off by default | "is this already known?" without uploading the sample — only the SHA-256 leaves, and only when you pass `--reputation` with a key |

## Install

```bash
pip install -e .[dev]
```

Hard dependencies are `pefile` and `ppdeep` (pure-Python ssdeep — no C
toolchain). Optional: `yara-python` for the YARA stage and `py-tlsh` for
TLSH fuzzy hashing — each degrades to a note in the report when absent.

```bash
pip install -e .[dev,tlsh]   # include TLSH (needs a C++ compiler)
```

## Usage

```bash
# full report for one sample
gokdogan sample.exe

# scan a directory, one summary line per file
gokdogan C:\samples --quiet

# JSON for pipelines (SOAR, sandbox pre-filter, …)
gokdogan sample.exe --json report.json

# self-contained HTML report to attach to a case (verdict rationale embedded)
gokdogan sample.exe --html report.html

# MITRE ATT&CK Navigator layer — load it at
# https://mitre-attack.github.io/attack-navigator/ to see the sample's
# techniques highlighted on the matrix, shaded by triage confidence
gokdogan sample.exe --attack-layer sample.attack.json

# fuzzy-compare a sample against a known reference (clustering)
gokdogan suspect.exe --compare known_stealer.exe

# batch-triage a whole dropzone into one sortable table
gokdogan C:\dropzone --csv triage.csv
gokdogan C:\dropzone --jsonl triage.jsonl     # one JSON object per line, SIEM-ready

# your own rule set
gokdogan sample.exe --rules C:\rules\team-rules

# opt-in reputation: sends ONLY the SHA-256 (never the file) to VT/MalwareBazaar
gokdogan sample.exe --reputation --vt-key $VT_API_KEY
```

Reputation lookup is the **only** feature that touches the network, and it
is off unless you pass `--reputation` with an API key (`--vt-key`/`--mb-key`
or `VT_API_KEY`/`MB_API_KEY`). It sends the sample's SHA-256 only — never the
file — and prints a heads-up before any hash leaves the host. The core
`triage()` engine is always fully offline.

In batch mode gokdogan prints one line per sample plus a final tally
(`N file(s): X high-risk, Y suspicious, Z clean`) and writes a flat
summary row per file — verdict, score, imphash/rich_hash/ssdeep (for
clustering), capabilities, ATT&CK techniques, YARA hits, and counts of
embedded PEs / encoded strings / config blobs / anomalies. Sort the CSV by
score to work a dropzone worst-first, or group by imphash/rich_hash to
cluster variants.

Exit codes are pipeline-friendly: `0` clean, `2` suspicious, `3` high risk —
so `gokdogan dropzone/ --quiet && echo OK` works as a gate.

### Sample output

```text
gokdogan triage report — invoice_scan.exe

── File ──────────────────────────────────────────────────
  type       : PE32 executable (GUI) x86
  imphash    : 09d0478591d4f788cb3e5ea416c25237
  rich_hash  : 1e77c08b15cd344c938cc0b7389bbd3b
  ssdeep     : 6144:wYXtmo124T7G/baHXOgAcIXl0FIu0CH+h0FuiiCwSQ5gf:NXtmk2IG/GHAR0FIu7FQ5G
  compiled   : 2031-01-04 11:20:41 UTC  [compile timestamp is in the future]
  signed     : no

── Packer ────────────────────────────────────────────────
  DETECTED: UPX
    - section name 'UPX0' is a known UPX artifact
    - executable section 'UPX1' has entropy 7.91 (>= 7.2)

── Capabilities ──────────────────────────────────────────
  [!!!] process-injection      Writes and executes code in other processes  (T1055)
        CreateRemoteThread, VirtualAllocEx, WriteProcessMemory
  [!!!] keylogging             Captures keystrokes  (T1056.001)
        GetAsyncKeyState, SetWindowsHookExW

── MITRE ATT&CK ──────────────────────────────────────────
  Defense Evasion
    T1055       Process Injection
                from: process-injection, yara:Injection_API_Cluster
  Collection
    T1056.001   Input Capture: Keylogging
                from: keylogging
  Impact
    T1490       Inhibit System Recovery
                from: anti-recovery, yara:Shadow_Copy_Deletion

── Verdict ───────────────────────────────────────────────
  +15  packer detected: UPX
  +18  capability: process-injection
  +18  capability: keylogging
   +5  compile timestamp is in the future
  ...
  HIGH RISK  (score 74, thresholds: suspicious ≥ 30, high risk ≥ 60)
```

## Project layout

```text
gokdogan/
├── gokdogan/
│   ├── engine.py         # orchestrator: triage() pipeline
│   ├── loader.py         # PE parsing, hashes, imphash, anomalies
│   ├── rich.py          # Rich header hash, @comp.id decode, checksum check
│   ├── resources.py      # .rsrc walker: embedded PEs, high-entropy blobs
│   ├── fuzzy.py          # ssdeep + optional TLSH fuzzy hashing / compare
│   ├── entropy.py        # Shannon entropy + thresholds
│   ├── packers.py        # known-section-name table + heuristics
│   ├── strings_ext.py    # ASCII/UTF-16LE extraction + classification
│   ├── decoded.py        # FLOSS-lite: XOR/ADD/ROL/Base64/hex string recovery
│   ├── blobs.py          # config-blob spotting: entropy islands in .data
│   ├── exports.py        # export table + launch-mechanism export detection
│   ├── capabilities.py   # API → behavior rule table (capa-style)
│   ├── attack.py         # capability/YARA → MITRE ATT&CK technique mapping
│   ├── yara_scan.py      # optional yara-python integration
│   ├── verdict.py        # weighted scoring, thresholds
│   ├── models.py         # dataclasses shared by all stages
│   ├── report.py         # ANSI console + JSON renderers
│   ├── html_report.py    # self-contained HTML report (escaped, theme-aware)
│   ├── reputation.py     # opt-in VirusTotal / MalwareBazaar hash lookup
│   ├── summary.py        # flat per-sample rows for batch CSV/JSONL
│   └── cli.py            # argparse CLI, exit codes
├── rules/                # bundled starter YARA rules
└── tests/                # pytest: unit per module + e2e on notepad.exe
```

## Design notes

- **Every stage is a pure function over `bytes`/`pefile.PE` → dataclasses.**
  Analyzers don't know about each other or about the output format, so adding
  a stage (e.g. rich-header hashing) means one module + one line in `engine.py`.
- **Capability rules require minimum distinct API hits** — `GetTickCount`
  alone never lights up `anti-debug`; three timing/debug APIs together do.
  This is the difference between a tag an analyst trusts and alert fatigue.
- **The verdict is auditable by construction.** The score breakdown *is* the
  report; there is no hidden model. YARA rules can inject their own weight via
  `meta.weight`, so a team's high-confidence family rules can outvote heuristics.
- **Graceful degradation**: no yara-python, no rules dir, unparseable imports —
  each degrades to a note in the report instead of a crash.
- **Offline by default.** The `triage()` engine never touches the network;
  the sample is never executed. The single online feature (reputation) is
  opt-in, hash-only, and lives in the CLI layer — so the analysis core stays
  safe to run on an air-gapped malware workstation.

## Roadmap

- [x] **v0.1 — core engine** (this repo)
  - [x] PE parsing, hashes, imphash, section entropy
  - [x] packer detection (known names + heuristics)
  - [x] structural anomaly checks (W+X, TLS callbacks, overlay, timestamps)
  - [x] string extraction (ASCII + UTF-16LE) and IOC classification
  - [x] capa-style capability tagging from the import table
  - [x] MITRE ATT&CK technique mapping (capabilities + YARA `meta.attack`), grouped by tactic
  - [x] ATT&CK Navigator layer export (`--attack-layer`), shaded by triage confidence
  - [x] YARA integration with score-weighted rules
  - [x] transparent weighted verdict + ANSI/JSON reports
  - [x] pytest suite incl. e2e against known-benign system binaries
- [ ] **v0.2 — better clustering**
  - [x] TLSH/ssdeep fuzzy hashing + `--compare` similarity scoring
  - [x] Rich header hash, `@comp.id` toolchain decode, and checksum-tamper detection
  - [x] resource walker: embedded PEs in `.rsrc`, high-entropy blobs, dropper tagging
  - [x] export table analysis + delay-load imports merged into capabilities
  - [ ] `--baseline` mode: diff a sample against a known-good imphash/section set
- [ ] **v0.3 — deeper strings**
  - [x] single-byte XOR/ADD/ROL encoded-string recovery (FLOSS-lite), key-invariant adjacency search
  - [x] Base64 + hex blob detection and decode (IOCs and embedded PEs)
  - [x] config-blob spotting: entropy islands inside calm writable sections
  - [ ] true stack-string recovery (needs lightweight code emulation)
- [ ] **v0.4 — lab integration**
  - [x] batch mode with CSV/JSONL summary for a whole dropzone
  - [x] self-contained HTML report with embedded verdict rationale
  - [x] VirusTotal / MalwareBazaar hash lookup (opt-in, hash-only)

## Testing

```bash
pytest -v
```

Over 100 tests: unit tests cover each analyzer in isolation with synthetic
inputs, while the integration suite runs the full pipeline against real
system binaries (`notepad.exe`, `kernel32.dll`, `mmc.exe`) and asserts that
stock Microsoft binaries never score `HIGH_RISK` and never trip the
dropper / embedded-config / phantom-string false positives.

## License

MIT
