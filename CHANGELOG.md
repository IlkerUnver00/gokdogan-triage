# Changelog

All notable changes to **gokdogan** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.5.2] — 2026-09-24

Credibility pass: correctness fixes an expert reviewer would catch, hardening
against inputs an attacker controls, and an honest account of what the tool
does not do. Every change below was attacked by independent reviewers before
release; their bypasses are now regression tests.

### Fixed
- **Certificate-table data (CVE-2013-3900).** Data placed in the Authenticode
  certificate table was treated as "just the signature", so a 3CX-style
  payload stayed invisible and could still earn the valid-signature credit.
  The table is now parsed: only the first revision-2.0 PKCS_SIGNED_DATA entry
  is the signature, and only up to the real end of its blob (a small BER walker
  follows indefinite lengths). Bytes after it, every other entry and any tail
  count as unauthenticated. From 16 bytes on they raise an anomaly and cancel
  the credit; zero fill and stray alignment bytes do not.
- **Crash on a malformed header.** A PE declaring fewer than 15 data
  directories could crash triage (and abort a batch run). Directory lookups
  are now bounds-checked.
- **No credit for signatures that are not valid.** A self-signed, expired or
  unverified signature took 8 points off, and anyone can self-sign. It now
  earns nothing, with a 0-point line saying why.
- **Rich header product ids.** The table mislabelled most entries (0x91
  `Linker900` showed as "linker 8.00 (VS2005)", 0x5D `Implib710` as a linker)
  and had none of the VS2015–2022 ids. It now covers 0x00–0x10E with toolset
  eras.
- **Packing counted several times over.** Packer name, high entropy, packer
  YARA rules and unpacking-stub anomalies describe one fact; summed, they put
  a plain UPX-packed file at `HIGH_RISK` with no behavioural evidence. The
  group is now capped at the `SUSPICIOUS` threshold, and membership is decided
  by fixed prefixes, so an attacker-named resource cannot pull real dropper
  evidence under the cap.
- **.NET assemblies no longer look packed.** A structurally valid IL-only
  assembly (COR20 header, `BSJB` metadata, IL-only flag) that imports only
  `mscoree!_CorExeMain` no longer raises the low-import anomaly or the packer's
  tiny-import heuristic. A bogus CLR header on a native file does not qualify.
- **Clustering.** A shared imphash or impfuzzy no longer links .NET assemblies
  or packer stubs, whose import tables are generic, and link reasons are no
  longer lost when clusters merge.
- **MISP export.** Only the sample's own file hashes and the network IOCs it
  hid or configured (decoded strings, extracted config) are marked `to_ids`.
  Filenames, fuzzy hashes, plaintext strings and the authentihash (identical
  to the genuine vendor file's for a padded-certificate sample) are context.
- **HTML report:** a tampered or revoked signature now renders red (the CSS
  variable it used was undefined).
- The Windows build passes `--noupx`, so the bundled binaries are never
  UPX-compressed.

### Documentation
- New README section, "What gokdogan does not do": static-only; where capa,
  FLOSS, Detect It Easy, PEStudio and AssemblyLine go further; the .NET blind
  spot; unmeasured accuracy; Windows-only signature verification; strict
  certificate-table checks.
- The docs said the integration suite asserts `mmc.exe` never scores
  `HIGH_RISK`. It never ran `mmc.exe`, and `mmc.exe` does score `HIGH_RISK`.
  The claim is corrected, and two known false positives (`mmc.exe`, a signed
  `chrome.exe`) are kept visible as `xfail` tests until a measured
  recalibration fixes them.
- Verdict tables describe the packing cap and the signature rules; counts and
  the Python requirement (3.10+) corrected everywhere.

### CI
- Tests run on Python 3.10, 3.11 and 3.12.

### Tests
- 174 → 207 tests: 204 passing, 2 known-false-positive `xfail`, 1 skipped
  (optional `py-tlsh` not installed).

## [0.5.1] — 2026-09-16

Publishability audit pass — detection hardening, packaging, and distribution.
Now installable from PyPI: `pip install gokdogan-triage`.

### Added
- **Published to PyPI** via GitHub Actions trusted publishing (OIDC, no stored
  token) — `pip install gokdogan-triage`.
- `[project.urls]` and PEP 639 license metadata in the package.
- Network-free demo sample builder
  ([`examples/make_demo_sample.py`](examples/make_demo_sample.py)) so anyone can
  watch a `HIGH_RISK` triage without touching real malware.

### Changed
- **Reputation now feeds the verdict score** (VirusTotal detection ratio /
  MalwareBazaar) instead of being display-only.
- **Signed-injector masking fixed:** a valid Authenticode signature no longer
  cancels a severe capability — the signature credit is capped and the verdict
  floors at `SUSPICIOUS` when a severity-3 capability is present, without
  false-positiving stock signed system binaries.
- Web upload service reads the body in chunks with a **64 MB cap** (HTTP 413 on
  overflow).
- Stack-string recovery tolerates x64 REX-prefixed instructions.
- CI actions bumped to `checkout@v5` / `setup-python@v6`.

### Fixed
- Documentation counts and module maps corrected across README, ARCHITECTURE,
  and MIMARI.

### Tests
- 163 → **173 tests**; console-report coverage 11% → ~70%, overall ~85%.

## [0.5.0] — 2026-09-02

First tagged release — a complete static PE triage engine with a Windows
distribution. Consolidates all prior feature work into one shippable tool.

### Added
- **Windows distribution:** one-file `gokdogan.exe` (PyInstaller) and a
  per-user installer `gokdogan-setup.exe` (Inno Setup); pushing a `v*` tag
  builds both and attaches them to a GitHub Release.
- **Authenticode verification** — offline `WinVerifyTrust`, with signer/issuer
  names and tampered/expired/untrusted detection.
- **Overlay analysis** and **.NET/CLR detection** with obfuscator fingerprints.
- **authentihash + impfuzzy**, dropzone **clustering** (`--cluster`), and
  known-good **baseline diff** (`--baseline`).
- **MISP event export** and an optional **FastAPI upload-and-triage web
  service** (`[web]` extra).
- **Stack-string recovery** (pattern-based, no emulator).
- **Opt-in, hash-only reputation** (VirusTotal / MalwareBazaar), off by
  default — only the SHA-256 ever leaves the host.
- **FLOSS-lite** encoded-string recovery (single-byte XOR/ADD/ROL + Base64/hex)
  and **entropy-island** encrypted-config-blob spotting.
- **Reporting:** ANSI console, JSON, self-contained HTML, CSV/JSONL batch, and
  MITRE ATT&CK Navigator layer export.
- **Identity & clustering:** imphash, Rich header hash, ssdeep, optional TLSH.
- **Core engine:** PE loader, per-section entropy, packer detection, string
  classification, import-based capability tags, YARA, and a transparent
  weighted verdict (`LIKELY_CLEAN` / `SUSPICIOUS` / `HIGH_RISK`) where every
  point carries a printed reason.

[0.5.2]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.5.2
[0.5.1]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.5.1
[0.5.0]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.5.0
