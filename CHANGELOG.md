# Changelog

All notable changes to **gokdogan** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

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

[0.5.1]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.5.1
[0.5.0]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.5.0
