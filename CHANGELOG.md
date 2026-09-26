# Changelog

All notable changes to **gokdogan** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased] — 0.6.0

False positives, measured and cut. A new benchmark script triaged installed
software on one workstation and counted every verdict above `LIKELY_CLEAN`
as a false positive. Each change below removes a cause it found, was priced
on the same benign files before it went in, and was attacked by independent
reviewers for lost detection; their findings are fixed and are now tests.

| Benign PE files, one Windows 11 machine | v0.5.2 | this release |
|---|---:|---:|
| Tuning sample (2,887 files): `SUSPICIOUS` or worse | 11.8% (341) | 2.0% (58) |
| Tuning sample: `HIGH_RISK` | 1.9% (56) | 0.1% (3) |
| Held-out sample (2,694 other files): `SUSPICIOUS` or worse | 12.7% (341) | 2.2% (59) |
| Held-out sample: `HIGH_RISK` | 2.2% (59) | 0.15% (4) |

The held-out files played no part in tuning, so that row is the estimate to
quote (95% interval 1.7–2.8%; native PE files alone 17.7% → 3.0%). No file
clean at v0.5.2 is flagged now, in either sample. It is one machine's
software, and only the benign half of a benchmark:
recall on real malware is still unmeasured (see README, "What gokdogan does
not do").

### Added
- **`scripts/benign_sweep.py`**: the false-positive benchmark. It sweeps PE
  files (or a seeded random sample), in parallel with a per-file timeout, and
  writes per-file results, a signal table (which reasons fire on benign
  files, and how many points they carry in flagged ones) and the worst files.
  `--paths-from` re-scores exactly the files of an earlier run,
  `--exclude-results` draws a held-out sample, and `--engine` pins the code
  under test; the engine's code hash and the arguments are recorded.
- **Detection guard** (`tests/archetypes.py`): twelve synthetic
  malware-shaped reports whose verdicts may not fall below what v0.5.2 gave
  them, with one documented exception (below).
- `triage_bytes()` triages PE bytes that are not on disk.
- JSON output: `import_count` on the report, `source` on each capability
  (imports, exports, strings, decoded, resources, sections), `matched` text
  on each YARA hit.

### Changed — scoring
- **Common capabilities in large programs are capped.** In a file that
  imports 200 or more distinct functions, the severity 1–2 tags read from
  imports and exports (network, crypto, registry, screen, clipboard,
  privileges, services, …) count at most 16 points together. They were the
  main source of false positives: a program that large has them all. Below
  200 imports, and for severity-3 tags and tags read from content, nothing
  changes. Duplicate and delay-load imports do not count towards the 200;
  a sample that links 200 real functions still gets the cap (a known limit).
- **One fact counts once.** A YARA rule whose `meta.overlaps` names a
  capability that fired on the same matched text adds only what its weight
  exceeds the capability's points by (`Injection_API_Cluster` vs
  `process-injection`, `Shadow_Copy_Deletion` vs `anti-recovery`). A rule
  that matched other text (injection APIs resolved by name, not imported)
  counts in full.
- **Capability rules need specific APIs.** `anti-debug` needs
  `CheckRemoteDebuggerPresent` or `NtQueryInformationProcess`: the timing and
  `IsDebuggerPresent` calls it used to count are linked into every MSVC
  program. `keylogging` needs a capture mechanism (hook, async polling, raw
  input) plus a second one, a keyboard-state read or a key-to-character
  translation; `GetKeyState` and `MapVirtualKey` alone are ordinary GUI code.
  The ANSI and wide variants of one function count once.
- `persistence-registry` from registry-write imports alone is severity 1
  (still 3 with Run-key strings). The export-derived `regsvr32-loadable` and
  `service-dll` tags are severity 1: every COM server and service DLL has them.
- TLS callbacks count 2 points instead of 6 (present in 25% of benign files);
  network IOC strings count at most 5 instead of 10 (present in 52%).
- **Commands.** A string counts as a command when the invocation is
  suspicious: encoded or hidden PowerShell (any prefix of `-EncodedCommand`,
  `-WindowStyle`, `-ExecutionPolicy`), Defender exclusions, `certutil`
  decode/download, `bitsadmin` transfers, `regsvr32 /i:`, `mshta` with a URL
  or script, `rundll32`/`regsvr32`/`wscript` run from a user-writable folder,
  `schtasks /create`, `sc create`, `net user … /add`, backup and log
  destruction (`vssadmin`, `wmic shadowcopy`, `bcdedit`, `wbadmin`,
  `wevtutil`), with or without `.exe` and a full path. A tool that is merely
  named (`C:\Windows\System32\rundll32.exe`) is a new `lolbin` category:
  shown, not scored.

### Fixed
- **Reproducible builds.** A `/Brepro` binary stores a hash where the link
  time would be, so it read as "compiled in the future" or "before the PE
  era": timestamp anomalies fell from 62% to 4% of the benign files. Such a
  stamp is now shown as a hash and not flagged; a zero stamp is flagged
  whatever the debug directory says.
- **Resources.** Media resources are recognised by their header, whatever
  type they are filed under (MFC and Office keep hundreds of PNGs under a
  custom type): one DLL scored 2,363 from them. Archives (ZIP, CAB, gzip, 7z,
  bzip2, xz) stay flagged. Resource anomalies are one note per kind, not one
  per resource.
- **Stager URLs** stop at the first binary byte instead of running through
  NULs into the next string, and a bare host prefix (a paste id appended at
  runtime) is still extracted.
- **Classification cost is linear.** The command patterns bound every gap,
  and encoded-string recovery classifies each printable run once, so a long
  hostile string cannot stall triage.
- The integration tests on `mmc.exe` and a signed `chrome.exe`, kept as
  known false positives (`xfail`) in 0.5.2, now pass as ordinary tests:
  `mmc.exe` scores 18 (`LIKELY_CLEAN`, was `HIGH_RISK` 83) and `chrome.exe` 30
  (`SUSPICIOUS`, held there by the signature floor; was `HIGH_RISK` 79).

### Known trade-off
- A ransomware sample whose only plaintext tell is one shadow-copy command
  (its note encrypted) is now `SUSPICIOUS` rather than `HIGH_RISK`: at
  v0.5.2 the capability and the YARA rule read that same command and were
  added up. The detection guard records this as its one lowered floor.

### Tests
- 207 → 256 tests. The benchmark is a script, not part of `pytest`.

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
