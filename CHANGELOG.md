# Changelog

All notable changes to **gokdogan** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.7.0] — 2026-10-04

Detection, measured. The recall benchmark ran twice in an isolated lab
over the same 445 MalwareBazaar samples: before the scoring changes below
and after them. The changes were chosen on the tuning parts (295 malware
samples, 2,845 benign files); the malware held-out part was scored with
them only in the second run. The benign held-out sample was also checked
at two intermediate builds during development, so it is the weaker
hold-out of the two. .NET assemblies are now read from their metadata,
and Windows catalog signatures count.

| Held-out samples | before the scoring changes | this release |
|---|---:|---:|
| Malware (150, isolated lab): `SUSPICIOUS` or worse | 55.3% (83) | 71.3% (107) |
| Malware: `HIGH_RISK` | 17.3% (26) | 14.7% (22) |
| Benign files (one Windows 11 machine): `SUSPICIOUS` or worse | 2.17% (58) | 1.72% (46) |

Both columns include the .NET stage. The 95% interval for the malware gain,
with families resampled, is +8 to +26 points; see
[benchmarks/malwarebazaar-r1](benchmarks/malwarebazaar-r1/README.md). The
numbers were measured at engine code `1dcb545569ce`; this release
(`bfeb6fcbe56b`) differs from it only in its version string.

### Changed — scoring, from the first recall measurement
The first recall run, in an isolated lab over four MalwareBazaar daily
batches (445 EXE/DLL samples of 75 families: the manifest built at lab time
from an export updated since our test build, which had 440), flagged 55.3%
of its held-out part (83/150) at `SUSPICIOUS` or worse, against 2.2% of
held-out benign files. Four lenses proposed changes on the tuning parts
only (295 malware samples, 2,845 benign files); each was recomputed and
attacked by an independent reviewer, and the implementation was reviewed
again. These were kept. "Nobody vouches for" below means a GUI or console
program (not a DLL, driver or boot image) with no valid signature. No
signature is valid off Windows, with `--no-verify-sig` or through
`triage_bytes()`, so there the rules below treat signed files, Windows'
own included, like unsigned ones, and a file can score higher there than
on Windows.
- **A program nobody vouches for whose image is mostly ciphertext**
  (entropy 7.0 or more over the file without its overlay) is not cleared:
  it is raised to `SUSPICIOUS`, the engine's existing rule for named
  packers applied to unknown crypters.
- **A program nobody vouches for with almost no imports** (five or fewer,
  or none, and an entry point) is treated as packed: the API is resolved at
  run time, as shellcode stagers and packer stubs do. IL-only .NET images
  are exempt.
- **Keylogging** scores 8 instead of 18 (still severity 3 for the
  signature floor): GUI frameworks hook and translate keys, and the tag
  was on 27 benign files against 13 malware samples.
- **A stale PE checksum** scores 12 and **a high-entropy overlay** 10 in any
  file (DLLs and drivers too) without the signature credit, unless its
  signature is tampered (which already scores 30); 6 otherwise.
- **Windows catalog signatures count.** Most files Windows ships carry no
  embedded signature: a signed catalog lists their hashes. On Windows a
  file without an embedded signature is now checked against the installed
  catalogs (offline, as Explorer does), using the hash of the bytes the
  engine analysed, and a match is a valid signature. Without it, the rules
  above flagged 18 of Windows' own 32-bit programs. Reading a signer's name
  no longer leaks the decoded signature (hundreds of KB per catalog) in a
  long-running process.
- **The certificate table is no longer read as an overlay payload**:
  measured with the rest, a signed file with a few bytes of slack before
  its table looked like a "high-entropy overlay" (149 of 152 benign
  carriers). A table that runs past the end of the file no longer hides an
  appended one, and an executable hidden inside the table is still
  reported. Reports show the overlay bytes outside the signature, and the
  overlay's entropy and type now describe only those bytes. Fewer than
  1 KB of them is slack, in unsigned files too: no type, no overlay note,
  and an empty overlay column in the batch summary.
- Floors show the points they add as an entry of their own.

Benign files, measured at this code: tuning sample 2.21% -> 1.86% (one file
newly flagged, eleven cleared; 841 of the 2,845 files now verified through a
catalog), held-out sample 2.17% -> 1.72% over the files still on disk at
the same paths (58 of 2,675 -> 46 of 2,674 distinct files; `HIGH_RISK`
6 -> 3; 12 of those paths hold a file updated between the two sweeps, and
on the 2,663 files both sweeps scored it is 56 -> 44), and Windows' 32-bit
programs (`SysWOW64`, 2,998 files, swept one build earlier, which scores
every file of both benign samples the same) 3.3% -> 2.3% with none newly
flagged.

Malware, measured in a second lab run at this code over the same 445
samples and the same hash split: held-out 55.3% -> **71.3%** (83 -> 107 of
150; 95% interval 63.6–78.0%). Nothing run 1 flagged was missed (24 gained,
0 lost), each of the four daily batches improved, and no family went down.
Samples of one family can be near-identical builds (7 of the 24 gains are
BlackMatter, 6 of them probably one build), so the interval for the gain
resamples families: +8 to +26 points. 21 of the 24 gains score exactly 30
(17 of them lifted by the new floor), and `HIGH_RISK` fell from 26 to 22
(keylogging now scores 8, not 18). Had every signature been valid (the lab
cannot verify them): 64.0%. Tuning part 51.9% -> 71.2% (210/295; the
recompute had predicted 209).

Rejected or deferred: raising the zero-timestamp and
embedded-config weights (they are the Go toolchain's fingerprint: 31
benign Go programs on the test machine score like the missed Go loaders,
and the benign samples, capped at 12 MB, hold none), a floor for unsigned
programs with a stale checksum alone, a lower threshold (28 or 25: more
benign files per malware sample gained), and a floor for appended
ciphertext (unsigned PyInstaller-style bundles look the same).

### Added
- The sweeps record each file's structure (`features`: subsystem, import
  count, sections, resources, overlay, entropies, string counts) so the
  next analysis can weigh features the score does not use without another
  lab run. The lab worker also scores every signed sample as if its
  signature were valid (`score_if_valid`), so "had every signature been
  valid" comes from the engine instead of an estimate.
- `scripts/bazaar_manifest.py` builds the recall manifest from
  MalwareBazaar's CSV export for the days whose daily batches make up the
  corpus: EXE and DLL only, capped per family (spellings of one family
  merged), with the samples a cap keeps chosen independently of the
  held-out split. It warns when the export was made before a requested day
  ended and fails when a day selects nothing. It reads metadata only and
  downloads nothing. On MalwareBazaar's export for four days it selects
  440 samples of 75 families; 34% land in the held-out part.
- The recall sweep reads ZipCrypto members (MalwareBazaar's daily
  batches) with the standard library, faster than pyzipper, which it keeps
  for WinZip AES.
- **.NET analysis stage.** A managed assembly imports almost nothing native,
  so its behaviour is now read from its metadata with `dnfile` (a new hard
  dependency: pure Python, MIT): the framework members it references, the
  native functions it declares through P/Invoke, and, from the IL, which of
  them each class actually calls.
  - P/Invoke functions the code calls go through the native rules, so a C#
    injector, keylogger or anti-debug check is tagged like a native one
    (bare `SetWindowsHookEx`-style names match the A/W rules).
  - New managed rules: network, download-and-run, loading an assembly from
    memory (`Assembly.Load(byte[])`, recognised from the method signature),
    screenshots, clipboard, SMTP exfiltration (`email-exfiltration`),
    registry writes, symmetric crypto, DPAPI decryption (`credential-access`)
    and in-process shellcode runners (`shellcode-execution`).
  - Two-part rules (download-and-run, load-from-memory, shellcode) need both
    parts in one class when the IL can be read: a framework library that
    downloads in one place and starts processes in another is not a
    downloader. If the IL cannot be tied to calls (an obfuscator, or
    references resolved at runtime), rules read every declaration instead.
  - Native and .NET evidence for one behaviour is one capability.
  - Metadata that cannot be read, or declares tables larger than its own
    stream, is an anomaly: it costs an author nothing and would blind the
    stage. Each such case is refused before `dnfile` builds a row for it.
  - Reports show member references and P/Invoke declared and called.
  - The new tags map to ATT&CK (T1071.003 and T1048.003 for SMTP
    exfiltration, T1555 for credential access, T1620 for shellcode
    runners), and .NET-derived common tags count toward the
    large-program cap like import-derived ones. `dnfile` 0.18 or later
    is required.
  - Measured on the same benign samples: native files are unchanged. On
    the held-out sample, .NET assemblies flagged went from 0.25% to 0.51%
    (overall 2.15% to 2.23%; `HIGH_RISK` from 4 to 6 files), and on the
    tuning sample from 0.11% to 1.00%. The runtime's own folder,
    `C:\Windows\Microsoft.NET` (822 files, in neither sample), went from
    0.97% to 2.07%: core framework assemblies such as `System.dll` and
    `System.Core.dll` implement the risky APIs themselves and stay at
    `SUSPICIOUS` through the valid-signature floor, and the PowerShell
    engine is `HIGH_RISK`. `benign_sweep.py` now samples that folder too.
- **`scripts/recall_sweep.py`**: the detection half of the benchmark, for an
  isolated lab VM. It reads each sample (or password-protected ZIP member,
  AES with `pyzipper`) into memory with a bounded read and triages it with
  `triage_bytes()`: nothing is extracted, written or run, bzip2/LZMA members
  are skipped, and a corpus on a network drive or under a cloud-synced
  folder is refused. The corpus is split by hash into a tuning and a
  held-out part. The summary gives held-out detection with 95% intervals,
  the rate counting PEs the engine could not score as misses, a
  family-balanced held-out rate, a bound for signatures that cannot be
  verified from memory, and, from the tuning part only, rates by kind,
  family and first-seen year, the signals in missed vs detected samples and
  the lowest-scoring misses. With a benign sweep it adds a
  detection-vs-false-positive threshold table and warns when the two runs
  used different engine code or YARA state.
- **BENCHMARK.md**: how to run and read both sweeps, the lab procedure, and
  how to build and report on a corpus.
- Sweep rows record `signed`, `is_dll` and whether YARA ran.
- JSON output: `image_entropy` on the report; `subsystem` and `managed`
  on `file`; `pinvoke`, `pinvoke_count`, `pinvoke_called`, `member_refs`
  and `metadata_error` on `dotnet`; `payload_size` on `overlay`. A
  capability's `source` can be `managed`, and a file verified through a
  catalog has signature status `valid` with a note naming the catalog.

### Fixed
- **The benchmark scripts on Linux**, where the recall lab runs. CI now
  also runs the suite on Ubuntu (Python 3.10 and 3.12), including one
  recall run over a real PE with YARA, and both jobs stop after 20 minutes.
  - The sweeps' worker pool is rebuilt around one private pipe per worker
    process. A `multiprocessing.Pool` shares its queues between workers,
    so a worker killed on a timeout could leave a lock held and stall the
    rest, and a worker that died just after starting an item could leave
    that item unaccounted while the sweep waited for it forever. Now every
    item is either waiting or held by one worker, a timed-out worker is
    killed on its own and never reused, and a worker that dies before it
    starts an item has the item tried once more. The timeout counts from
    when an item is handed over; `report_start()` restarts it, so a fresh
    process's start-up does not count. A worker whose sweep dies exits too:
    at once, or, if it is stuck in native code on a file that never ends,
    once half the timeout again plus 30 s has passed. A worker stuck in the
    kernel after a kill no longer keeps the sweep from exiting: it warns
    and leaves once its results are written. On Windows
    at most 60 workers run (the handle limit of a wait), and the sweeps
    print the number that runs. Measured on 300 benign files, verdicts and
    scores are identical to the old pool's.
  - In 0.6.0, items that finished quickly were often recorded as "worker
    died" (138 of 180 fast-failing items in a check); the parent now knows
    which item each worker holds. The 0.6.0 numbers are unaffected: those
    runs had no timeouts or crashes. A path listed twice is triaged once,
    and results are flushed every 50 rows.
  - A timed-out or crashed sample keeps the hash its worker read, so the
    recall summary splits it into the held-out or tuning part and matches
    it to the manifest instead of counting it as missing from the corpus.
  - The recall guard now refuses, on Linux, a corpus on a host folder
    mounted into the VM (SMB/NFS, Hyper-V and WSL 9p, virtiofs, VirtualBox,
    VMware or Parallels shared folders, xrdp drive redirection, FUSE clients
    of remote storage), identified by device number in the mount table. It
    checks every filesystem mounted inside the corpus where it starts, and
    every link in it, Windows junctions included.
  - The engine code hash folds line endings, so a Windows (CRLF) and a
    Linux (LF) checkout of the same commit match when a recall run is paired
    with a benign sweep. Hashes recorded from CRLF checkouts change.
  - What the recall run leaves out while listing the corpus (bzip2/LZMA
    members, members over `--max-mb`, unreadable archives and folders,
    linked folders, which are not followed) is recorded in `engine.json`
    and shown in the summary, including under `--report`. A corpus folder
    that cannot be listed at all stops the run instead of scoring nothing.
  - A `::` in a corpus folder or member name no longer breaks reading, a
    symlink loop in the corpus is an unreadable file rather than a crash,
    and tied rows in both sweeps' summary tables are ordered the same way
    on every run.
  - `benign_sweep.py --jobs 0` is refused instead of spinning.
  - MISP export takes the file name from a Windows path on Linux too.

### Tests
- 256 → 345 tests, also run on Ubuntu in CI. The benchmarks are scripts,
  not part of `pytest`.

## [0.6.0] — 2026-09-26

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

[0.7.0]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.7.0
[0.6.0]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.6.0
[0.5.2]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.5.2
[0.5.1]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.5.1
[0.5.0]: https://github.com/IlkerUnver00/gokdogan-triage/releases/tag/v0.5.0
