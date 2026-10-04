# Measuring gokdogan

A triage verdict is only as useful as two numbers: how often it flags clean
software (false positives) and how often it flags malware (detection, or
recall). gokdogan ships a script for each half. Neither runs a sample.

| Half | Script | Where it runs | Measured so far |
|---|---|---|---|
| False positives | [`scripts/benign_sweep.py`](scripts/benign_sweep.py) | any machine, over installed software | 2.2% of 2,694 held-out benign files flagged (0.6.0, one Windows 11 machine); 1.7% of the 2,674 still on disk with the [Unreleased](CHANGELOG.md) scoring |
| Detection | [`scripts/recall_sweep.py`](scripts/recall_sweep.py) | an isolated analysis VM only | 71.3% of 150 held-out malware samples flagged with the [Unreleased](CHANGELOG.md) scoring, 55.3% before it (four MalwareBazaar daily batches, 445 EXE/DLL samples of 75 families; [runs](benchmarks/malwarebazaar-r1/README.md)) |

## False positives

```bash
python scripts/benign_sweep.py --limit 3000 --out sweep_results/tune
# the same files, scored by another engine (a worktree of a release)
python scripts/benign_sweep.py --paths-from sweep_results/tune/results.jsonl \
    --engine ../gokdogan-v0.5.2 --out sweep_results/tune_old
# a held-out sample: files (and byte-identical copies) of the tuning run left out
python scripts/benign_sweep.py --limit 3000 --seed 2 \
    --exclude-results sweep_results/tune/results.jsonl --out sweep_results/holdout
```

Every file is assumed benign because it is installed software. Results go
to `sweep_results/` (git-ignored: the paths describe your machine). Compare
engines only on the same file list (`--paths-from`): a seed picks a
different sample as soon as one file on disk changes.

## Detection

### Lab rules

- **Isolated VM only.** No shared folders, no clipboard sharing, no network
  while samples are inside, and a snapshot to revert to. Never the analyst's
  everyday machine. A Linux VM is the safer choice: a Windows sample cannot
  run there. A Hyper-V enhanced session (and any RDP client) shares the
  clipboard and can share drives: turn both off under Show Options → Local
  Resources before connecting. As a safety net the script refuses a corpus
  on a network share or mapped remote drive, on a host folder mounted into
  a Linux VM (SMB or NFS, Hyper-V and WSL 9p, virtiofs, VirtualBox or VMware
  shared folders, xrdp drive redirection), or under a OneDrive (including
  synced SharePoint libraries), Dropbox, Google Drive or iCloud folder; it
  cannot check the rest of these rules for you.
- **Samples stay zipped.** Keep them in password-protected ZIPs (password
  `infected`). `recall_sweep.py` reads each member into memory, never more
  than `--max-mb` of it whatever the archive claims, and triages it there
  with `triage_bytes()`: nothing is extracted, written or run. Members
  compressed with bzip2 or LZMA are skipped, since their output cannot be
  bounded. MalwareBazaar's AES ZIPs need `pyzipper`.
- **An antivirus inside the VM** may quarantine or upload what it can scan.
  Zipped samples on an offline VM give it nothing to act on.
- **Only results leave the lab.** `results.jsonl`, `summary.json`,
  `summary.md`, `engine.json` and the copied `manifest.csv` hold hashes,
  verdicts and score reasons (which can quote short names from a sample,
  such as a resource name), never sample bytes.
- Follow the terms of the source you draw samples from, and local law.

### Building a corpus

- **Windows PE files only** (EXE and DLL), a few hundred to a few thousand.
- **Many families, capped.** At most about 20 samples per family, so a few
  prolific families do not decide the number. The summary also reports a
  family-balanced held-out rate: the mean of per-family rates, leaving
  unlabelled samples out.
- **Recent, with some history.** Mostly samples first seen in the last one
  or two years, plus older ones to show drift.
- **The mix analysts see:** native and .NET, packed and not, EXE and DLL.
  The summary breaks the rate down along each of these.
- **A manifest CSV** with a `sha256` column and, where known, `family`,
  `first_seen` (any format containing the year) and `source`:

  ```csv
  sha256,family,first_seen,source
  <64 hex digits>,AgentTesla,2025-03-14,MalwareBazaar
  ```

  Family labels come from the source's tags and are noisy; say so when you
  report. The manifest holds hashes only, so it can be committed or shared:
  anyone with access to the same source can rebuild the corpus.
- **From MalwareBazaar.** It publishes one password-protected ZIP of each
  day's new samples (a *daily batch*, every sample first seen that day,
  UTC, of every file type) and a CSV export of every sample's hash,
  first-seen time, file type and family. Put the batches of a few days,
  spread over a year or two, in the corpus folder as they are, and build
  the manifest for those days from an export made after the last of them
  ended: EXE and DLL only, at most 20 per family and at most 100 without a
  family. Which samples a cap keeps depends on their hashes (the same
  export always gives the same manifest) but not in the way the held-out
  split does, so capped families land in both parts:

  ```bash
  python scripts/bazaar_manifest.py --csv full.csv.zip \
      --days 2026-09-25 2026-06-10 2026-01-15 2025-09-20 --out ~/corpus/manifest.csv
  ```

  The sweep triages every member of the batches but counts only the
  manifest's samples; the rest show up as "not in manifest". The batches
  are ZipCrypto archives, decrypted in pure Python at a few MB/s per
  worker, and a few of their PE files are larger than 64 MB: run the sweep
  with `--max-mb 128`. Downloads need a free abuse.ch Auth-Key; follow
  abuse.ch's fair-use terms.

### Running

The scripts live in the repository, not in the PyPI package.

1. With the VM still online and holding no samples, copy in a checkout,
   install it with `pip install -e ".[dev]" pyzipper` from the repository
   root (the `dev` extra brings YARA and pytest) and check the install with
   `python -m pytest -q`: tests that need Windows system files skip, none
   should fail, and one runs a real PE (pip's launcher stub) through the
   recall script, with YARA when yara-python is installed. On Ubuntu (the
   build tools matter only where yara-python has no ready-made wheel, such
   as Python 3.14):

   ```bash
   sudo apt update && sudo apt install -y python3-venv python3-dev build-essential git
   git clone https://github.com/IlkerUnver00/gokdogan-triage.git ~/gokdogan
   python3 -m venv ~/gkd-venv && source ~/gkd-venv/bin/activate
   cd ~/gokdogan && pip install -e ".[dev]" pyzipper && python -m pytest -q
   python -c "import yara, pyzipper; print('YARA', yara.__version__)"
   ```

   Take a snapshot.
2. Cut the network. Put the corpus on the VM's own disk (a folder, or a
   disk attached read-only for it) and run the sweep from the checkout,
   with the virtual environment active (a new terminal needs
   `source ~/gkd-venv/bin/activate && cd ~/gokdogan` again):

   ```bash
   python scripts/recall_sweep.py --corpus ~/corpus --manifest ~/corpus/manifest.csv \
       --jobs 2 --max-mb 128 --out recall_results
   ```

   A large sample can take a few hundred MB in its worker: on a VM with
   8 GB of memory, keep `--jobs` at 2 or 3. It stops before triaging
   anything if the manifest has no `sha256` column, the engine is older
   than 0.6.0, or AES archives are present without `pyzipper`; it warns if
   YARA did not run.
3. Copy `recall_results/` out, then revert the VM to the snapshot.
4. Outside, add a benign sweep of the same engine code for the threshold
   table. The run's split and its copy of the manifest are reused:

   ```bash
   python scripts/recall_sweep.py --report recall_results/results.jsonl \
       --benign sweep_results/holdout/results.jsonl --out recall_results
   ```

### Reading the results

- **Tuning vs held-out.** Every sample is assigned to a tuning part or a
  held-out part (30%) by its hash, the same way on every run. Quote the
  held-out row. Every table below it (kinds, families, years, scores,
  signals, lowest-scoring misses) comes from the tuning part only, so
  deciding what to change from them does not touch the held-out part. If
  rules change after held-out misses have been studied anyway, measure on a
  new corpus or a later time slice.
- **Samples in both parts can share a family.** The held-out rate is recall
  on the corpus's own distribution. For new families or builds, measure a
  corpus first seen after the rules were frozen, where the whole corpus is
  out of sample.
- **Unscored PEs.** A PE the engine could not score (the parser rejected it,
  it crashed or timed out) is a sample the triage failed to flag. The
  headline rate covers scored samples; the next column counts those
  failures as misses too. Files without an MZ header are not PE samples and
  are counted apart.
- **Signatures.** `triage_bytes()` cannot verify Authenticode (that needs a
  file on disk), so every signature scores as "unverified", which is 0
  points, and the file counts as one nobody vouches for. Real verification
  could move a sample either way: a valid signature takes 15 points off and
  lifts the rules for unvouched programs (the import-less packing entry, the
  unreadable-image floor, the 12/10 weights); a revoked one adds 15 and a
  tampered one 30 (less the 12/10 extras it no longer gets). The lab worker scores every signed sample a second time as if
  its signature were valid (`score_if_valid` in `results.jsonl`), and the
  summary reports the rate had every signature been valid from that.
- **Threshold table.** With `--benign`, the summary shows detection against
  the benign flag rate at each score threshold. It warns when the two runs
  used different engine code or when YARA ran on one side and not the other.
  The code hash ignores line endings, so a Linux lab checkout and a Windows
  checkout of the same commit match.
- **What the rate means.** It is the share of malware PE files a triage
  pre-filter would send for a closer look (`SUSPICIOUS` or worse). Packed
  samples top out at `SUSPICIOUS` by design, and .NET samples are read from
  metadata only (see README, "What gokdogan does not do"), so expect those
  strata to differ.

### Reporting a number

Give the held-out rate with its 95% interval and counts, the rate counting
unscored PEs as misses, the family-balanced held-out rate, the corpus
(source, first-seen range, number of families, native/.NET share), and the
engine version and code hash from `engine.json`.
