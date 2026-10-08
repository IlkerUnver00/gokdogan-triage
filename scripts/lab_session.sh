#!/usr/bin/env bash
# One guided recall-lab session, for the isolated Linux VM of BENCHMARK.md.
#
#   bash scripts/lab_session.sh --name r1b \
#       --days 2026-09-25 2026-06-10 2026-01-15 2025-09-20 \
#       --manifest benchmarks/malwarebazaar-r1/manifest.csv
#
#   bash scripts/lab_session.sh --name r3 --days 2026-10-05 2026-10-06 \
#       --build-manifest --also-ref v0.7.0
#
# While the VM is online it downloads MalwareBazaar's daily batches (and,
# with --build-manifest, the CSV export, using the Auth-Key in ~/.mb_key).
# It then waits until the network is cut and checks that it is, sweeps with
# this checkout's engine (and with each --also-ref, a tag, from a git
# worktree), deletes every sample, waits until the network is back and
# serves the results for copying out. Nothing is extracted or run. Whatever
# stops it, the samples are deleted on the way out. Run it from the
# repository with the virtual environment active.
#
# Other options: --dir DIR (default /mnt/lab when mounted, else ~/lab),
# --jobs N (3), --max-mb MB (128), --timeout SECONDS (600), and --dry-run,
# which touches no network and no sample; --yes answers its questions.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BATCHES="https://datalake.abuse.ch/malware-bazaar/daily"
EXPORT="https://mb-api.abuse.ch/v2/files/exports"
SHARES='thinclient|xrdp-chansrv| type (9p|cifs|smb3|smbfs|nfs|nfs4|virtiofs|vboxsf|fuse\.vmhgfs-fuse|fuse\.sshfs|fuse\.rclone|davfs) '

name="" manifest="" build_manifest=0 dry=0 yes=0
jobs=3 max_mb=128 timeout=600 lab="" marker=""
days=() refs=()

die() { printf '\nSTOP: %s\n' "$*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }
# A safety check a dry run reports instead of stopping on: a dry run touches
# no sample, and a test machine has its host drives mounted.
refuse() { if (( dry )); then printf '   (dry run) would stop: %s\n' "$*"; else die "$@"; fi; }
run() { if (( dry )); then printf '   (dry run) %s\n' "$*"; else "$@"; fi; }
value() { [[ $# -ge 2 && "$2" != --* ]] || die "$1 needs a value"; }
positive() {
    [[ "$2" =~ ^[0-9]+([.][0-9]+)?$ ]] && awk -v x="$2" 'BEGIN {exit !(x > 0)}' \
        || die "$1 must be a positive number"
}
usage() {
    awk 'NR == 1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "${BASH_SOURCE[0]}"
    exit "${1:-0}"
}

while (( $# )); do
    case "$1" in
        --name) value "$@"; name="$2"; shift 2 ;;
        --days) shift; while (( $# )) && [[ "$1" != --* ]]; do days+=("$1"); shift; done ;;
        --manifest) value "$@"; manifest="$2"; shift 2 ;;
        --build-manifest) build_manifest=1; shift ;;
        --also-ref) value "$@"; refs+=("$2"); shift 2 ;;
        --dir) value "$@"; lab="$2"; shift 2 ;;
        --jobs) value "$@"; jobs="$2"; shift 2 ;;
        --max-mb) value "$@"; max_mb="$2"; shift 2 ;;
        --timeout) value "$@"; timeout="$2"; shift 2 ;;
        --dry-run) dry=1; shift ;;
        --yes) yes=1; shift ;;
        -h|--help) usage 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

days_missing() {  # days_missing MANIFEST DAY... -> the days no sample in it was first seen on
    python - "$@" <<'PY'
import csv, sys
with open(sys.argv[1], encoding="utf-8-sig", newline="") as fh:
    covered = {(row.get("first_seen") or "").strip()[:10] for row in csv.DictReader(fh)}
print(" ".join(d for d in sys.argv[2:] if d not in covered))
PY
}

# ---------------------------------------------------------------- arguments
# Everything a typo can break is checked here, before anything is downloaded.
(( yes && ! dry )) && die "--yes is for --dry-run only: a real session's questions need your answers"
[[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] || die "--name must be letters, digits, - or _ (e.g. r3)"
(( ${#days[@]} )) || die "--days needs at least one YYYY-MM-DD"
today="$(date -u +%F)"
declare -A seen=()
for d in "${days[@]}"; do
    [[ "$d" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && "$(date -ud "$d" +%F 2>/dev/null)" == "$d" ]] \
        || die "not a day: $d (YYYY-MM-DD)"
    [[ "$d" < "$today" ]] || die "$d has no batch yet: a day's batch is published after it ends (UTC)"
    [[ -z "${seen[$d]:-}" ]] || die "$d is listed twice"
    seen[$d]=1
done
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a whole number from 1"
positive --max-mb "$max_mb"
positive --timeout "$timeout"
if (( build_manifest )) && [[ -n "$manifest" ]]; then die "use --manifest or --build-manifest, not both"; fi
if (( ! build_manifest )) && [[ -z "$manifest" ]]; then die "--manifest FILE or --build-manifest is needed"; fi
declare -A ref_seen=()
for ref in "${refs[@]}"; do
    [[ "$ref" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "not a tag this script accepts: $ref"
    [[ -z "${ref_seen[$ref]:-}" ]] || die "--also-ref $ref is listed twice"
    ref_seen[$ref]=1
done
for tool in python git awk; do
    command -v "$tool" >/dev/null || die "$tool is not installed"
done
for tool in wget unzip ping ip; do
    command -v "$tool" >/dev/null || refuse "$tool is not installed (sudo apt install wget unzip iputils-ping iproute2)"
done
if [[ -n "$manifest" ]]; then
    [[ "$manifest" = /* ]] || manifest="$REPO/$manifest"
    [[ -f "$manifest" ]] || die "no manifest at $manifest"
    # A day the manifest does not cover would be downloaded for nothing.
    missing="$(days_missing "$manifest" "${days[@]}")"
    [[ -z "$missing" ]] || die "the manifest has no sample first seen on: $missing"
fi

ask() {  # ask "question" -> 0 for yes
    (( yes )) && { printf '%s [y/N] y (--yes)\n' "$1"; return 0; }
    local answer
    read -r -p "$1 [y/N] " answer </dev/tty
    [[ "$answer" =~ ^([Yy]([Ee][Ss])?|[Ee]([Vv][Ee][Tt])?)$ ]]
}

pause() {
    (( yes )) && { printf '%s (--yes)\n' "$1"; return 0; }
    read -r -p "$1 Press Enter when done. " _ </dev/tty
}

# ---------------------------------------------------------------- network
reachable() {  # ping, or any answer at all from an HTTPS server
    ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1 && return 0
    local rc=0
    wget -q --spider -T 5 -t 1 https://datalake.abuse.ch/ 2>/dev/null || rc=$?
    (( rc == 0 || rc == 8 ))            # 8: the server answered with an error
}

link_gone() {  # no default route, or no interface but lo with a carrier
    [[ -z "$(ip route show default 2>/dev/null)" ]] && return 0
    local links
    links="$(ip -o link show up 2>/dev/null | grep -v ': lo:' || true)"
    [[ -z "$(grep -v NO-CARRIER <<<"$links" || true)" ]]
}

wait_online() {
    (( dry )) && return 0
    until reachable; do
        pause "The VM is offline. In Hyper-V Manager set the network adapter's virtual switch to Default Switch."
        sleep 3
    done
    echo "   online"
}

wait_offline() {
    (( dry )) && return 0
    while true; do
        if ! reachable && link_gone; then
            echo "   offline: no route out, and ping and HTTPS both fail"; return 0
        fi
        if ! reachable && ask "Nothing answers, but the VM still has a network link. Does Hyper-V show the adapter's switch as Not connected?"; then
            echo "   offline: nothing answers, and you confirmed Not connected"; return 0
        fi
        pause "Cut the network: Hyper-V Manager > VM Settings > Network Adapter > Virtual switch: Not connected."
        sleep 3
    done
}

still_offline() {
    (( dry )) && return 0
    if reachable; then
        die "the network came back during the sweep. The samples are deleted now; what was swept so far is in $results"
    fi
}

# ---------------------------------------------------------------- checks
say "Checks"
[[ "$(uname -s)" == Linux ]] || die "run this inside the Linux lab VM"
# From /, so the import shows what the sweep will get, not this folder.
engine_path="$(cd / && python -c 'import gokdogan, os; print(os.path.dirname(gokdogan.__file__))' 2>/dev/null)" \
    || die "python cannot import gokdogan: activate the virtual environment (source ~/gkd-venv/bin/activate)"
[[ "$engine_path" == "$REPO/gokdogan" ]] \
    || die "the virtual environment's gokdogan is $engine_path, not this checkout: pip install -e . here"
drives="$HOME/thinclient_drives"
if [[ -e "$drives" ]] && { ! ls -A "$drives" >/dev/null 2>&1 || [[ -n "$(ls -A "$drives" 2>/dev/null)" ]]; }; then
    refuse "$drives shows Windows drives: reconnect with Show Options > Local Resources > More > Drives off"
fi
mounts="$(mount)"
if grep -Eq "$SHARES" <<<"$mounts"; then
    refuse "a host folder is mounted in the VM (see mount): unmount it or reconnect without shared drives"
fi
ask "Is the clipboard off (Ctrl+Shift+V pastes nothing from Windows)?" \
    || die "turn the clipboard off: reconnect with Show Options > Local Resources > Clipboard unticked"
echo "   days:"
for d in "${days[@]}"; do echo "     $(date -ud "$d" '+%F (%A)')"; done
ask "Are these the days to sweep?" || die "run again with the right --days"

if [[ -z "$lab" ]]; then
    if mountpoint -q /mnt/lab 2>/dev/null && [[ -w /mnt/lab ]]; then lab=/mnt/lab; else lab="$HOME/lab"; fi
fi
mkdir -p "$lab"
lab="$(cd "$lab" && pwd)"
corpus="$lab/$name/corpus"
results="$lab/results"
outs=("$results/$name")
for ref in "${refs[@]}"; do outs+=("$results/$name-$ref"); done
for out in "${outs[@]}"; do
    [[ ! -e "$out" ]] || die "$out already exists: a lab run is never overwritten. Pick another --name."
done
if compgen -G "$lab/*/corpus/*.zip" >/dev/null; then
    die "samples are still in $lab from an earlier session: rm -f $lab/*/corpus/*.zip (with the network cut)"
fi
need_mb=$(( ${#days[@]} * 1500 + 300 ))
free_mb=$(df -Pm "$lab" | awk 'NR == 2 {print $4}')
echo "   lab folder $lab: ${free_mb} MB free, ${need_mb} MB wanted (1.5 GB a day)"
(( free_mb >= need_mb )) || die "not enough space in $lab: add the lab data disk (BENCHMARK.md, \"A data disk for the corpus\")"
mkdir -p "$corpus" "$results"

# From here on, whatever ends the script deletes the samples first.
cleanup() {
    [[ -n "$marker" ]] && rm -f "$marker"
    (( dry )) && return 0
    if compgen -G "$lab/*/corpus/*.zip" >/dev/null; then
        rm -f "$lab"/*/corpus/*.zip
        printf '\n   samples deleted from %s on the way out\n' "$lab" >&2
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# ---------------------------------------------------------------- online: download
say "Online: code, manifest and samples"
wait_online
for ref in "${refs[@]}"; do
    tree="$HOME/gokdogan-$ref"
    if [[ ! -d "$tree" ]]; then
        run git -C "$REPO" fetch --quiet --tags origin
        run git -C "$REPO" worktree add --detach "$tree" "$ref"
    fi
    if (( ! dry )); then
        [[ "$(git -C "$tree" describe --tags --exact-match 2>/dev/null)" == "$ref" ]] || die "$tree is not at tag $ref"
        # The sweep with this engine runs offline: make sure it loads now.
        (cd / && python - "$tree" <<'PY') || die "the $ref engine in $tree does not load with this environment"
import os, sys
sys.path.insert(0, sys.argv[1])
import gokdogan, gokdogan.engine
assert os.path.dirname(gokdogan.__file__) == os.path.join(sys.argv[1], "gokdogan"), gokdogan.__file__
PY
        echo "   $ref engine loads from $tree"
    fi
done

if (( build_manifest )); then
    if [[ ! -s "$HOME/.mb_key" ]]; then
        refuse "no abuse.ch Auth-Key in ~/.mb_key. Save it without echoing it:
    (umask 077; read -rs -p 'Auth-Key: ' key && printf '%s' \"\$key\" > ~/.mb_key)"
    fi
    echo "   downloading MalwareBazaar's CSV export (hashes and labels, no samples)"
    if (( ! dry )); then
        # wget reads the URL, which holds the key, from stdin: the key stays
        # out of the process list and, with -q, out of every message.
        wget -q -T 60 -t 2 -O "$corpus/full.csv.zip" -i - <<<"$EXPORT/$(<"$HOME/.mb_key")/full.csv.zip" \
            || { rm -f "$corpus/full.csv.zip"; die "the CSV export did not download (is the Auth-Key current?)"; }
    fi
    run python "$REPO/scripts/bazaar_manifest.py" --csv "$corpus/full.csv.zip" --days "${days[@]}" \
        --out "$corpus/manifest.csv"
    run rm -f "$corpus/full.csv.zip"
    if (( ! dry )); then
        missing="$(days_missing "$corpus/manifest.csv" "${days[@]}")"
        [[ -z "$missing" ]] || die "the export has no EXE or DLL first seen on: $missing"
    fi
else
    cp "$manifest" "$corpus/manifest.csv"
fi
(( dry )) || echo "   manifest: $(( $(wc -l < "$corpus/manifest.csv") - 1 )) samples"

for d in "${days[@]}"; do
    if (( dry )); then
        printf '   (dry run) wget %s/%s.zip\n' "$BATCHES" "$d"
        continue
    fi
    echo "   batch $d"
    wget -q --show-progress -O "$corpus/$d.zip" "$BATCHES/$d.zip" || die "batch $d did not download"
    members="$(unzip -l "$corpus/$d.zip" 2>/dev/null | tail -1 | awk '{print $2}')" \
        || die "$d.zip is not a complete archive"
    echo "   $d.zip: $members files (not extracted)"
done

# ---------------------------------------------------------------- offline: sweep
say "Offline: sweep"
wait_offline
offline_since="$(date -u '+%F %T UTC')"
ulimit -c 0                              # a crashed worker leaves no core file
marker="$(mktemp)"
if (( ! dry )); then
    if gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing' 2>/dev/null \
            && gsettings set org.gnome.desktop.session idle-delay 0 2>/dev/null; then
        echo "   automatic suspend and screen blanking off"
    else
        echo "   could not turn automatic suspend off: keep the VM awake (Settings > Power)"
    fi
fi
sweep=(python "$REPO/scripts/recall_sweep.py" --corpus "$corpus" --manifest "$corpus/manifest.csv"
       --jobs "$jobs" --max-mb "$max_mb" --timeout "$timeout")
(cd "$REPO" && run "${sweep[@]}" --out "$results/$name") \
    || die "the sweep stopped; what it wrote is in $results/$name"
still_offline
for ref in "${refs[@]}"; do
    say "Offline: sweep with $ref"
    (cd "$REPO" && run "${sweep[@]}" --engine "$HOME/gokdogan-$ref" --out "$results/$name-$ref") \
        || die "the sweep with $ref stopped; what it wrote is in $results/$name-$ref"
    still_offline
done

say "Deleting the samples"
run rm -f "$corpus"/*.zip
if (( ! dry )) && compgen -G "$lab/*/corpus/*.zip" >/dev/null; then die "ZIP files are still in $lab"; fi
echo "   no sample left in $lab"
# Ubuntu uploads crash reports once it is online, and a crashed worker's
# report can hold sample bytes.
while (( ! dry )) && crashes="$(find /var/crash -type f -newer "$marker" 2>/dev/null)" && [[ -n "$crashes" ]]; do
    printf '   crash reports were written during the sweep:\n%s\n' "$crashes"
    pause "Delete them before the network comes back: sudo rm -f /var/crash/*.crash"
done
for out in "${outs[@]}"; do
    (( dry )) || printf 'checkout %s\ndays %s\noffline from %s to %s\n' \
        "$(git -C "$REPO" rev-parse --short HEAD)" "${days[*]}" "$offline_since" "$(date -u '+%F %T UTC')" \
        > "$out/lab_session.txt"
done

# ---------------------------------------------------------------- online: copy out
say "Online: copy the results out"
wait_online
for out in "${outs[@]}"; do
    [[ -f "$out/summary.md" ]] && sed -n '3,4p' "$out/summary.md" | sed "s|^|   $(basename "$out"): |" || true
done
echo
echo "   VM address: $(hostname -I 2>/dev/null | awk '{print $1}')"
echo "   Give Claude this address. When it says the files are copied, press Ctrl+C here"
echo "   and apply the VM's clean checkpoint."
run python -m http.server 8000 --directory "$results"
