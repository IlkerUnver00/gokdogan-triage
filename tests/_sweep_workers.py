"""Stand-in workers for benign_sweep.run(): no engine, no PE files.

They live in a plain module so worker processes can import them under any
start method (spawn and forkserver re-import the worker by name).
"""

import hashlib
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import benign_sweep  # noqa: E402

_process = None  # (pid, first call): names this process even if a PID is reused


def _row(item: str) -> dict:
    global _process
    if _process is None or _process[0] != os.getpid():   # a forked child starts with None too
        _process = (os.getpid(), time.time_ns())
    return {"path": item, "sha256": hashlib.sha256(item.encode()).hexdigest(),
            "process": f"{_process[0]}-{_process[1]}"}


def behaves_as_named(args: tuple):
    """By name prefix: "late" exits before reporting a start, "sleepy" takes
    its time before starting, "die" exits right after starting, "hashdie"
    exits after reporting its hash, "slow" hangs after reporting it, "none"
    returns no row; the rest return at once."""
    item = args[0]
    name = os.path.basename(item)
    if name.startswith("late"):
        os._exit(4)
    if name.startswith("sleepy"):
        with open(item + ".attempts", "a") as fh:
            fh.write("x")
        time.sleep(30)
    benign_sweep.report_start(item)
    if name.startswith("die"):
        os._exit(3)
    if name.startswith("hangpid"):   # a file that never finishes, and says which process has it
        Path(item + ".pid").write_text(str(os.getpid()))
        time.sleep(120)
    if name.startswith(("hashdie", "slow")):
        benign_sweep.report_progress(sha256=_row(item)["sha256"])
        if name.startswith("hashdie"):
            os._exit(6)
        time.sleep(120)
    if name.startswith("none"):
        return None
    return _row(item)


def dies_once_before_starting(args: tuple) -> dict:
    """Lost before starting on the first try (a marker file remembers it), then fine."""
    item = args[0]
    marker = Path(item + ".tried")
    if not marker.exists():
        marker.write_text("x")
        os._exit(5)
    benign_sweep.report_start(item)
    return _row(item)
