import os
from pathlib import Path

import pytest

import pefile

from gokdogan.blobs import _islands, find_config_blobs
from gokdogan.capabilities import infer_capabilities
from gokdogan.models import ConfigBlob

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
has_notepad = pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")


def test_islands_finds_random_region_in_calm_data():
    calm = b"A" * 2048                    # entropy ~0
    island = os.urandom(4096)            # entropy ~8
    data = calm + island + calm
    found = _islands(data)
    assert len(found) == 1
    start, size, entropy = found[0]
    assert 2048 <= start <= 2048 + 512
    assert size >= 3072
    assert entropy > 7.5


def test_islands_ignores_small_spikes():
    data = b"B" * 8192
    data = data[:2000] + os.urandom(256) + data[2256:]   # 256B spike < min island
    assert _islands(data) == []


def test_islands_none_in_uniform_low_entropy():
    assert _islands(b"\x00" * 8192) == []


def test_config_blob_yields_capability():
    blobs = [ConfigBlob(section=".data", file_offset=0x4000, size=2048, entropy=7.93)]
    caps = infer_capabilities({}, [], None, None, None, blobs)
    cfg = next((c for c in caps if c.name == "embedded-config"), None)
    assert cfg is not None
    assert cfg.severity == 2
    assert "T1027" in cfg.attack


@has_notepad
def test_clean_binary_has_no_config_blobs():
    pe = pefile.PE(str(NOTEPAD), fast_load=False)
    # A stock binary's data sections shouldn't look like they hide a payload.
    assert find_config_blobs(pe) == []
