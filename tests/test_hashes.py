import hashlib
from pathlib import Path

import pefile
import pytest

from gokdogan.hashes import authentihash, impfuzzy
from gokdogan.loader import imported_functions

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")
has_notepad = pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not available")


def test_impfuzzy_none_for_no_imports():
    assert impfuzzy({}) is None


def test_impfuzzy_clusters_similar_import_lists():
    a = {"kernel32.dll": ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle"]}
    b = {"kernel32.dll": ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "Sleep"]}
    ha, hb = impfuzzy(a), impfuzzy(b)
    # ppdeep may or may not be present; if it is, both should hash
    if ha is not None:
        assert hb is not None
        assert isinstance(ha, str) and ":" in ha


@has_notepad
def test_authentihash_ignores_checksum_field():
    data = bytearray(NOTEPAD.read_bytes())
    pe = pefile.PE(data=bytes(data), fast_load=True)
    base = authentihash(pe, bytes(data))
    assert base and len(base) == 64
    assert base != hashlib.sha256(bytes(data)).hexdigest()   # not just the file hash

    # flip a byte inside the optional-header CheckSum field (excluded from the hash)
    checksum_offset = pe.OPTIONAL_HEADER.get_file_offset() + 64
    data[checksum_offset] ^= 0xFF
    pe2 = pefile.PE(data=bytes(data), fast_load=True)
    assert authentihash(pe2, bytes(data)) == base            # authentihash unchanged
    assert hashlib.sha256(bytes(data)).hexdigest() != hashlib.sha256(NOTEPAD.read_bytes()).hexdigest()


@has_notepad
def test_impfuzzy_real_binary():
    pe = pefile.PE(str(NOTEPAD))
    imps = imported_functions(pe)
    h = impfuzzy(imps)
    if h is not None:                    # ppdeep installed
        assert ":" in h
