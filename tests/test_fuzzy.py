import os

import pytest

from gokdogan import fuzzy

ssdeep_only = pytest.mark.skipif(not fuzzy.HAVE_SSDEEP, reason="ppdeep not installed")
tlsh_only = pytest.mark.skipif(not fuzzy.HAVE_TLSH, reason="tlsh not installed")


def test_availability_note_shape():
    note = fuzzy.availability_note()
    assert note is None or note.startswith("fuzzy hashing unavailable")


def test_hash_returns_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(fuzzy, "HAVE_SSDEEP", False)
    monkeypatch.setattr(fuzzy, "HAVE_TLSH", False)
    assert fuzzy.ssdeep_hash(b"A" * 4096) is None
    assert fuzzy.tlsh_hash(b"A" * 4096) is None


def test_compare_none_inputs_are_safe():
    assert fuzzy.compare_ssdeep(None, "x") is None
    assert fuzzy.compare_tlsh("x", None) is None


@ssdeep_only
def test_ssdeep_identical_is_100():
    data = os.urandom(8192)
    h = fuzzy.ssdeep_hash(data)
    assert h
    assert fuzzy.compare_ssdeep(h, h) == 100


@ssdeep_only
def test_ssdeep_similar_beats_unrelated():
    base = bytearray(os.urandom(16384))
    tweaked = bytearray(base)
    for i in range(0, 200, 8):          # small perturbation
        tweaked[i] ^= 0x01
    unrelated = os.urandom(16384)

    h_base = fuzzy.ssdeep_hash(bytes(base))
    h_tweaked = fuzzy.ssdeep_hash(bytes(tweaked))
    h_unrelated = fuzzy.ssdeep_hash(unrelated)

    sim = fuzzy.compare_ssdeep(h_base, h_tweaked)
    dissim = fuzzy.compare_ssdeep(h_base, h_unrelated)
    assert sim > dissim


@ssdeep_only
def test_tlsh_short_input_is_none():
    # too short for TLSH regardless of whether the lib is present
    assert fuzzy.tlsh_hash(b"short") is None


@tlsh_only
def test_tlsh_identical_is_zero_distance():
    data = os.urandom(8192)
    h = fuzzy.tlsh_hash(data)
    assert h
    assert fuzzy.compare_tlsh(h, h) == 0
