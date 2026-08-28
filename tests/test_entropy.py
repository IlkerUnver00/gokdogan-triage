import os

from gokdogan.entropy import entropy_label, shannon_entropy


def test_empty_data_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_single_byte_value_is_zero():
    assert shannon_entropy(b"\x00" * 4096) == 0.0


def test_uniform_random_is_near_eight():
    assert shannon_entropy(os.urandom(65536)) > 7.9


def test_all_256_values_exactly_eight():
    assert abs(shannon_entropy(bytes(range(256)) * 16) - 8.0) < 1e-9


def test_text_is_midrange():
    text = (b"The quick brown fox jumps over the lazy dog. " * 200)
    assert 3.0 < shannon_entropy(text) < 5.5


def test_labels():
    assert entropy_label(7.9) == "packed/encrypted"
    assert entropy_label(6.8) == "compressed/high"
    assert entropy_label(5.0) == "code/data"
    assert entropy_label(0.0) == "empty/padding"
