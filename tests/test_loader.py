from types import SimpleNamespace

from gokdogan.loader import _timestamp


def _pe(stamp, debug_types=()):
    return SimpleNamespace(
        FILE_HEADER=SimpleNamespace(TimeDateStamp=stamp),
        DIRECTORY_ENTRY_DEBUG=[SimpleNamespace(struct=SimpleNamespace(Type=t)) for t in debug_types],
    )


def test_reproducible_build_hash_is_shown_not_flagged():
    # /Brepro writes a hash where the link time would be; 0xF4865700 reads as 2100.
    shown, anomaly = _timestamp(_pe(0xF4865700, debug_types=(2, 16)))
    assert anomaly is None
    assert shown.startswith("0xf4865700") and "reproducible" in shown


def test_future_stamp_without_repro_entry_is_flagged():
    _, anomaly = _timestamp(_pe(0xF4865700, debug_types=(2,)))
    assert anomaly == "compile timestamp is in the future"


def test_zero_stamp_is_flagged_even_with_a_repro_entry():
    # A build hash is never zero; the repro entry is one field to forge.
    _, anomaly = _timestamp(_pe(0, debug_types=(16,)))
    assert anomaly == "compile timestamp is zero (deliberately wiped)"


def test_import_count_ignores_duplicate_entries():
    from gokdogan.loader import distinct_import_count
    imports = {"kernel32.dll": ["Sleep"] * 170 + ["CreateFileW", "ReadFile"], "user32.dll": ["GetDC"]}
    assert distinct_import_count(imports) == 4
