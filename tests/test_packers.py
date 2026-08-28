from gokdogan.models import SectionInfo
from gokdogan.packers import detect_packer


def _section(name, entropy=6.0, is_exec=True, flags=None, raw_size=4096):
    return SectionInfo(
        name=name,
        virtual_size=raw_size,
        raw_size=raw_size,
        entropy=entropy,
        md5="0" * 32,
        is_executable=is_exec,
        is_writable=False,
        flags=flags or [],
    )


def test_upx_by_section_name():
    result = detect_packer([_section("UPX0"), _section("UPX1")], import_count=4)
    assert result.detected
    assert "UPX" in result.names


def test_clean_layout_not_detected():
    sections = [
        _section(".text", entropy=6.2),
        _section(".data", entropy=4.0, is_exec=False),
        _section(".rsrc", entropy=5.0, is_exec=False),
    ]
    result = detect_packer(sections, import_count=200)
    assert not result.detected


def test_heuristic_detection_without_known_name():
    sections = [
        _section(
            ".krkr",
            entropy=7.8,
            flags=["high-entropy executable section"],
        ),
        _section(
            ".empty",
            entropy=0.0,
            raw_size=0,
            flags=["zero raw size (unpacking target)"],
        ),
    ]
    result = detect_packer(sections, import_count=3)
    assert result.detected
    assert result.names == ["unknown packer (heuristic)"]


def test_high_entropy_alone_is_not_enough():
    sections = [_section(".text", entropy=7.5, flags=["high-entropy executable section"])]
    result = detect_packer(sections, import_count=150)
    assert not result.detected
    assert result.indicators  # evidence is still reported
