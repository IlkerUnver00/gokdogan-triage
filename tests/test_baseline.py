from types import SimpleNamespace

from gokdogan.baseline import diff_reports


def _sec(name, md5):
    return SimpleNamespace(name=name, md5=md5)


def _report(imphash="I", authentihash="A", entropy=6.0, sections=(), caps=()):
    return SimpleNamespace(
        file=SimpleNamespace(imphash=imphash, authentihash=authentihash),
        overall_entropy=entropy,
        sections=[_sec(n, m) for n, m in sections],
        capabilities=[SimpleNamespace(name=c) for c in caps],
    )


def test_identical_reports():
    base = _report(sections=[(".text", "aa"), (".data", "bb")], caps=["execution"])
    same = _report(sections=[(".text", "aa"), (".data", "bb")], caps=["execution"])
    d = diff_reports(same, base)
    assert d.identical
    assert d.same_imphash and d.same_authentihash


def test_trojanized_adds_section_and_capability():
    base = _report(sections=[(".text", "aa")], caps=[])
    evil = _report(authentihash="B", sections=[(".text", "aa"), (".evil", "cc")],
                   caps=["process-injection"])
    d = diff_reports(evil, base)
    assert not d.identical
    assert d.sections_added == [".evil"]
    assert "process-injection" in d.capabilities_added
    assert d.same_authentihash is False


def test_modified_section_detected():
    base = _report(sections=[(".text", "aa"), (".data", "bb")])
    patched = _report(sections=[(".text", "aa"), (".data", "ZZ")])   # .data content changed
    d = diff_reports(patched, base)
    assert d.sections_changed == [".data"]
    assert not d.sections_added and not d.sections_removed


def test_entropy_delta():
    d = diff_reports(_report(entropy=7.5), _report(entropy=6.0))
    assert d.entropy_delta == 1.5
