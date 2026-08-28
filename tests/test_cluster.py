from types import SimpleNamespace

from gokdogan.cluster import cluster_reports


def _report(path, imphash=None, rich=None, authentihash=None, ssdeep=None, impfuzzy=None):
    file = SimpleNamespace(path=path, imphash=imphash, authentihash=authentihash,
                           ssdeep=ssdeep, impfuzzy=impfuzzy)
    rich_obj = SimpleNamespace(hash=rich) if rich else None
    return SimpleNamespace(file=file, rich=rich_obj)


def test_shared_imphash_clusters():
    reports = [
        _report("a.exe", imphash="AAA"),
        _report("b.exe", imphash="AAA"),
        _report("c.exe", imphash="BBB"),
    ]
    clusters = cluster_reports(reports)
    assert len(clusters) == 1
    members = set(clusters[0].members)
    assert members == {"a.exe", "b.exe"}
    assert "imphash" in clusters[0].bases


def test_no_relation_no_cluster():
    reports = [
        _report("a.exe", imphash="AAA"),
        _report("b.exe", imphash="BBB"),
    ]
    assert cluster_reports(reports) == []


def test_transitive_chain_merges_into_one():
    # a~b by imphash, b~c by rich_hash -> a,b,c all one cluster
    reports = [
        _report("a.exe", imphash="X", rich="R1"),
        _report("b.exe", imphash="X", rich="R2"),
        _report("c.exe", imphash="Y", rich="R2"),
    ]
    clusters = cluster_reports(reports)
    assert len(clusters) == 1
    assert set(clusters[0].members) == {"a.exe", "b.exe", "c.exe"}
    assert {"imphash", "rich_hash"} <= set(clusters[0].bases)


def test_empty_hashes_do_not_link():
    # two files with empty imphash must NOT be considered related
    reports = [_report("a.exe", imphash=""), _report("b.exe", imphash="")]
    assert cluster_reports(reports) == []


def test_authentihash_links():
    reports = [
        _report("a.exe", authentihash="H"),
        _report("b.exe", authentihash="H"),
    ]
    clusters = cluster_reports(reports)
    assert len(clusters) == 1
    assert "authentihash" in clusters[0].bases
