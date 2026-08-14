import json

from peregrine.attack import (
    CAPABILITY_ATTACK,
    TACTIC_ORDER,
    TECHNIQUES,
    build_attack_summary,
    parse_meta_attack,
    tactic_shortname,
    techniques_for,
    to_navigator_layer,
)
from peregrine.capabilities import infer_capabilities
from peregrine.models import (
    AttackTechnique,
    Capability,
    FileInfo,
    TriageReport,
    Verdict,
    YaraHit,
)


def _report(capabilities, attack):
    fi = FileInfo(
        path="sample.exe", size=1, md5="0" * 32, sha1="0" * 40, sha256="a" * 64,
        imphash=None, ssdeep=None, tlsh=None, file_type="PE32", compile_timestamp=None,
        compile_timestamp_anomaly=None, is_dll=False, is_driver=False,
        is_signed=False, entry_point=0, entry_section=".text",
    )
    return TriageReport(
        file=fi, capabilities=capabilities, attack=attack,
        score=99, verdict=Verdict.HIGH_RISK,
    )


def test_every_mapped_technique_is_in_catalog():
    for cap, tids in CAPABILITY_ATTACK.items():
        for tid in tids:
            assert tid in TECHNIQUES, f"{cap} -> {tid} missing from TECHNIQUES"


def test_techniques_for_unknown_capability_is_empty():
    assert techniques_for("nonexistent") == []


def test_parse_meta_attack_string_and_list():
    assert parse_meta_attack("T1055,T1486") == ["T1055", "T1486"]
    assert parse_meta_attack("T1547.001 and T1059") == ["T1547.001", "T1059"]
    assert parse_meta_attack(["T1055", "junk", "T1113"]) == ["T1055", "T1113"]
    assert parse_meta_attack(None) == []


def test_capabilities_carry_attack_ids():
    imports = {"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]}
    caps = infer_capabilities(imports, [])
    injection = next(c for c in caps if c.name == "process-injection")
    assert "T1055" in injection.attack


def test_summary_dedupes_and_records_sources():
    caps = [
        Capability("process-injection", "", 3, [], attack=["T1055"]),
        Capability("network", "", 2, [], attack=["T1071"]),
    ]
    yara = [YaraHit(rule="Injection_API_Cluster", tags=["injection"], meta={"attack": "T1055"})]
    summary = build_attack_summary(caps, yara)

    by_id = {t.id: t for t in summary}
    assert "T1055" in by_id
    # T1055 came from both the capability and the YARA rule -> two sources, one entry.
    assert by_id["T1055"].sources == ["process-injection", "yara:Injection_API_Cluster"]
    assert by_id["T1071"].name == "Application Layer Protocol"


def test_summary_sorted_by_kill_chain_tactic():
    caps = [
        Capability("anti-recovery", "", 3, [], attack=["T1490"]),      # Impact (late)
        Capability("execution", "", 1, [], attack=["T1106"]),          # Execution (early)
        Capability("persistence-registry", "", 2, [], attack=["T1547.001"]),  # Persistence
    ]
    summary = build_attack_summary(caps, [])
    tactics = [t.tactic for t in summary]
    assert tactics.index("Execution") < tactics.index("Persistence") < tactics.index("Impact")


def test_yara_meta_attack_alone_contributes():
    yara = [YaraHit(rule="Shadow_Copy_Deletion", tags=["ransomware"], meta={"attack": "T1490"})]
    summary = build_attack_summary([], yara)
    ids = {t.id for t in summary}
    # T1490 from meta, T1486 from the "ransomware" tag.
    assert {"T1490", "T1486"} <= ids


# --- Navigator layer export ---------------------------------------------

def test_tactic_shortname_kebab_case():
    assert tactic_shortname("Defense Evasion") == "defense-evasion"
    assert tactic_shortname("Command and Control") == "command-and-control"
    # every catalog tactic maps to a non-empty shortname
    for tactic in TACTIC_ORDER:
        assert tactic_shortname(tactic) and " " not in tactic_shortname(tactic)


def test_navigator_layer_schema_basics():
    caps = [Capability("process-injection", "", 3, [], attack=["T1055"])]
    attack = build_attack_summary(caps, [])
    layer = to_navigator_layer(_report(caps, attack))

    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert len(layer["techniques"]) == 1
    tech = layer["techniques"][0]
    assert tech["techniqueID"] == "T1055"
    assert tech["tactic"] == "defense-evasion"
    assert tech["enabled"] is True
    assert tech["comment"].startswith("from:")


def test_navigator_score_tracks_severity():
    info = _report(
        [Capability("execution", "", 1, [], attack=["T1106"])],
        [AttackTechnique("T1106", "Native API", "Execution", ["execution"])],
    )
    high = _report(
        [Capability("process-injection", "", 3, [], attack=["T1055"])],
        [AttackTechnique("T1055", "Process Injection", "Defense Evasion", ["process-injection"])],
    )
    info_score = to_navigator_layer(info)["techniques"][0]["score"]
    high_score = to_navigator_layer(high)["techniques"][0]["score"]
    assert info_score < high_score == 100


def test_navigator_layer_is_json_serializable():
    caps = [Capability("keylogging", "", 3, [], attack=["T1056.001"])]
    attack = build_attack_summary(caps, [])
    text = json.dumps(to_navigator_layer(_report(caps, attack)))
    reparsed = json.loads(text)
    assert reparsed["techniques"][0]["techniqueID"] == "T1056.001"
