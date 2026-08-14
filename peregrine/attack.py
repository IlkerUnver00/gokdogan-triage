"""MITRE ATT&CK mapping.

A small, curated slice of the ATT&CK Enterprise matrix — only the
techniques peregrine's capabilities and YARA rules can actually imply
from static features. Kept deliberately hand-maintained rather than
pulling the full STIX bundle: triage wants a handful of high-confidence
techniques an analyst recognizes, not the entire matrix.

Two tables:
  TECHNIQUES        — technique id -> (name, tactic)
  CAPABILITY_ATTACK — capability name -> [technique ids]

YARA rules may additionally declare `meta.attack = "T1055,T1486"` and those
ids are merged into the report's technique summary.
"""

from __future__ import annotations

import re

# Kill-chain order, used to sort the summary matrix.
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# technique id -> (technique name, ATT&CK tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1095": ("Non-Application Layer Protocol", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1573": ("Encrypted Channel", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),
    "T1106": ("Native API", "Execution"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", "Defense Evasion"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1622": ("Debugger Evasion", "Defense Evasion"),
    "T1497": ("Virtualization / Sandbox Evasion", "Defense Evasion"),
    "T1056.001": ("Input Capture: Keylogging", "Collection"),
    "T1113": ("Screen Capture", "Collection"),
    "T1115": ("Clipboard Data", "Collection"),
    "T1140": ("Deobfuscate / Decode Files or Information", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1134": ("Access Token Manipulation", "Privilege Escalation"),
    "T1027.007": ("Obfuscated Files or Information: Dynamic API Resolution", "Defense Evasion"),
    "T1027.002": ("Obfuscated Files or Information: Software Packing", "Defense Evasion"),
    "T1027.009": ("Obfuscated Files or Information: Embedded Payloads", "Defense Evasion"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
}

# capability name -> technique ids it implies.
CAPABILITY_ATTACK: dict[str, list[str]] = {
    "network": ["T1071"],
    "embedded-executable": ["T1027.009"],
    "reflective-loading": ["T1620"],
    "string-obfuscation": ["T1140"],
    "embedded-config": ["T1027"],
    "regsvr32-loadable": ["T1218.010"],
    "service-dll": ["T1543.003"],
    "download-execute": ["T1105"],
    "process-injection": ["T1055"],
    "self-modifying-memory": ["T1620"],
    "process-discovery": ["T1057"],
    "execution": ["T1106"],
    "persistence-registry": ["T1547.001"],
    "persistence-service": ["T1543.003"],
    "anti-debug": ["T1622", "T1497"],
    "keylogging": ["T1056.001"],
    "screen-capture": ["T1113"],
    "clipboard-access": ["T1115"],
    "crypto": ["T1140"],
    "privilege-manipulation": ["T1134"],
    "dynamic-api-resolution": ["T1027.007"],
    "anti-forensics": ["T1070.001"],
    "anti-recovery": ["T1490"],
    # string/YARA-derived pseudo-capabilities (also matched against YARA tags):
    "packer": ["T1027.002"],
    "ransomware": ["T1486"],
    "exfil": ["T1048"],
    "injection": ["T1055"],
    "execution": ["T1106"],
}

_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def techniques_for(capability_name: str) -> list[str]:
    """ATT&CK technique ids implied by a capability name (empty if unmapped)."""
    return list(CAPABILITY_ATTACK.get(capability_name, []))


def parse_meta_attack(value: object) -> list[str]:
    """Extract technique ids from a YARA `meta.attack` value (str or list)."""
    if isinstance(value, str):
        return _TID_RE.findall(value)
    if isinstance(value, (list, tuple)):
        ids: list[str] = []
        for item in value:
            ids.extend(_TID_RE.findall(str(item)))
        return ids
    return []


def technique_name(tid: str) -> str:
    entry = TECHNIQUES.get(tid)
    return entry[0] if entry else "Unknown technique"


def technique_tactic(tid: str) -> str:
    entry = TECHNIQUES.get(tid)
    return entry[1] if entry else "Uncategorized"


def _tactic_sort_key(tactic: str) -> int:
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(TACTIC_ORDER)


def build_attack_summary(capabilities, yara_hits) -> "list":
    """Aggregate ATT&CK techniques from capabilities and YARA hits.

    Returns a list of AttackTechnique, deduplicated by id, each carrying
    the sources (capability names / YARA rule names) that implied it,
    sorted in kill-chain tactic order then by id.
    """
    from .models import AttackTechnique  # local import to avoid a cycle

    # technique id -> ordered, unique list of source labels
    collected: dict[str, list[str]] = {}

    def add(tid: str, source: str) -> None:
        sources = collected.setdefault(tid, [])
        if source not in sources:
            sources.append(source)

    for cap in capabilities:
        for tid in getattr(cap, "attack", []) or []:
            add(tid, cap.name)

    for hit in yara_hits:
        for tid in parse_meta_attack(hit.meta.get("attack")):
            add(tid, f"yara:{hit.rule}")
        for tag in hit.tags:
            for tid in CAPABILITY_ATTACK.get(tag.lower(), []):
                add(tid, f"yara:{hit.rule}")

    techniques = [
        AttackTechnique(
            id=tid,
            name=technique_name(tid),
            tactic=technique_tactic(tid),
            sources=sources,
        )
        for tid, sources in collected.items()
    ]
    techniques.sort(key=lambda t: (_tactic_sort_key(t.tactic), t.id))
    return techniques


# --- MITRE ATT&CK Navigator layer export --------------------------------

# Navigator pins a technique to a cell by tactic *shortname* (kebab-case).
def tactic_shortname(tactic: str) -> str:
    return tactic.lower().replace(" ", "-")


# Score reflects triage confidence so Navigator's gradient is meaningful.
_SEVERITY_SCORE = {1: 40, 2: 70, 3: 100}
_YARA_SCORE = 85
_DEFAULT_SCORE = 60


def _technique_score(technique, capabilities) -> int:
    severity_by_name = {c.name: c.severity for c in capabilities}
    severities = [severity_by_name[s] for s in technique.sources if s in severity_by_name]
    score = max((_SEVERITY_SCORE[s] for s in severities), default=0)
    if any(s.startswith("yara:") for s in technique.sources):
        score = max(score, _YARA_SCORE)
    return score or _DEFAULT_SCORE


def to_navigator_layer(report, name: str | None = None) -> dict:
    """Build a MITRE ATT&CK Navigator (layer format 4.5) dict for a report.

    Load the result at https://mitre-attack.github.io/attack-navigator/ to
    see the sample's observed techniques highlighted on the matrix, shaded
    by triage confidence.
    """
    sample = name or report.file.sha256[:16] or report.file.path

    techniques = []
    for tech in report.attack:
        techniques.append(
            {
                "techniqueID": tech.id,
                "tactic": tactic_shortname(tech.tactic),
                "score": _technique_score(tech, report.capabilities),
                "comment": "from: " + ", ".join(tech.sources),
                "enabled": True,
                "showSubtechniques": True,
                "metadata": [],
            }
        )

    return {
        "name": f"peregrine — {sample}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"peregrine static triage of {report.file.path} "
            f"(verdict {report.verdict.value}, score {report.score}, "
            f"sha256 {report.file.sha256})"
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe6e6", "#ff6666", "#cc0000"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "info (sev 1)", "color": "#ffe6e6"},
            {"label": "notable (sev 2) / YARA", "color": "#ff6666"},
            {"label": "high (sev 3)", "color": "#cc0000"},
        ],
        "sorting": 3,          # descending by score
        "hideDisabled": True,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
    }
