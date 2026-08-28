"""Orchestrator: wires every analyzer into a single triage() call."""

from __future__ import annotations

from pathlib import Path

from .attack import build_attack_summary
from .blobs import find_config_blobs
from .capabilities import infer_capabilities
from .decoded import recover_encoded_strings
from .dotnet import analyze_dotnet
from .entropy import shannon_entropy
from .exports import parse_exports
from .loader import (
    NotAPEError,
    build_file_info,
    build_sections,
    delay_imported_functions,
    find_anomalies,
    imported_functions,
    load_pe,
)
from .models import SignatureInfo, TriageReport
from .overlay import analyze_overlay, overlay_anomalies
from .packers import detect_packer
from .resources import resource_anomalies, walk_resources
from .rich import parse_rich_header
from .signature import verify as verify_signature_file
from .strings_ext import analyze_strings
from .verdict import score_report
from .yara_scan import scan as yara_scan

__all__ = ["triage", "NotAPEError"]


def triage(
    path: str | Path,
    rules_dir: str | Path | None = None,
    min_string_length: int = 6,
    use_yara: bool = True,
    verify_signature: bool = True,
) -> TriageReport:
    """Run the full static triage pipeline on one PE file."""
    pe, data = load_pe(path)
    try:
        file_info = build_file_info(path, pe, data)
        dotnet = analyze_dotnet(pe, data)
        rich = parse_rich_header(pe, data)
        sections = build_sections(pe)
        anomalies = find_anomalies(pe, data, sections)
        resources = walk_resources(pe)
        overlay = analyze_overlay(pe, data)
        config_blobs = find_config_blobs(pe)
        imports = imported_functions(pe)
        delay = delay_imported_functions(pe)
        exports = parse_exports(pe, Path(path).name)
    finally:
        pe.close()

    # Authenticode verification (offline, Windows-only) — only when a blob
    # is actually present, so unsigned malware pays no cost.
    if verify_signature and file_info.is_signed:
        signature = verify_signature_file(str(path))
    elif file_info.is_signed:
        signature = SignatureInfo(status="unverified", present=True,
                                  note="verification skipped")
    else:
        signature = SignatureInfo(status="unsigned", present=False)

    if rich is not None and rich.checksum_valid is False:
        anomalies.append("Rich header checksum invalid (toolchain header forged or copied)")
    if signature.status in ("tampered", "revoked"):
        anomalies.append(f"Authenticode signature {signature.status}: {signature.note}")
    anomalies.extend(resource_anomalies(resources))
    anomalies.extend(overlay_anomalies(overlay))
    if dotnet is not None and dotnet.obfuscators:
        anomalies.append(f".NET obfuscator detected: {', '.join(dotnet.obfuscators)}")

    # Delay-loaded APIs count for capability inference just like normal ones.
    merged_imports = dict(imports)
    for dll, names in delay.items():
        merged_imports.setdefault(dll, []).extend(names)

    import_count = sum(len(v) for v in merged_imports.values())
    packer = detect_packer(sections, import_count)
    string_hits, string_stats = analyze_strings(data, min_string_length)
    decoded_strings = recover_encoded_strings(data)
    capabilities = infer_capabilities(
        merged_imports, string_hits, resources, exports, decoded_strings, config_blobs, overlay
    )

    if use_yara:
        yara_hits, yara_error = yara_scan(data, rules_dir)
    else:
        yara_hits, yara_error = [], None

    attack = build_attack_summary(capabilities, yara_hits)

    report = TriageReport(
        file=file_info,
        dotnet=dotnet,
        signature=signature,
        overlay=overlay,
        rich=rich,
        sections=sections,
        resources=resources,
        config_blobs=config_blobs,
        exports=exports,
        delay_imports=sorted(delay.keys()),
        overall_entropy=round(shannon_entropy(data), 3),
        packer=packer,
        anomalies=anomalies,
        strings=string_hits,
        string_stats=string_stats,
        decoded_strings=decoded_strings,
        capabilities=capabilities,
        attack=attack,
        yara=yara_hits,
        yara_error=yara_error,
    )
    score_report(report)
    return report
