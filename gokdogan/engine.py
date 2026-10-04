"""Orchestrator: wires every analyzer into a single triage() call."""

from __future__ import annotations

from pathlib import Path

from .attack import build_attack_summary
from .blobs import find_config_blobs
from .capabilities import infer_capabilities
from .decoded import recover_encoded_strings
from .dotnet import analyze_dotnet, read_references
from .entropy import shannon_entropy
from .exports import parse_exports
from .extractors import extract_config
from .hashes import authentihash, impfuzzy
from .loader import (
    NotAPEError,
    build_file_info,
    build_sections,
    delay_imported_functions,
    distinct_import_count,
    find_anomalies,
    imported_functions,
    is_managed,
    load_pe,
    parse_pe,
)
from .models import SignatureInfo, TriageReport
from .overlay import analyze_overlay, overlay_anomalies
from .packers import detect_packer
from .resources import resource_anomalies, walk_resources
from .rich import parse_rich_header
from .signature import verify as verify_signature_file
from .signature import verify_catalog
from .stackstrings import recover_stackstrings
from .strings_ext import analyze_strings
from .verdict import score_report
from .yara_scan import scan as yara_scan

__all__ = ["triage", "triage_bytes", "NotAPEError"]


def triage(
    path: str | Path,
    rules_dir: str | Path | None = None,
    min_string_length: int = 6,
    use_yara: bool = True,
    verify_signature: bool = True,
) -> TriageReport:
    """Run the full static triage pipeline on one PE file."""
    pe, data = load_pe(path)
    return _triage(pe, data, path, rules_dir, min_string_length, use_yara,
                   verify_signature)


def triage_bytes(
    data: bytes,
    name: str = "<memory>",
    rules_dir: str | Path | None = None,
    min_string_length: int = 6,
    use_yara: bool = True,
) -> TriageReport:
    """Triage PE bytes that are not on disk (an upload, a carved file, a test).

    Authenticode verification needs a file, so a signature is reported as
    present but unverified.
    """
    return _triage(parse_pe(data, name), data, name, rules_dir, min_string_length, use_yara,
                   verify_signature=False)


def _triage(pe, data: bytes, path: str | Path, rules_dir, min_string_length: int,
            use_yara: bool, verify_signature: bool) -> TriageReport:
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
        file_info.impfuzzy = impfuzzy(imports)
        stack_strings = recover_stackstrings(pe)
        managed = is_managed(pe)
        file_info.managed = managed
        # A catalog lookup uses the hash of the bytes analysed here, never a
        # second read of a file that may have changed since.
        digests = ({"SHA256": file_info.authentihash or "", "SHA1": authentihash(pe, data, "sha1") or ""}
                   if verify_signature and not file_info.is_signed else None)
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
        # No embedded signature: Windows may still vouch for the file through
        # an installed catalog, as it does for most of what it ships.
        signature = ((verify_catalog(str(path), digests) if verify_signature else None)
                     or SignatureInfo(status="unsigned", present=False))

    if rich is not None and rich.checksum_valid is False:
        anomalies.append("Rich header checksum invalid (toolchain header forged or copied)")
    if signature.status in ("tampered", "revoked"):
        anomalies.append(f"Authenticode signature {signature.status}: {signature.note}")
    anomalies.extend(resource_anomalies(resources))
    anomalies.extend(overlay_anomalies(overlay))
    if dotnet is not None and dotnet.obfuscators:
        anomalies.append(f".NET obfuscator detected: {', '.join(dotnet.obfuscators)}")

    # Delay-loaded APIs count for capability inference just like normal ones.
    merged_imports = {dll: list(names) for dll, names in imports.items()}
    for dll, names in delay.items():
        merged_imports.setdefault(dll, []).extend(names)

    # .NET: what the managed code calls. P/Invoke functions are native imports
    # in all but name, so they join the import table for the rules: the ones
    # the IL calls when it can be read, every declaration when it cannot.
    managed_refs = pinvoke = managed_classes = None
    if dotnet is not None:
        refs = read_references(data)
        managed_refs = refs.members
        pinvoke = refs.called if refs.precise else refs.declared
        managed_classes = refs.classes if refs.precise else None
        declared = sorted({f"{dll}!{fn}" for dll, fns in refs.declared.items() for fn in fns})
        dotnet.pinvoke, dotnet.pinvoke_count = declared[:500], len(declared)
        dotnet.pinvoke_called = (sum(len(set(v)) for v in refs.called.values())
                                 if refs.precise else None)
        dotnet.member_refs = refs.member_refs
        dotnet.metadata_error = refs.error
        for dll, names in pinvoke.items():
            merged_imports.setdefault(dll, []).extend(names)
        # Malformed metadata the runtime never touches costs an author
        # nothing and blinds this stage, so it is itself a signal.
        if refs.error:
            anomalies.append(f".NET metadata unreadable ({refs.error})")
        elif refs.bad_rows:
            anomalies.append(f".NET metadata has {refs.bad_rows} malformed rows")

    import_count = sum(len(v) for v in merged_imports.values())
    packer = detect_packer(sections, import_count, is_dotnet=managed)
    string_hits, string_stats = analyze_strings(data, min_string_length)
    decoded_strings = recover_encoded_strings(data) + stack_strings
    config_extractions = extract_config(data, [d.value for d in decoded_strings])
    capabilities = infer_capabilities(
        merged_imports, string_hits, resources, exports, decoded_strings, config_blobs, overlay,
        managed=managed_refs, pinvoke=pinvoke, managed_classes=managed_classes,
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
        import_count=distinct_import_count(imports),
        overall_entropy=round(shannon_entropy(data), 3),
        # An appended payload is judged on its own (overlay.py); this is the rest.
        image_entropy=round(shannon_entropy(data[:overlay.offset] if overlay else data), 3),
        packer=packer,
        anomalies=anomalies,
        strings=string_hits,
        string_stats=string_stats,
        decoded_strings=decoded_strings,
        config_extractions=config_extractions,
        capabilities=capabilities,
        attack=attack,
        yara=yara_hits,
        yara_error=yara_error,
    )
    score_report(report)
    return report
