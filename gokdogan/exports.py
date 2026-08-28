"""Export table analysis.

For DLLs, the export directory is as identifying as the import table is for
EXEs. Triage cares about a few things here:

  * **what the module exposes** — named vs ordinal-only exports, and
    forwarders (an export that redirects to another DLL, occasionally used
    to hide real behavior);
  * **how it expects to be launched** — an exported ``ReflectiveLoader`` is
    the fingerprint of a reflectively-injected DLL (Cobalt Strike / MSF
    beacons); ``DllRegisterServer``/``DllInstall`` mark a DLL built to be
    run via ``regsvr32``; ``ServiceMain`` marks a service DLL;
  * **masquerade** — an internal export name that disagrees with the file
    name can indicate a renamed/hijacked module.

Only the launch-mechanism exports feed capabilities; the rest are reported
as context.
"""

from __future__ import annotations

from .models import ExportInfo

# Exported symbol name (lowercase) -> capability key it implies.
_SUSPICIOUS_EXPORTS: dict[str, str] = {
    "reflectiveloader": "reflective-loading",
    "_reflectiveloader@4": "reflective-loading",
    "dllregisterserver": "regsvr32-loadable",
    "dllinstall": "regsvr32-loadable",
    "servicemain": "service-dll",
}

_DISPLAY_CAP = 64  # exported names kept for display / JSON


def parse_exports(pe, file_name: str) -> ExportInfo | None:
    """Return an ExportInfo for the module, or None if it exports nothing."""
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is None:
        return None

    dll_name = ""
    raw_name = getattr(export_dir, "name", None)
    if raw_name:
        dll_name = raw_name.decode("latin-1", errors="replace") if isinstance(raw_name, bytes) else str(raw_name)

    names: list[str] = []
    forwarders: list[str] = []
    ordinal_only = 0
    suspicious: set[str] = set()

    for sym in getattr(export_dir, "symbols", []):
        name = sym.name.decode("latin-1", errors="replace") if sym.name else None
        if name:
            names.append(name)
            key = _SUSPICIOUS_EXPORTS.get(name.lower())
            if key:
                suspicious.add(key)
        else:
            ordinal_only += 1
        if sym.forwarder:
            fwd = sym.forwarder.decode("latin-1", errors="replace")
            forwarders.append(f"{name or ('#' + str(sym.ordinal))} -> {fwd}")

    total = len(names) + ordinal_only
    name_mismatch = bool(dll_name) and bool(file_name) and dll_name.lower() != file_name.lower()

    return ExportInfo(
        dll_name=dll_name,
        total=total,
        named=len(names),
        ordinal_only=ordinal_only,
        forwarders=forwarders[:_DISPLAY_CAP],
        names=names[:_DISPLAY_CAP],
        suspicious=sorted(suspicious),
        name_mismatch=name_mismatch,
    )
