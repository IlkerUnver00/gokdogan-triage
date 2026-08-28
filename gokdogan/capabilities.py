"""Capability inference from imports and classified strings.

Maps imported Windows APIs to behavioral capability tags (network,
process injection, keylogging, ...) in the spirit of Mandiant's capa,
but as a lightweight rule table. Each capability needs a minimum number
of distinct API hits so a single benign import doesn't light up a tag.

Severity: 1 = informational, 2 = notable, 3 = high-signal.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attack import techniques_for
from .models import (
    Capability,
    ConfigBlob,
    DecodedString,
    ExportInfo,
    ResourceInfo,
    StringHit,
)

# Export-derived capabilities: key -> (description, severity).
_EXPORT_CAPS: dict[str, tuple[str, int]] = {
    "reflective-loading": ("Exports ReflectiveLoader — a reflectively-injected DLL (beacon/implant)", 3),
    "regsvr32-loadable": ("Exports DllRegisterServer/DllInstall — designed to run via regsvr32", 2),
    "service-dll": ("Exports ServiceMain — a service DLL (persistence host)", 2),
}


@dataclass(frozen=True)
class CapabilityRule:
    name: str
    description: str
    severity: int
    apis: frozenset[str]
    min_hits: int = 1


def _rule(name: str, description: str, severity: int, apis: list[str], min_hits: int = 1) -> CapabilityRule:
    return CapabilityRule(name, description, severity, frozenset(a.lower() for a in apis), min_hits)


RULES: list[CapabilityRule] = [
    _rule(
        "network",
        "Communicates over the network",
        2,
        [
            "WSAStartup", "socket", "connect", "send", "recv", "sendto", "recvfrom",
            "gethostbyname", "getaddrinfo", "inet_addr",
            "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
            "InternetConnectA", "InternetConnectW", "InternetReadFile",
            "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
            "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "WinHttpReadData",
            "DnsQuery_A", "DnsQuery_W",
        ],
        min_hits=2,
    ),
    _rule(
        "download-execute",
        "Can download files from the internet to disk",
        3,
        ["URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA", "URLDownloadToCacheFileW"],
    ),
    _rule(
        "process-injection",
        "Writes and executes code in other processes",
        3,
        [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
            "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
            "SetThreadContext", "NtSetContextThread", "NtMapViewOfSection", "NtUnmapViewOfSection",
            "VirtualProtectEx",
        ],
        min_hits=2,
    ),
    _rule(
        "self-modifying-memory",
        "Allocates or reprotects executable memory in its own process (shellcode staging)",
        2,
        ["VirtualAlloc", "VirtualProtect", "NtAllocateVirtualMemory", "NtProtectVirtualMemory"],
        min_hits=2,
    ),
    _rule(
        "process-discovery",
        "Enumerates running processes",
        1,
        [
            "CreateToolhelp32Snapshot", "Process32First", "Process32FirstW",
            "Process32Next", "Process32NextW", "EnumProcesses", "NtQuerySystemInformation",
        ],
        min_hits=2,
    ),
    _rule(
        "execution",
        "Launches other programs",
        1,
        ["CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW", "WinExec", "system", "_wsystem"],
    ),
    _rule(
        "persistence-registry",
        "Writes to the registry (autorun persistence when paired with Run-key strings)",
        2,
        ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW", "RegSetKeyValueA", "RegSetKeyValueW"],
    ),
    _rule(
        "persistence-service",
        "Installs or controls Windows services",
        2,
        ["CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW", "StartServiceA", "StartServiceW", "ChangeServiceConfigA", "ChangeServiceConfigW"],
        min_hits=2,
    ),
    _rule(
        "anti-debug",
        "Detects debuggers / analysis environments",
        2,
        [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "GetTickCount64",
            "QueryPerformanceCounter", "FindWindowA", "FindWindowW",
        ],
        min_hits=3,
    ),
    _rule(
        "keylogging",
        "Captures keystrokes",
        3,
        ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "RegisterRawInputDevices", "MapVirtualKeyA", "MapVirtualKeyW"],
        min_hits=2,
    ),
    _rule(
        "screen-capture",
        "Takes screenshots",
        2,
        ["GetDC", "GetWindowDC", "BitBlt", "StretchBlt", "CreateCompatibleBitmap", "CreateCompatibleDC", "GetDIBits"],
        min_hits=3,
    ),
    _rule(
        "clipboard-access",
        "Reads the clipboard",
        2,
        ["OpenClipboard", "GetClipboardData"],
        min_hits=2,
    ),
    _rule(
        "crypto",
        "Uses Windows crypto APIs (config decryption, ransomware, C2 crypto)",
        2,
        [
            "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
            "CryptGenKey", "CryptImportKey", "CryptDeriveKey", "CryptHashData",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey", "BCryptOpenAlgorithmProvider",
        ],
        min_hits=2,
    ),
    _rule(
        "privilege-manipulation",
        "Manipulates process tokens / privileges",
        2,
        ["OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW", "DuplicateTokenEx", "ImpersonateLoggedOnUser", "SetTokenInformation"],
        min_hits=2,
    ),
    _rule(
        "dynamic-api-resolution",
        "Resolves APIs at runtime (hides real imports)",
        1,
        ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"],
        min_hits=2,
    ),
    _rule(
        "anti-forensics",
        "Deletes shadow copies / clears event logs (via APIs)",
        3,
        ["EvtClearLog", "ClearEventLogA", "ClearEventLogW"],
    ),
]

# String-category evidence that upgrades or adds capabilities.
_RUN_KEY_MARKERS = ("currentversion\\run", "currentversion\\runonce", "userinit", "winlogon\\shell")
_RANSOM_COMMANDS = ("vssadmin delete", "bcdedit", "wevtutil cl", "wbadmin delete")


def infer_capabilities(
    imports: dict[str, list[str]],
    string_hits: list[StringHit],
    resources: list[ResourceInfo] | None = None,
    exports: ExportInfo | None = None,
    decoded: list[DecodedString] | None = None,
    config_blobs: list[ConfigBlob] | None = None,
    overlay=None,
) -> list[Capability]:
    all_apis = {api.lower(): api for apis in imports.values() for api in apis}
    capabilities: list[Capability] = []

    for rule in RULES:
        matched = sorted(all_apis[a] for a in (rule.apis & all_apis.keys()))
        if len(matched) >= rule.min_hits:
            capabilities.append(
                Capability(
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    evidence=matched,
                    attack=techniques_for(rule.name),
                )
            )

    # --- string-derived upgrades -------------------------------------
    run_key_strings = [
        h.value for h in string_hits
        if h.category == "registry" and any(m in h.value.lower() for m in _RUN_KEY_MARKERS)
    ]
    if run_key_strings:
        existing = next((c for c in capabilities if c.name == "persistence-registry"), None)
        if existing:
            existing.severity = 3
            existing.description += " — Run-key strings present"
            existing.evidence += [f"string: {s}" for s in run_key_strings[:5]]
        else:
            capabilities.append(
                Capability(
                    name="persistence-registry",
                    description="References autorun registry keys in strings",
                    severity=2,
                    evidence=[f"string: {s}" for s in run_key_strings[:5]],
                    attack=techniques_for("persistence-registry"),
                )
            )

    ransom_strings = [
        h.value for h in string_hits
        if h.category == "command" and any(m in h.value.lower() for m in _RANSOM_COMMANDS)
    ]
    if ransom_strings:
        capabilities.append(
            Capability(
                name="anti-recovery",
                description="Commands that destroy backups/logs (shadow copies, boot config, event logs)",
                severity=3,
                evidence=[f"string: {s}" for s in ransom_strings[:5]],
                attack=techniques_for("anti-recovery"),
            )
        )

    # --- resource/overlay-derived (dropper) --------------------------
    embedded = [
        r for r in (resources or [])
        if any(f.startswith("embedded PE") or f.startswith("contains an embedded") for f in r.flags)
    ]
    overlay_pe = overlay is not None and getattr(overlay, "contains_pe", False) \
        and not getattr(overlay, "is_signature", False)
    if embedded or overlay_pe:
        evidence = [f"resource {r.type}/{r.name} ({r.size} bytes)" for r in embedded[:5]]
        if overlay_pe:
            evidence.append(f"overlay ({overlay.size} bytes) at offset 0x{overlay.offset:x}")
        capabilities.append(
            Capability(
                name="embedded-executable",
                description="Carries a second executable inside its resources/overlay (dropper)",
                severity=3,
                evidence=evidence,
                attack=techniques_for("embedded-executable"),
            )
        )

    # --- decoded-string-derived (obfuscation) ------------------------
    if decoded:
        methods = sorted({d.encoding.split("-")[0] for d in decoded})
        capabilities.append(
            Capability(
                name="string-obfuscation",
                description="Hides strings via encoding (recovered by brute force)",
                severity=2,
                evidence=[f"{d.encoding}: {d.value}" for d in decoded[:5]] + [f"methods: {', '.join(methods)}"],
                attack=techniques_for("string-obfuscation"),
            )
        )

    # --- config-blob-derived (embedded encrypted data) ---------------
    if config_blobs:
        capabilities.append(
            Capability(
                name="embedded-config",
                description="High-entropy island(s) in a calm data section (encrypted config/payload)",
                severity=2,
                evidence=[f"{b.section}@0x{b.file_offset:x} ({b.size} B, entropy {b.entropy:.2f})"
                          for b in config_blobs[:5]],
                attack=techniques_for("embedded-config"),
            )
        )

    # --- export-derived (launch mechanism) ---------------------------
    if exports is not None:
        for key in exports.suspicious:
            description, severity = _EXPORT_CAPS[key]
            capabilities.append(
                Capability(
                    name=key,
                    description=description,
                    severity=severity,
                    evidence=[f"export of {exports.dll_name or 'this DLL'}"],
                    attack=techniques_for(key),
                )
            )

    capabilities.sort(key=lambda c: (-c.severity, c.name))
    return capabilities
