"""Capability inference from imports and classified strings.

Maps imported Windows APIs to behavioral capability tags (network,
process injection, keylogging, ...) in the spirit of Mandiant's capa,
but as a lightweight rule table. Each capability needs a minimum number
of distinct API hits so a single benign import doesn't light up a tag.

Severity: 1 = informational, 2 = notable, 3 = high-signal.
"""

from __future__ import annotations

import re
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
    # How a DLL is launched, not what it does: every COM server exports
    # DllRegisterServer and every svchost service exports ServiceMain.
    "regsvr32-loadable": ("Exports DllRegisterServer/DllInstall — designed to run via regsvr32", 1),
    "service-dll": ("Exports ServiceMain — a service DLL (persistence host)", 1),
}


@dataclass(frozen=True)
class CapabilityRule:
    name: str
    description: str
    severity: int
    apis: frozenset[str]
    min_hits: int = 1
    # Functions specific enough to carry the rule, as groups: the A and W
    # variants of one function are one group, so importing both is one piece
    # of evidence, not two. Generic APIs every program links still count
    # towards min_hits and show as evidence, but the rule also needs
    # min_required groups, at least one of them from `required`; a `support`
    # group only counts alongside one.
    required: tuple[frozenset[str], ...] = ()
    support: tuple[frozenset[str], ...] = ()
    min_required: int = 0


_CHARSET_SUFFIX = re.compile(r"(?<=[a-z0-9])[AW]$")


def _groups(apis: list[str] | None) -> tuple[frozenset[str], ...]:
    families: dict[str, set[str]] = {}
    for api in apis or []:
        families.setdefault(_CHARSET_SUFFIX.sub("", api), set()).add(api.lower())
    return tuple(frozenset(g) for g in families.values())


def _rule(name: str, description: str, severity: int, apis: list[str], min_hits: int = 1,
          required: list[str] | None = None, support: list[str] | None = None,
          min_required: int = 1) -> CapabilityRule:
    req, sup = _groups(required), _groups(support)
    every = frozenset(a.lower() for a in apis).union(*req, *sup)
    return CapabilityRule(name, description, severity, every, min_hits, req, sup,
                          min_required if req else 0)


def _specific_evidence(rule: CapabilityRule, names: set[str]) -> bool:
    if not rule.min_required:
        return True
    required = sum(1 for g in rule.required if g & names)
    support = sum(1 for g in rule.support if g & names)
    return required >= 1 and required + support >= rule.min_required


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
    # Writing the registry is how programs store settings; it becomes
    # persistence (severity 3) only with Run-key strings, upgraded below.
    _rule(
        "persistence-registry",
        "Writes to the registry (autorun persistence when paired with Run-key strings)",
        1,
        ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW", "RegSetKeyValueA", "RegSetKeyValueW"],
    ),
    _rule(
        "persistence-service",
        "Installs or controls Windows services",
        2,
        ["CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW", "StartServiceA", "StartServiceW", "ChangeServiceConfigA", "ChangeServiceConfigW"],
        min_hits=2,
    ),
    # IsDebuggerPresent, the tick counters and OutputDebugString are linked
    # into every MSVC runtime, so alone they prove nothing; an actual check
    # needs CheckRemoteDebuggerPresent or NtQueryInformationProcess.
    _rule(
        "anti-debug",
        "Detects debuggers / analysis environments",
        2,
        [
            "IsDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW",
            "GetTickCount", "GetTickCount64", "QueryPerformanceCounter", "FindWindowA", "FindWindowW",
        ],
        min_hits=3,
        required=["CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
    ),
    # GetKeyState is how every GUI checks Ctrl/Shift. Capturing keystrokes
    # takes a capture mechanism (a hook, async polling or raw input) plus a
    # second one, a keyboard-state read, or a key-to-character translation:
    # translation is what turns key events into a log.
    _rule(
        "keylogging",
        "Captures keystrokes",
        3,
        ["GetKeyState"],
        min_hits=2,
        required=["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
                  "RegisterRawInputDevices"],
        support=["GetKeyboardState", "ToUnicode", "ToUnicodeEx", "ToAscii", "ToAsciiEx",
                 "MapVirtualKeyA", "MapVirtualKeyW", "MapVirtualKeyExA", "MapVirtualKeyExW",
                 "GetKeyNameTextA", "GetKeyNameTextW"],
        min_required=2,
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
# Applied to strings already classified as commands (strings_ext). A tool
# name may carry ".exe" and a closing quote, as the command patterns allow.
_X = r"(?:\.exe)?\"?"
_ANTI_RECOVERY = re.compile(
    r"vssadmin" + _X + r"\s+(?:delete|resize)|shadowcopy[^\r\n]{0,160}?delete|"
    r"bcdedit" + _X + r"\s[^\r\n]{0,80}?/(?:set|delete)\b|wbadmin" + _X + r"\s+delete|"
    r"wevtutil" + _X + r"\s+(?:cl|clear-log)\b",
    re.I,
)


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

    names = set(all_apis)
    for rule in RULES:
        matched = sorted(all_apis[a] for a in (rule.apis & names))
        if not _specific_evidence(rule, names):
            continue
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
                    source="strings",
                )
            )

    ransom_strings = [
        h.value for h in string_hits
        if h.category == "command" and _ANTI_RECOVERY.search(h.value)
    ]
    if ransom_strings:
        capabilities.append(
            Capability(
                name="anti-recovery",
                description="Commands that destroy backups/logs (shadow copies, boot config, event logs)",
                severity=3,
                # All of them, not a sample: the verdict checks YARA matches
                # against this list (reports show the first few).
                evidence=[f"string: {s}" for s in ransom_strings],
                attack=techniques_for("anti-recovery"),
                source="strings",
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
                source="resources",
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
                source="decoded",
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
                source="sections",
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
                    source="exports",
                )
            )

    capabilities.sort(key=lambda c: (-c.severity, c.name))
    return capabilities
