"""Authenticode signature verification (Windows-only, offline).

The static parser can only see *that* a security directory exists — not
whether the signature is actually valid. This module asks Windows itself
(``WinVerifyTrust``) to verify the Authenticode chain and reports the real
status: valid, tampered (digest mismatch — the file was modified after
signing, a strong malware tell), expired, untrusted root, or unsigned. It
also pulls the signer/issuer common names from the embedded certificate.

Revocation checks are disabled so verification stays fully offline — no
CRL/OCSP network calls — keeping the promise that reputation is gokdogan's
only networked feature. On non-Windows (or any failure) it degrades to a
``status='unavailable'`` note and the static ``is_signed`` flag still holds.
"""

from __future__ import annotations

import functools
import sys
import types

from .models import SignatureInfo

_IS_WINDOWS = sys.platform == "win32"

# WinVerifyTrust result codes -> (status, human note).
_TRUST_CODES = {
    0x00000000: ("valid", "signature valid and chain trusted"),
    0x800B0100: ("unsigned", "no Authenticode signature"),
    0x800B0001: ("invalid", "unknown/invalid trust provider"),
    0x800B0003: ("invalid", "subject form not recognized"),
    0x800B0004: ("untrusted", "subject not trusted"),
    0x800B0010: ("invalid", "unknown verification action"),
    0x80096010: ("tampered", "digest mismatch — file modified after signing"),
    0x800B0101: ("expired", "signing certificate expired"),
    0x800B0109: ("untrusted", "certificate chains to an untrusted root"),
    0x800B010A: ("untrusted", "certificate chain could not be built"),
    0x800B010C: ("revoked", "signing certificate was revoked"),
}


def verify(path: str) -> SignatureInfo:
    """Verify a file's Authenticode signature via Windows WinVerifyTrust."""
    if not _IS_WINDOWS:
        return SignatureInfo(status="unavailable",
                             note="signature verification needs Windows (WinVerifyTrust)")
    try:
        status, note = _win_verify_trust(path)
    except Exception as exc:  # pragma: no cover - defensive against odd ctypes state
        return SignatureInfo(status="unavailable", note=f"verification error: {exc}")

    info = SignatureInfo(status=status, note=note,
                         verified=(status == "valid"),
                         present=(status != "unsigned"))
    if info.present:
        try:
            info.signer, info.issuer = _cert_names(path)
        except Exception:  # pragma: no cover - cert extraction is best-effort
            pass
    return info


def verify_catalog(path: str, digests: dict[str, str] | None = None) -> SignatureInfo | None:
    """A valid signature from an installed Windows catalog, or None.

    Most files Windows ships carry no embedded signature: a signed catalog
    (.cat, under System32\\CatRoot) lists their hashes instead, and
    WinVerifyTrust checks a file against it as Explorer and AppLocker do.
    Without this, every such file reads as unsigned, and rules for programs
    nobody vouches for would apply to Windows' own. Only a valid catalog
    entry counts; anything else leaves the file as unsigned as it was.

    `digests` maps "SHA256"/"SHA1" to the Authenticode hash of the bytes the
    engine analysed. With it the lookup uses those bytes, not a second read
    of a file that may have changed in between.
    """
    if not _IS_WINDOWS:
        return None
    try:
        found = _catalog_trust(path, digests)
    except Exception:  # pragma: no cover - defensive against odd ctypes state
        return None
    if found is None or found[0] != 0:
        return None
    catalog = found[1]
    info = SignatureInfo(status="valid", present=True, verified=True,
                         note=f"Windows catalog signature ({catalog.rsplit(chr(92), 1)[-1]})")
    try:
        info.signer, info.issuer = _cert_names(catalog, content=_CONTENT_PKCS7_SIGNED)
    except Exception:  # pragma: no cover - cert extraction is best-effort
        pass
    return info


# --- ctypes: WinVerifyTrust --------------------------------------------

def _win_verify_trust(path: str):
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPWSTR),
                    ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2
    guid = GUID(0xAAC56B, 0xCD44, 0x11D0,
                (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = 2            # WTD_UI_NONE
    data.fdwRevocationChecks = 0   # WTD_REVOKE_NONE — stays offline
    data.dwUnionChoice = 1         # WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 1         # WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0x00000010  # WTD_REVOCATION_CHECK_NONE

    wintrust = ctypes.windll.wintrust
    code = wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data)) & 0xFFFFFFFF

    # Release the state data.
    data.dwStateAction = 2         # WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))

    status, note = _TRUST_CODES.get(code, ("invalid", f"trust error 0x{code:08x}"))
    return status, note


# --- ctypes: catalog signatures ----------------------------------------

@functools.lru_cache(maxsize=1)
def _catalog_api():
    """The wintrust prototypes and structures, built once: ctypes caches a
    pointer type per structure class, so classes made per call add up."""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class CATALOG_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]

    class WINTRUST_CATALOG_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("dwCatalogVersion", wintypes.DWORD),
                    ("pcwszCatalogFilePath", wintypes.LPCWSTR),
                    ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR),
                    ("hMemberFile", wintypes.HANDLE),
                    ("pbCalculatedFileHash", ctypes.c_void_p),
                    ("cbCalculatedFileHash", wintypes.DWORD),
                    ("pcCatalogContext", ctypes.c_void_p),
                    ("hCatAdmin", wintypes.HANDLE)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pCatalog", ctypes.POINTER(WINTRUST_CATALOG_INFO)),
                    ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPWSTR),
                    ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    wintrust = ctypes.WinDLL("wintrust")
    acquire = wintrust.CryptCATAdminAcquireContext2
    acquire.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.LPCWSTR,
                        ctypes.c_void_p, wintypes.DWORD]
    acquire.restype = wintypes.BOOL
    calc = wintrust.CryptCATAdminCalcHashFromFileHandle2
    calc.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                     ctypes.c_void_p, wintypes.DWORD]
    calc.restype = wintypes.BOOL
    enum = wintrust.CryptCATAdminEnumCatalogFromHash
    enum.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                     ctypes.c_void_p]
    enum.restype = wintypes.HANDLE
    info_from = wintrust.CryptCATCatalogInfoFromContext
    info_from.argtypes = [wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
    info_from.restype = wintypes.BOOL
    release_cat = wintrust.CryptCATAdminReleaseCatalogContext
    release_cat.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
    release_admin = wintrust.CryptCATAdminReleaseContext
    release_admin.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    verify_trust = wintrust.WinVerifyTrust
    verify_trust.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p]
    verify_trust.restype = wintypes.LONG
    # WINTRUST_ACTION_GENERIC_VERIFY_V2
    action = GUID(0xAAC56B, 0xCD44, 0x11D0,
                  (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    return types.SimpleNamespace(
        CATALOG_INFO=CATALOG_INFO, WINTRUST_CATALOG_INFO=WINTRUST_CATALOG_INFO,
        WINTRUST_DATA=WINTRUST_DATA, acquire=acquire, calc=calc, enum=enum, info_from=info_from,
        release_cat=release_cat, release_admin=release_admin, verify_trust=verify_trust, action=action)


def _catalog_trust(path: str, digests: dict[str, str] | None = None) -> tuple[int, str] | None:
    """(WinVerifyTrust result, catalog path) for the catalog that lists this
    file's hash, or None when no installed catalog lists it."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    api = _catalog_api()
    with open(path, "rb") as fh:
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(fh.fileno()))
        # Current catalogs list SHA-256 hashes, older ones SHA-1.
        for algorithm in ("SHA256", "SHA1"):
            admin = wintypes.HANDLE()
            if not api.acquire(ctypes.byref(admin), None, algorithm, None, 0):
                continue
            try:
                digest = (ctypes.c_ubyte * 64)()
                size = wintypes.DWORD(64)
                if digests is not None:      # the bytes the engine read, not a second read
                    known = bytes.fromhex(digests.get(algorithm) or "")
                    if not known:
                        continue
                    ctypes.memmove(digest, known, len(known))
                    size.value = len(known)
                elif not api.calc(admin, handle, ctypes.byref(size), digest, 0):
                    continue
                cat = api.enum(admin, digest, size, 0, None)
                if not cat:
                    continue
                try:
                    catalog = api.CATALOG_INFO()
                    catalog.cbStruct = ctypes.sizeof(api.CATALOG_INFO)
                    if not api.info_from(cat, ctypes.byref(catalog), 0):
                        continue
                    member = api.WINTRUST_CATALOG_INFO()
                    member.cbStruct = ctypes.sizeof(api.WINTRUST_CATALOG_INFO)
                    member.pcwszCatalogFilePath = catalog.wszCatalogFile
                    member.pcwszMemberTag = bytes(digest[:size.value]).hex().upper()
                    member.pcwszMemberFilePath = path
                    member.hMemberFile = handle
                    member.pbCalculatedFileHash = ctypes.addressof(digest)
                    member.cbCalculatedFileHash = size.value
                    member.hCatAdmin = admin
                    data = api.WINTRUST_DATA()
                    data.cbStruct = ctypes.sizeof(api.WINTRUST_DATA)
                    data.dwUIChoice = 2            # WTD_UI_NONE
                    data.fdwRevocationChecks = 0   # WTD_REVOKE_NONE
                    data.dwUnionChoice = 2         # WTD_CHOICE_CATALOG
                    data.pCatalog = ctypes.pointer(member)
                    data.dwStateAction = 1         # WTD_STATEACTION_VERIFY
                    # WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL: offline by flag
                    data.dwProvFlags = 0x00000010 | 0x00001000
                    code = api.verify_trust(None, ctypes.byref(api.action), ctypes.byref(data)) & 0xFFFFFFFF
                    data.dwStateAction = 2         # WTD_STATEACTION_CLOSE
                    api.verify_trust(None, ctypes.byref(api.action), ctypes.byref(data))
                    return code, catalog.wszCatalogFile
                finally:
                    api.release_cat(admin, cat, 0)
            finally:
                api.release_admin(admin, 0)
    return None


# --- ctypes: certificate signer / issuer names -------------------------

_CONTENT_PKCS7_SIGNED_EMBED = 1 << 10   # a signature inside a PE
_CONTENT_PKCS7_SIGNED = 1 << 8          # a signed message on its own, such as a catalog


def _cert_names(path: str, content: int = _CONTENT_PKCS7_SIGNED_EMBED) -> tuple[str, str]:
    import ctypes
    from ctypes import wintypes

    crypt32 = ctypes.windll.crypt32
    # 64-bit safety: functions returning pointers must declare restype, or
    # ctypes truncates the pointer to 32 bits and later calls get garbage.
    crypt32.CertEnumCertificatesInStore.restype = ctypes.c_void_p
    crypt32.CertEnumCertificatesInStore.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD
    crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                           ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]

    CERT_QUERY_OBJECT_FILE = 1
    CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
    CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
    CERT_NAME_ISSUER_FLAG = 0x1

    crypt32.CryptMsgGetParam.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                         ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
    crypt32.CertFindCertificateInStore.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                                   wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]

    CMSG_SIGNER_CERT_INFO_PARAM = 7
    CERT_FIND_SUBJECT_CERT = 0x000B0000
    X509_ASN_ENCODING = 0x00000001
    PKCS_7_ASN_ENCODING = 0x00010000
    encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING

    h_store = wintypes.HANDLE()
    h_msg = wintypes.HANDLE()
    ok = crypt32.CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, wintypes.LPCWSTR(path),
        content, CERT_QUERY_FORMAT_FLAG_BINARY,
        0, None, None, None, ctypes.byref(h_store), ctypes.byref(h_msg), None)
    if not ok:
        return "", ""

    try:
        # Resolve the actual leaf signer cert (not an intermediate) via the
        # signed message's signer-cert info, then find it in the store.
        cert_ctx = _signer_cert(ctypes, wintypes, crypt32, h_msg, h_store,
                                CMSG_SIGNER_CERT_INFO_PARAM, CERT_FIND_SUBJECT_CERT, encoding)
        if not cert_ctx:
            cert_ctx = crypt32.CertEnumCertificatesInStore(h_store, None)  # fallback
        if not cert_ctx:
            return "", ""

        def name_string(issuer_flag: int) -> str:
            flags = CERT_NAME_ISSUER_FLAG if issuer_flag else 0
            size = crypt32.CertGetNameStringW(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                              flags, None, None, 0)
            if size <= 1:
                return ""
            buf = ctypes.create_unicode_buffer(size)
            crypt32.CertGetNameStringW(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                       flags, None, buf, size)
            return buf.value

        signer = name_string(0)
        issuer = name_string(1)
        crypt32.CertFreeCertificateContext(cert_ctx)
        return signer, issuer
    finally:
        crypt32.CertCloseStore(h_store, 0)
        # The decoded message holds the whole signature (a catalog: hundreds
        # of KB); left open it stays in memory for the life of the process.
        crypt32.CryptMsgClose.argtypes = [wintypes.HANDLE]
        if h_msg:
            crypt32.CryptMsgClose(h_msg)


def _signer_cert(ctypes, wintypes, crypt32, h_msg, h_store, param_id, find_type, encoding):
    """Look up the leaf signer certificate from a signed message."""
    size = wintypes.DWORD(0)
    if not crypt32.CryptMsgGetParam(h_msg, param_id, 0, None, ctypes.byref(size)) or size.value == 0:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if not crypt32.CryptMsgGetParam(h_msg, param_id, 0, buf, ctypes.byref(size)):
        return None
    # buf holds a CERT_INFO; CertFindCertificateInStore matches by issuer+serial.
    return crypt32.CertFindCertificateInStore(h_store, encoding, 0, find_type, buf, None)
