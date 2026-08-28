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

import sys

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
    data.dwProvFlags = 0x00000010  # WTD_SAFER_FLAG

    wintrust = ctypes.windll.wintrust
    code = wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data)) & 0xFFFFFFFF

    # Release the state data.
    data.dwStateAction = 2         # WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))

    status, note = _TRUST_CODES.get(code, ("invalid", f"trust error 0x{code:08x}"))
    return status, note


# --- ctypes: certificate signer / issuer names -------------------------

def _cert_names(path: str) -> tuple[str, str]:
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
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
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
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
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
