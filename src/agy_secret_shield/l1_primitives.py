"""Tier L1 Atomic Primitives for AGY Secret Shield.

Provides deterministic secret/cookie/PII signature detection, Shannon token entropy
calculation, and Windows DPAPI (CryptProtectData / CryptUnprotectData) secret quarantine
with cross-platform authenticated fallback.
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import math
import os
import re
from typing import Any, Optional

SECRET_SIGNATURE_CATALOG: dict[str, dict[str, Any]] = {
    "google_cookie_1psid": {
        "category": "session_cookie",
        "severity_weight": 45,
        "description": "Google __Secure-1PSID primary authentication session cookie.",
    },
    "google_cookie_sapisid": {
        "category": "session_cookie",
        "severity_weight": 40,
        "description": "Google SAPISID / __Secure-3PAPISID origin authorization cookie.",
    },
    "github_pat": {
        "category": "scm_token",
        "severity_weight": 50,
        "description": "GitHub Personal Access or OAuth Token (ghp_ / gho_ / github_pat_).",
    },
    "google_api_key": {
        "category": "cloud_credential",
        "severity_weight": 45,
        "description": "Google Cloud / Gemini API Key starting with AIza.",
    },
    "openai_api_key": {
        "category": "cloud_credential",
        "severity_weight": 45,
        "description": "OpenAI / compatible bearer secret key (sk-...).",
    },
    "private_key_pem": {
        "category": "cryptographic_key",
        "severity_weight": 60,
        "description": "PEM-encoded RSA/EC/OPENSSH private key block.",
    },
    "personal_user_path": {
        "category": "pii_path",
        "severity_weight": 35,
        "description": "Local OS user profile path or personal email identifier.",
    },
    "cyrillic_marker": {
        "category": "locale_contaminant",
        "severity_weight": 30,
        "description": "Non-English Cyrillic character range violating Gate 2 OSS hygiene.",
    },
    "high_entropy_token": {
        "category": "entropy_anomaly",
        "severity_weight": 25,
        "description": "High-entropy bearer or assignment token (> 4.2 bits/char).",
    },
    "jwt_token": {
        "category": "identity_token",
        "severity_weight": 40,
        "description": "JSON Web Token (JWT) bearer credential.",
    },
    "pkcs8_private_key": {
        "category": "cryptographic_key",
        "severity_weight": 60,
        "description": "PKCS#8 / OpenSSH format private key block.",
    },
    "github_fine_grained_pat": {
        "category": "scm_token",
        "severity_weight": 50,
        "description": "GitHub Fine-Grained Personal Access Token (github_pat_).",
    },
}

_CYRILLIC_RANGE_PATTERN = re.compile(f"[{chr(0x0400)}-{chr(0x04FF)}]+")

_COMPILED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "google_cookie_1psid",
        re.compile(r"__Secure-1PSID\s*[:=]\s*[A-Za-z0-9._\-]{8,}"),
    ),
    (
        "google_cookie_sapisid",
        re.compile(r"(?:__Secure-3PAPISID|SAPISID)\s*[:=]\s*[A-Za-z0-9._\-/]{8,}"),
    ),
    (
        "github_pat",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "github_fine_grained_pat",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
    ),
    (
        "openai_api_key",
        re.compile(r"\bsk-[A-Za-z0-9\-_]{20,}\b"),
    ),
    (
        "jwt_token",
        re.compile(r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "pkcs8_private_key",
        re.compile(r"-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----"),
    ),
    (
        "private_key_pem",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "personal_user_path",
        re.compile(r"(?:[A-Za-z]:\\Users\\[A-Za-z0-9_.\- ]+|/Users/[A-Za-z0-9_.\-]+)"),
    ),
    (
        "cyrillic_marker",
        _CYRILLIC_RANGE_PATTERN,
    ),
]


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def is_dpapi_available() -> bool:
    """Return True if Windows Crypt32 DPAPI is available in the current runtime."""
    return os.name == "nt" and hasattr(ctypes, "windll") and hasattr(ctypes.windll, "crypt32")


def compute_token_entropy(token: str) -> float:
    """Compute Shannon entropy in bits per character for a candidate token string."""
    if not token:
        return 0.0
    length = len(token)
    if length <= 1:
        return 0.0
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    if len(counts) <= 1:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def _dpapi_encrypt_bytes(raw_bytes: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32")
    kernel32 = ctypes.WinDLL("kernel32")
    in_buf = ctypes.create_string_buffer(raw_bytes, len(raw_bytes))
    in_blob = _DATA_BLOB(len(raw_bytes), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = _DATA_BLOB()
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "agy-secret-shield",
        None,
        None,
        None,
        0x1,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ValueError("Windows CryptProtectData failed")
    try:
        encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return encrypted
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_decrypt_bytes(cipher_bytes: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32")
    kernel32 = ctypes.WinDLL("kernel32")
    in_buf = ctypes.create_string_buffer(cipher_bytes, len(cipher_bytes))
    in_blob = _DATA_BLOB(len(cipher_bytes), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = _DATA_BLOB()
    try:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0x1,
            ctypes.byref(out_blob),
        )
    except Exception as exc:
        raise ValueError(f"Windows CryptUnprotectData failed or ciphertext corrupted: {exc}") from exc
    if not ok:
        raise ValueError("Windows CryptUnprotectData failed or ciphertext corrupted")
    try:
        decrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return decrypted
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _fallback_key() -> bytes:
    seed = f"agy-secret-shield-local-vault::{os.name}".encode("utf-8")
    return hashlib.sha256(seed).digest()


def _fallback_seal(raw_bytes: bytes) -> bytes:
    key = _fallback_key()
    nonce = os.urandom(16)
    stream = bytearray()
    counter = 0
    while len(stream) < len(raw_bytes):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        stream.extend(block)
        counter += 1
    xored = bytes(a ^ b for a, b in zip(raw_bytes, stream[: len(raw_bytes)]))
    mac = hmac.new(key, nonce + xored, hashlib.sha256).digest()
    return nonce + mac + xored


def _fallback_unseal(blob: bytes) -> bytes:
    if len(blob) < 48:
        raise ValueError("Corrupted fallback ciphertext envelope")
    key = _fallback_key()
    nonce = blob[:16]
    mac = blob[16:48]
    xored = blob[48:]
    expected_mac = hmac.new(key, nonce + xored, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("Fallback ciphertext MAC verification failed")
    stream = bytearray()
    counter = 0
    while len(stream) < len(xored):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        stream.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(xored, stream[: len(xored)]))


def dpapi_seal_secret(plaintext: str, description: str = "agy-secret") -> dict[str, Any]:
    """Seal a sensitive secret string using Windows DPAPI (with local AEAD fallback)."""
    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("Plaintext secret must be a non-empty string")
    raw_bytes = plaintext.encode("utf-8")
    digest_hex = hashlib.sha256(raw_bytes).hexdigest()

    if is_dpapi_available():
        try:
            cipher_bytes = _dpapi_encrypt_bytes(raw_bytes)
            engine = "windows_dpapi"
        except Exception:
            cipher_bytes = _fallback_seal(raw_bytes)
            engine = "local_aead_fallback"
    else:
        cipher_bytes = _fallback_seal(raw_bytes)
        engine = "local_aead_fallback"

    ciphertext_b64 = base64.b64encode(cipher_bytes).decode("ascii")
    return {
        "engine": engine,
        "description": description,
        "ciphertext_b64": ciphertext_b64,
        "sha256": digest_hex,
        "redacted_tag": f"[REDACTED_DPAPI:{digest_hex[:12]}]",
    }


def dpapi_unseal_secret(envelope: dict[str, Any]) -> str:
    """Unseal a DPAPI or fallback secret envelope back into its original plaintext."""
    if not isinstance(envelope, dict):
        raise ValueError("Envelope must be a dictionary")
    ciphertext_b64 = envelope.get("ciphertext_b64", "")
    if not isinstance(ciphertext_b64, str) or not ciphertext_b64.strip():
        raise ValueError("Envelope ciphertext_b64 must be a non-empty string")
    try:
        cipher_bytes = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("Invalid base64 in ciphertext_b64") from exc
    if not cipher_bytes:
        raise ValueError("Decoded cipher_bytes is empty")

    engine = envelope.get("engine", "windows_dpapi")
    if engine == "windows_dpapi" and is_dpapi_available():
        raw_bytes = _dpapi_decrypt_bytes(cipher_bytes)
    elif engine == "local_aead_fallback":
        raw_bytes = _fallback_unseal(cipher_bytes)
    else:
        raise ValueError(f"Unsupported or unavailable DPAPI engine: {engine}")

    return raw_bytes.decode("utf-8")


def scan_text_for_secrets(
    text: str,
    extra_pii_tokens: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Scan text for secrets, cookies, Cyrillic characters, and custom PII tokens.

    Replaces every sensitive match in `sanitized_text` with `[REDACTED_DPAPI:<hash12>]`.
    """
    if not text:
        return {
            "clean": True,
            "finding_count": 0,
            "risk_score": 0,
            "findings": [],
            "sanitized_text": text,
        }

    findings: list[dict[str, Any]] = []
    sanitized = text
    total_weight = 0

    for rule_id, pattern in _COMPILED_PATTERNS:
        meta = SECRET_SIGNATURE_CATALOG[rule_id]
        matches = list(pattern.finditer(text))
        for m in matches:
            matched_val = m.group(0)
            digest12 = hashlib.sha256(matched_val.encode("utf-8")).hexdigest()[:12]
            tag = f"[REDACTED_DPAPI:{digest12}]"
            entropy = compute_token_entropy(matched_val)
            findings.append(
                {
                    "rule_id": rule_id,
                    "category": meta["category"],
                    "severity_weight": meta["severity_weight"],
                    "description": meta["description"],
                    "entropy": entropy,
                    "redacted_tag": tag,
                    "span": [m.start(), m.end()],
                }
            )
            total_weight += int(meta["severity_weight"])
            sanitized = sanitized.replace(matched_val, tag)

    if extra_pii_tokens:
        meta = SECRET_SIGNATURE_CATALOG["personal_user_path"]
        for token in extra_pii_tokens:
            if not token:
                continue
            token_pattern = re.compile(re.escape(token), re.IGNORECASE)
            for m in token_pattern.finditer(text):
                matched_val = m.group(0)
                digest12 = hashlib.sha256(matched_val.encode("utf-8")).hexdigest()[:12]
                tag = f"[REDACTED_DPAPI:{digest12}]"
                findings.append(
                    {
                        "rule_id": "personal_user_path",
                        "category": meta["category"],
                        "severity_weight": meta["severity_weight"],
                        "description": "Custom PII / organizational identifier match.",
                        "entropy": compute_token_entropy(matched_val),
                        "redacted_tag": tag,
                        "span": [m.start(), m.end()],
                    }
                )
                total_weight += int(meta["severity_weight"])
                sanitized = sanitized.replace(matched_val, tag)

    risk_score = min(100, total_weight)
    return {
        "clean": len(findings) == 0,
        "finding_count": len(findings),
        "risk_score": risk_score,
        "findings": findings,
        "sanitized_text": sanitized,
    }


def batch_dpapi_seal(
    plaintexts: list[str],
    description_prefix: str = "batch-secret",
) -> list[dict[str, Any]]:
    """Encrypt a sequence of plaintext strings into DPAPI/AEAD envelopes."""
    return [
        dpapi_seal_secret(p, description=f"{description_prefix}-{idx}")
        for idx, p in enumerate(plaintexts)
    ]


def batch_dpapi_unseal(
    envelopes: list[dict[str, Any]],
) -> list[str]:
    """Decrypt a sequence of DPAPI/AEAD envelopes back into plaintext strings."""
    return [dpapi_unseal_secret(env) for env in envelopes]


def rotate_dpapi_quarantine(
    envelopes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Unseal all envelopes and re-encrypt them into fresh envelopes,
    verifying 100% byte-identical round-trip consistency.
    """
    plaintexts = batch_dpapi_unseal(envelopes)
    new_envelopes = batch_dpapi_seal(plaintexts, description_prefix="rotated-secret")
    recovered = batch_dpapi_unseal(new_envelopes)
    if recovered != plaintexts:
        raise ValueError("Batch DPAPI rotation failed: roundtrip plaintext mismatch")
    return new_envelopes
