#!/usr/bin/env python3
"""
Crypto utilities for FortifyOne
- Encrypt/decrypt audit JSON at rest (Fernet + PBKDF2)
- HMAC-SHA256 signatures for report integrity

Key source (first match wins):
  1. FORTIFYONE_PASSPHRASE environment variable
  2. FORTIFYONE_KEY_FILE path to a passphrase file
  3. Explicit passphrase argument

If no key is available, data is stored plaintext (backward compatible).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Optional, Tuple, Union

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

MAGIC = b"F1ENC1"  # encrypted audit file magic
SALT_SIZE = 16
ITERATIONS = 390_000
SIG_SUFFIX = ".sig"


def _get_passphrase(explicit: Optional[str] = None) -> Optional[str]:
    if explicit:
        return explicit.strip()
    env = os.environ.get("FORTIFYONE_PASSPHRASE", "").strip()
    if env:
        return env
    key_file = os.environ.get("FORTIFYONE_KEY_FILE", "").strip()
    if key_file and Path(key_file).is_file():
        try:
            return Path(key_file).read_text(encoding="utf-8").strip()
        except OSError:
            return None
    return None


def _derive_fernet_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def _derive_hmac_key(passphrase: str) -> bytes:
    # Separate domain separation from encryption key
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        b"fortifyone-hmac-v1",
        ITERATIONS,
        dklen=32,
    )


def is_encrypted_bytes(data: bytes) -> bool:
    return data.startswith(MAGIC)


def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography package required for encryption. pip install cryptography")
    salt = os.urandom(SALT_SIZE)
    key = _derive_fernet_key(passphrase, salt)
    token = Fernet(key).encrypt(plaintext)
    return MAGIC + salt + token


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography package required for decryption. pip install cryptography")
    if not blob.startswith(MAGIC):
        raise ValueError("Not an encrypted FortifyOne file")
    salt = blob[len(MAGIC) : len(MAGIC) + SALT_SIZE]
    token = blob[len(MAGIC) + SALT_SIZE :]
    key = _derive_fernet_key(passphrase, salt)
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken as e:
        raise ValueError("Decryption failed — wrong passphrase or corrupted file") from e


def save_json_secure(
    path: Path,
    data: dict,
    passphrase: Optional[str] = None,
    force_encrypt: bool = False,
) -> bool:
    """
    Save audit JSON. Encrypts when passphrase is available (or force_encrypt).
    Returns True if encrypted, False if plaintext.
    """
    raw = json.dumps(data, indent=2, default=str).encode("utf-8")
    pw = _get_passphrase(passphrase)
    path = Path(path)

    if pw and HAS_CRYPTO:
        blob = encrypt_bytes(raw, pw)
        path.write_bytes(blob)
        encrypted = True
    else:
        if force_encrypt and not HAS_CRYPTO:
            raise RuntimeError("Cannot force encrypt: cryptography not installed")
        if force_encrypt and not pw:
            raise ValueError("No passphrase provided for encryption")
        path.write_text(raw.decode("utf-8"), encoding="utf-8")
        encrypted = False

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return encrypted


def load_json_secure(path: Path, passphrase: Optional[str] = None) -> dict:
    """Load audit JSON, decrypting if needed."""
    path = Path(path)
    blob = path.read_bytes()

    if is_encrypted_bytes(blob):
        pw = _get_passphrase(passphrase)
        if not pw:
            raise ValueError(
                "File is encrypted. Set FORTIFYONE_PASSPHRASE or pass --passphrase"
            )
        plain = decrypt_bytes(blob, pw)
        return json.loads(plain.decode("utf-8"))

    # Plaintext JSON
    return json.loads(blob.decode("utf-8"))


def sign_file(path: Path, passphrase: Optional[str] = None) -> Optional[Path]:
    """
    Create path.sig containing hex HMAC-SHA256 of file contents.
    Returns signature path or None if no key available.
    """
    pw = _get_passphrase(passphrase)
    if not pw:
        return None
    path = Path(path)
    if not path.is_file():
        return None
    key = _derive_hmac_key(pw)
    digest = hmac.new(key, path.read_bytes(), hashlib.sha256).hexdigest()
    sig_path = path.with_suffix(path.suffix + SIG_SUFFIX)
    # Format: algorithm key-id digest
    sig_path.write_text(f"HMAC-SHA256 fortifyone-v1 {digest}\n", encoding="utf-8")
    try:
        os.chmod(sig_path, 0o600)
    except OSError:
        pass
    return sig_path


def verify_file(path: Path, passphrase: Optional[str] = None) -> Tuple[bool, str]:
    """
    Verify path against path.sig.
    Returns (ok, message).
    """
    path = Path(path)
    sig_path = path.with_suffix(path.suffix + SIG_SUFFIX)
    if not path.is_file():
        return False, "File not found"
    if not sig_path.is_file():
        return False, "No signature file (.sig) found"

    pw = _get_passphrase(passphrase)
    if not pw:
        return False, "No passphrase — cannot verify"

    try:
        line = sig_path.read_text(encoding="utf-8").strip().split()
        if len(line) < 3 or line[0] != "HMAC-SHA256":
            return False, "Unrecognized signature format"
        expected = line[-1]
    except OSError as e:
        return False, f"Cannot read signature: {e}"

    key = _derive_hmac_key(pw)
    actual = hmac.new(key, path.read_bytes(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(actual, expected):
        return True, "Signature valid"
    return False, "Signature INVALID — file may have been tampered with"


def crypto_status() -> dict:
    return {
        "cryptography_installed": HAS_CRYPTO,
        "passphrase_configured": bool(_get_passphrase()),
        "encryption_available": HAS_CRYPTO and bool(_get_passphrase()),
        "signing_available": bool(_get_passphrase()),
    }
