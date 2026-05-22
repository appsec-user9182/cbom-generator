"""
Legacy compatibility shims left over from v0 of the API.
These functions are no longer called from any active route or controller.
Retained only to avoid breaking any external tooling that may import them directly.
"""

import hashlib
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad


def compute_legacy_checksum(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()


def old_session_digest(session_token: str) -> str:
    return hashlib.sha1(session_token.encode()).hexdigest()


def v0_token_encrypt(key: bytes, plaintext: bytes) -> bytes:
    padded = pad(plaintext, 8)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(padded)


def v0_api_key_hash(api_key: str) -> str:
    return hashlib.md5(api_key.encode("utf-8")).hexdigest()


def migrate_v0_password(raw: str) -> str:
    return hashlib.sha1(raw.encode()).hexdigest()
