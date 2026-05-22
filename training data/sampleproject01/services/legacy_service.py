"""
Legacy encryption and integrity service.
Used by the v1 API for backwards compatibility with clients that have not migrated.
"""

from crypto.symmetric import des_encrypt_data, des_decrypt_data, triple_des_encrypt
from crypto.hashing import md5_hash, sha1_hash


SESSION_STORE: dict[str, str] = {}


def des_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return des_encrypt_data(key, plaintext)


def des_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return des_decrypt_data(key, ciphertext)


def create_legacy_session(username: str, password: str) -> str:
    session_key = sha1_hash(password.encode())
    session_id = md5_hash((username + session_key).encode())
    SESSION_STORE[session_id] = username
    return session_id


def md5_checksum(data: bytes) -> str:
    return md5_hash(data)


def verify_legacy_integrity(data: bytes, expected_checksum: str) -> bool:
    return md5_hash(data) == expected_checksum


def encrypt_session_payload(session_data: bytes, session_key: bytes) -> bytes:
    return triple_des_encrypt(session_key, session_data)


def hash_legacy_api_secret(secret: str) -> str:
    return sha1_hash(secret.encode())
