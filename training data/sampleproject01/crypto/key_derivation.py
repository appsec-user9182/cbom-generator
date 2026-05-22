import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.backends import default_backend


PBKDF2_ITERATIONS = 260_000
KEY_LENGTH = 32


def derive_key_pbkdf2(password: bytes, salt: bytes | None = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=crypto_hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key, salt


def derive_key_legacy(password: bytes, salt: bytes) -> bytes:
    combined = password + salt
    return hashlib.sha256(combined).digest()


def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)


def stretch_key(raw_key: bytes, target_length: int = 32) -> bytes:
    stretched = b""
    counter = 0
    while len(stretched) < target_length:
        stretched += hashlib.sha256(raw_key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return stretched[:target_length]
