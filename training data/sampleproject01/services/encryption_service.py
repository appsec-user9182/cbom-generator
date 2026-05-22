import os
from crypto.symmetric import aes_encrypt_data, aes_decrypt_data
from crypto.key_derivation import derive_key_pbkdf2


def aes_encrypt(plaintext: bytes, passphrase: str) -> dict:
    salt = os.urandom(16)
    key, used_salt = derive_key_pbkdf2(passphrase.encode(), salt)
    iv, ciphertext = aes_encrypt_data(key, plaintext)
    return {
        "algorithm": "AES-256-CBC",
        "salt": used_salt.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
    }


def aes_decrypt(payload: dict, passphrase: str) -> bytes:
    salt = bytes.fromhex(payload["salt"])
    key, _ = derive_key_pbkdf2(passphrase.encode(), salt)
    iv = bytes.fromhex(payload["iv"])
    ciphertext = bytes.fromhex(payload["ciphertext"])
    return aes_decrypt_data(key, iv, ciphertext)


def encrypt_with_stored_key(key_bytes: bytes, plaintext: bytes) -> dict:
    iv, ciphertext = aes_encrypt_data(key_bytes, plaintext)
    return {
        "algorithm": "AES-256-CBC",
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
    }


def decrypt_with_stored_key(key_bytes: bytes, payload: dict) -> bytes:
    iv = bytes.fromhex(payload["iv"])
    ciphertext = bytes.fromhex(payload["ciphertext"])
    return aes_decrypt_data(key_bytes, iv, ciphertext)
