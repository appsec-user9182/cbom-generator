import os

from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad


AES_BLOCK_SIZE = 16
DES_BLOCK_SIZE = 8


def aes_encrypt_data(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(AES_BLOCK_SIZE)
    algorithm = AES(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = plaintext + b"\x00" * (AES_BLOCK_SIZE - len(plaintext) % AES_BLOCK_SIZE)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt_data(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    algorithm = AES(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def des_encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    padded = pad(plaintext, DES_BLOCK_SIZE)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(padded)


def des_decrypt_data(key: bytes, ciphertext: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES_BLOCK_SIZE)


def triple_des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    padded = pad(plaintext, DES_BLOCK_SIZE)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(padded)


def triple_des_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES_BLOCK_SIZE)
