import uuid
from services.key_service import (
    create_rsa_key,
    create_rsa_key_legacy,
    create_dsa_key,
    get_key_metadata,
    delete_key,
)
from services.encryption_service import aes_encrypt, aes_decrypt
from services.legacy_service import des_encrypt, des_decrypt, md5_checksum, verify_legacy_integrity


def generate_key(request: dict) -> dict:
    owner = request.get("owner", "anonymous")
    algorithm = request.get("algorithm", "RSA-2048")
    key_id = str(uuid.uuid4())

    if algorithm == "RSA-2048":
        return create_rsa_key(key_id, owner)
    elif algorithm == "DSA-2048":
        return create_dsa_key(key_id, owner)
    else:
        return {"error": f"Unsupported algorithm: {algorithm}"}


def generate_legacy_key(request: dict) -> dict:
    owner = request.get("owner", "anonymous")
    key_id = str(uuid.uuid4())
    return create_rsa_key_legacy(key_id, owner)


def encrypt_data(request: dict) -> dict:
    plaintext = request.get("plaintext", "").encode()
    passphrase = request.get("passphrase", "")
    if not plaintext or not passphrase:
        return {"error": "Missing plaintext or passphrase"}
    return aes_encrypt(plaintext, passphrase)


def decrypt_data(request: dict) -> dict:
    payload = request.get("payload")
    passphrase = request.get("passphrase", "")
    if not payload or not passphrase:
        return {"error": "Missing payload or passphrase"}
    plaintext = aes_decrypt(payload, passphrase)
    return {"plaintext": plaintext.decode(errors="replace")}


def encrypt_data_legacy(request: dict) -> dict:
    plaintext = request.get("plaintext", "").encode()
    key_hex = request.get("key", "")
    if not plaintext or not key_hex:
        return {"error": "Missing plaintext or key"}
    key = bytes.fromhex(key_hex)
    ciphertext = des_encrypt(plaintext, key)
    return {"algorithm": "DES-ECB", "ciphertext": ciphertext.hex()}


def decrypt_data_legacy(request: dict) -> dict:
    ciphertext_hex = request.get("ciphertext", "")
    key_hex = request.get("key", "")
    if not ciphertext_hex or not key_hex:
        return {"error": "Missing ciphertext or key"}
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = des_decrypt(ciphertext, key)
    return {"plaintext": plaintext.decode(errors="replace")}


def verify_data_integrity_legacy(request: dict) -> dict:
    data = request.get("data", "").encode()
    checksum = request.get("checksum", "")
    if not data:
        return {"error": "Missing data"}
    if checksum:
        is_valid = verify_legacy_integrity(data, checksum)
        return {"valid": is_valid, "algorithm": "MD5"}
    computed = md5_checksum(data)
    return {"checksum": computed, "algorithm": "MD5"}


def get_key_info(request: dict) -> dict:
    key_id = request.get("key_id", "")
    if not key_id:
        return {"error": "Missing key_id"}
    meta = get_key_metadata(key_id)
    if not meta:
        return {"error": "Key not found"}
    return meta


def revoke_key(request: dict) -> dict:
    key_id = request.get("key_id", "")
    if not key_id:
        return {"error": "Missing key_id"}
    deleted = delete_key(key_id)
    return {"deleted": deleted, "key_id": key_id}
