import os
from crypto.asymmetric import generate_rsa_2048, generate_rsa_1024, generate_dsa_key
from crypto.asymmetric import serialize_private_key_pem, serialize_public_key_pem
from crypto.hashing import sha256_hash


KEY_STORE: dict[str, dict] = {}


def create_rsa_key(key_id: str, owner: str) -> dict:
    private_key, public_key = generate_rsa_2048()
    private_pem = serialize_private_key_pem(private_key)
    public_pem = serialize_public_key_pem(public_key)
    fingerprint = sha256_hash(public_pem)
    KEY_STORE[key_id] = {
        "owner": owner,
        "algorithm": "RSA-2048",
        "private_pem": private_pem,
        "public_pem": public_pem,
        "fingerprint": fingerprint,
    }
    return {
        "key_id": key_id,
        "algorithm": "RSA-2048",
        "fingerprint": fingerprint,
        "public_pem": public_pem.decode(),
    }


def create_rsa_key_legacy(key_id: str, owner: str) -> dict:
    private_key, public_key = generate_rsa_1024()
    private_pem = serialize_private_key_pem(private_key)
    public_pem = serialize_public_key_pem(public_key)
    fingerprint = sha256_hash(public_pem)
    KEY_STORE[key_id] = {
        "owner": owner,
        "algorithm": "RSA-1024",
        "private_pem": private_pem,
        "public_pem": public_pem,
        "fingerprint": fingerprint,
    }
    return {
        "key_id": key_id,
        "algorithm": "RSA-1024",
        "fingerprint": fingerprint,
        "public_pem": public_pem.decode(),
    }


def create_dsa_key(key_id: str, owner: str) -> dict:
    private_key, public_key = generate_dsa_key()
    private_pem = serialize_private_key_pem(private_key)
    public_pem = serialize_public_key_pem(public_key)
    fingerprint = sha256_hash(public_pem)
    KEY_STORE[key_id] = {
        "owner": owner,
        "algorithm": "DSA-2048",
        "private_pem": private_pem,
        "public_pem": public_pem,
        "fingerprint": fingerprint,
    }
    return {
        "key_id": key_id,
        "algorithm": "DSA-2048",
        "fingerprint": fingerprint,
        "public_pem": public_pem.decode(),
    }


def get_key_metadata(key_id: str) -> dict | None:
    record = KEY_STORE.get(key_id)
    if not record:
        return None
    return {
        "key_id": key_id,
        "owner": record["owner"],
        "algorithm": record["algorithm"],
        "fingerprint": record["fingerprint"],
    }


def delete_key(key_id: str) -> bool:
    if key_id in KEY_STORE:
        del KEY_STORE[key_id]
        return True
    return False
