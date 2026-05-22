import os
from crypto.hashing import sha1_hash, sha256_hash, sha512_hash
from crypto.key_derivation import derive_key_pbkdf2, derive_key_legacy


USER_STORE: dict[str, dict] = {}


def register_user_legacy(username: str, password: str) -> dict:
    password_hash = sha1_hash(password.encode())
    USER_STORE[username] = {
        "hash": password_hash,
        "scheme": "sha1",
    }
    return {"username": username, "scheme": "sha1"}


def register_user(username: str, password: str) -> dict:
    salt = os.urandom(16)
    key, used_salt = derive_key_pbkdf2(password.encode(), salt)
    USER_STORE[username] = {
        "hash": key.hex(),
        "salt": used_salt.hex(),
        "scheme": "pbkdf2-sha256",
    }
    return {"username": username, "scheme": "pbkdf2-sha256"}


def verify_password_legacy(username: str, password: str) -> bool:
    record = USER_STORE.get(username)
    if not record or record.get("scheme") != "sha1":
        return False
    return sha1_hash(password.encode()) == record["hash"]


def verify_password(username: str, password: str) -> bool:
    record = USER_STORE.get(username)
    if not record or record.get("scheme") != "pbkdf2-sha256":
        return False
    salt = bytes.fromhex(record["salt"])
    key, _ = derive_key_pbkdf2(password.encode(), salt)
    return key.hex() == record["hash"]


def generate_session_token(username: str) -> str:
    entropy = os.urandom(32)
    token_data = username.encode() + entropy
    return sha512_hash(token_data)


def validate_api_key(api_key: str) -> bool:
    expected_prefix = sha256_hash(api_key.encode()[:16])
    return api_key.startswith(expected_prefix[:8])
