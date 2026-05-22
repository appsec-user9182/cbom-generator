import time
import base64
from typing import Optional


TOKEN_TTL_SECONDS = 3600


def decode_bearer_token(authorization_header: str) -> Optional[str]:
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return None
    return authorization_header[len("Bearer "):]


def is_token_expired(issued_at: float, ttl: int = TOKEN_TTL_SECONDS) -> bool:
    return (time.time() - issued_at) > ttl


def encode_key_id(namespace: str, key_id: str) -> str:
    raw = f"{namespace}:{key_id}".encode()
    return base64.urlsafe_b64encode(raw).decode()


def decode_key_id(encoded: str) -> tuple[str, str]:
    raw = base64.urlsafe_b64decode(encoded.encode()).decode()
    namespace, key_id = raw.split(":", 1)
    return namespace, key_id


def sanitize_key_id(key_id: str) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    return "".join(c for c in key_id if c in allowed)
