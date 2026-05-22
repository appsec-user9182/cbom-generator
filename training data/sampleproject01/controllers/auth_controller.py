from services.auth_service import (
    verify_password_legacy,
    verify_password,
    register_user_legacy,
    register_user,
    generate_session_token,
    validate_api_key,
)
from utils.token_validator import decode_bearer_token, is_token_expired


def authenticate_user_legacy(request: dict) -> dict:
    username = request.get("username", "")
    password = request.get("password", "")
    if not username or not password:
        return {"success": False, "error": "Missing credentials"}
    ok = verify_password_legacy(username, password)
    if not ok:
        return {"success": False, "error": "Invalid credentials"}
    token = generate_session_token(username)
    return {"success": True, "token": token, "scheme": "sha1-legacy"}


def authenticate_user(request: dict) -> dict:
    username = request.get("username", "")
    password = request.get("password", "")
    if not username or not password:
        return {"success": False, "error": "Missing credentials"}
    ok = verify_password(username, password)
    if not ok:
        return {"success": False, "error": "Invalid credentials"}
    token = generate_session_token(username)
    return {"success": True, "token": token, "scheme": "pbkdf2-sha256"}


def register_new_user_legacy(request: dict) -> dict:
    username = request.get("username", "")
    password = request.get("password", "")
    if not username or not password:
        return {"success": False, "error": "Missing fields"}
    result = register_user_legacy(username, password)
    return {"success": True, "user": result}


def register_new_user(request: dict) -> dict:
    username = request.get("username", "")
    password = request.get("password", "")
    if not username or not password:
        return {"success": False, "error": "Missing fields"}
    result = register_user(username, password)
    return {"success": True, "user": result}


def check_api_key(request: dict) -> dict:
    auth_header = request.get("Authorization", "")
    token = decode_bearer_token(auth_header)
    if not token:
        return {"valid": False, "reason": "Missing token"}
    if not validate_api_key(token):
        return {"valid": False, "reason": "Invalid API key"}
    return {"valid": True}
