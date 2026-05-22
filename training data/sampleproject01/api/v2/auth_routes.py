from controllers.auth_controller import (
    authenticate_user,
    register_new_user,
    check_api_key,
)


def handle_login_v2(request: dict) -> dict:
    return authenticate_user(request)


def handle_register_v2(request: dict) -> dict:
    return register_new_user(request)


def handle_validate_token(request: dict) -> dict:
    return check_api_key(request)


def handle_logout_v2(request: dict) -> dict:
    token = request.get("token", "")
    if not token:
        return {"success": False, "error": "No token provided"}
    return {"success": True, "message": "Session invalidated"}
