from controllers.auth_controller import (
    authenticate_user_legacy,
    register_new_user_legacy,
)


def handle_login_v1(request: dict) -> dict:
    return authenticate_user_legacy(request)


def handle_register_v1(request: dict) -> dict:
    return register_new_user_legacy(request)


def handle_logout_v1(request: dict) -> dict:
    token = request.get("token", "")
    if not token:
        return {"success": False, "error": "No token provided"}
    return {"success": True, "message": "Logged out"}
