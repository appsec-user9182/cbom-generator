from api.v1.auth_routes import handle_login_v1, handle_register_v1, handle_logout_v1
from api.v1.key_routes import (
    handle_generate_key_v1,
    handle_encrypt_v1,
    handle_decrypt_v1,
    handle_verify_integrity_v1,
    handle_get_key_v1,
    handle_revoke_key_v1,
)
from api.v2.auth_routes import handle_login_v2, handle_register_v2, handle_validate_token, handle_logout_v2
from api.v2.key_routes import handle_generate_key, handle_encrypt, handle_decrypt, handle_get_key, handle_revoke_key
from api.v2.cert_routes import (
    handle_sign_data,
    handle_verify_signature,
    handle_issue_certificate,
    handle_sign_document,
    handle_revoke_certificate,
)


ROUTE_TABLE = {
    "POST /v1/auth/login":         handle_login_v1,
    "POST /v1/auth/register":      handle_register_v1,
    "POST /v1/auth/logout":        handle_logout_v1,
    "POST /v1/keys/generate":      handle_generate_key_v1,
    "POST /v1/keys/encrypt":       handle_encrypt_v1,
    "POST /v1/keys/decrypt":       handle_decrypt_v1,
    "POST /v1/keys/integrity":     handle_verify_integrity_v1,
    "GET  /v1/keys/:id":           handle_get_key_v1,
    "DELETE /v1/keys/:id":         handle_revoke_key_v1,
    "POST /v2/auth/login":         handle_login_v2,
    "POST /v2/auth/register":      handle_register_v2,
    "POST /v2/auth/token/validate": handle_validate_token,
    "POST /v2/auth/logout":        handle_logout_v2,
    "POST /v2/keys/generate":      handle_generate_key,
    "POST /v2/keys/encrypt":       handle_encrypt,
    "POST /v2/keys/decrypt":       handle_decrypt,
    "GET  /v2/keys/:id":           handle_get_key,
    "DELETE /v2/keys/:id":         handle_revoke_key,
    "POST /v2/certs/sign":         handle_sign_data,
    "POST /v2/certs/verify":       handle_verify_signature,
    "POST /v2/certs/issue":        handle_issue_certificate,
    "POST /v2/certs/document/sign": handle_sign_document,
    "DELETE /v2/certs/:id/revoke": handle_revoke_certificate,
}


def dispatch(method_path: str, request: dict) -> dict:
    handler = ROUTE_TABLE.get(method_path)
    if not handler:
        return {"error": "Route not found", "path": method_path}
    return handler(request)
