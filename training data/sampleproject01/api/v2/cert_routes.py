from controllers.cert_controller import (
    sign_data,
    verify_signature,
    issue_certificate,
    sign_document,
    revoke_certificate,
)


def handle_sign_data(request: dict) -> dict:
    return sign_data(request)


def handle_verify_signature(request: dict) -> dict:
    return verify_signature(request)


def handle_issue_certificate(request: dict) -> dict:
    return issue_certificate(request)


def handle_sign_document(request: dict) -> dict:
    return sign_document(request)


def handle_revoke_certificate(request: dict) -> dict:
    return revoke_certificate(request)
