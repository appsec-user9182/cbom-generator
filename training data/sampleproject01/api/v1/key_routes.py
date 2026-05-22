from controllers.key_controller import (
    generate_legacy_key,
    encrypt_data_legacy,
    decrypt_data_legacy,
    verify_data_integrity_legacy,
    get_key_info,
    revoke_key,
)


def handle_generate_key_v1(request: dict) -> dict:
    return generate_legacy_key(request)


def handle_encrypt_v1(request: dict) -> dict:
    return encrypt_data_legacy(request)


def handle_decrypt_v1(request: dict) -> dict:
    return decrypt_data_legacy(request)


def handle_verify_integrity_v1(request: dict) -> dict:
    return verify_data_integrity_legacy(request)


def handle_get_key_v1(request: dict) -> dict:
    return get_key_info(request)


def handle_revoke_key_v1(request: dict) -> dict:
    return revoke_key(request)
