from controllers.key_controller import (
    generate_key,
    encrypt_data,
    decrypt_data,
    get_key_info,
    revoke_key,
)


def handle_generate_key(request: dict) -> dict:
    return generate_key(request)


def handle_encrypt(request: dict) -> dict:
    return encrypt_data(request)


def handle_decrypt(request: dict) -> dict:
    return decrypt_data(request)


def handle_get_key(request: dict) -> dict:
    return get_key_info(request)


def handle_revoke_key(request: dict) -> dict:
    return revoke_key(request)
