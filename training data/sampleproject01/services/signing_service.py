from crypto.asymmetric import ecdsa_sign, ecdsa_verify, generate_rsa_2048, rsa_encrypt, rsa_decrypt
from crypto.hashing import sha256_hash, sha512_hash


SIGNING_KEY_CACHE: dict[str, object] = {}


def sign_with_ecdsa(payload: bytes, key_id: str) -> dict:
    signature, public_key = ecdsa_sign(payload)
    SIGNING_KEY_CACHE[key_id] = public_key
    return {
        "key_id": key_id,
        "algorithm": "ECDSA-SHA256",
        "signature": signature.hex(),
        "payload_hash": sha256_hash(payload),
    }


def verify_ecdsa_signature(payload: bytes, signature_hex: str, key_id: str) -> bool:
    public_key = SIGNING_KEY_CACHE.get(key_id)
    if not public_key:
        return False
    signature = bytes.fromhex(signature_hex)
    return ecdsa_verify(public_key, payload, signature)


def sign_with_rsa(payload: bytes) -> dict:
    private_key, public_key = generate_rsa_2048()
    payload_hash = sha512_hash(payload).encode()
    ciphertext = rsa_encrypt(public_key, payload_hash)
    return {
        "algorithm": "RSA-2048-OAEP-SHA256",
        "signature": ciphertext.hex(),
        "payload_hash": sha256_hash(payload),
    }


def create_document_signature(document_bytes: bytes, signer_id: str) -> dict:
    doc_hash = sha256_hash(document_bytes)
    sig_result = sign_with_ecdsa(document_bytes, key_id=signer_id)
    sig_result["document_hash"] = doc_hash
    return sig_result
