from services.signing_service import (
    sign_with_ecdsa,
    verify_ecdsa_signature,
    sign_with_rsa,
    create_document_signature,
)
from services.key_service import create_rsa_key


def sign_data(request: dict) -> dict:
    payload = request.get("payload", "").encode()
    key_id = request.get("key_id", "default-signing-key")
    if not payload:
        return {"error": "Missing payload"}
    return sign_with_ecdsa(payload, key_id)


def verify_signature(request: dict) -> dict:
    payload = request.get("payload", "").encode()
    signature = request.get("signature", "")
    key_id = request.get("key_id", "")
    if not payload or not signature or not key_id:
        return {"error": "Missing payload, signature, or key_id"}
    is_valid = verify_ecdsa_signature(payload, signature, key_id)
    return {"valid": is_valid, "algorithm": "ECDSA-SHA256"}


def issue_certificate(request: dict) -> dict:
    subject = request.get("subject", "")
    owner = request.get("owner", "anonymous")
    if not subject:
        return {"error": "Missing subject"}
    key_result = create_rsa_key(f"cert-{subject}", owner)
    payload = f"CERT:{subject}:{key_result['fingerprint']}".encode()
    signature_result = sign_with_rsa(payload)
    return {
        "subject": subject,
        "public_key": key_result["public_pem"],
        "fingerprint": key_result["fingerprint"],
        "signature": signature_result,
    }


def sign_document(request: dict) -> dict:
    document = request.get("document", "").encode()
    signer_id = request.get("signer_id", "anonymous")
    if not document:
        return {"error": "Missing document"}
    return create_document_signature(document, signer_id)


def revoke_certificate(request: dict) -> dict:
    cert_id = request.get("cert_id", "")
    reason = request.get("reason", "unspecified")
    if not cert_id:
        return {"error": "Missing cert_id"}
    return {"revoked": True, "cert_id": cert_id, "reason": reason}
