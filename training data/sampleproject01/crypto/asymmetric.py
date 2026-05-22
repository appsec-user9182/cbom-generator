from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_2048() -> tuple:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_rsa_1024() -> tuple:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def ecdsa_sign(data: bytes) -> tuple:
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature, private_key.public_key()


def ecdsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def generate_dsa_key() -> tuple:
    private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key_pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
