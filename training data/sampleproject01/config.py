import os


class Config:
    SERVICE_NAME = "CloudKMS"
    VERSION = "2.1.0"

    HOST = os.getenv("CLOUDKMS_HOST", "0.0.0.0")
    PORT = int(os.getenv("CLOUDKMS_PORT", "8080"))

    # v1 legacy settings (deprecated)
    V1_ENABLED = os.getenv("V1_ENABLED", "true").lower() == "true"
    V1_DES_KEY_HEX = os.getenv("V1_DES_KEY", "0123456789abcdef")

    # v2 settings
    V2_RSA_KEY_SIZE = int(os.getenv("V2_RSA_KEY_SIZE", "2048"))
    V2_AES_KEY_LENGTH = int(os.getenv("V2_AES_KEY_LENGTH", "32"))
    V2_PBKDF2_ITERATIONS = int(os.getenv("V2_PBKDF2_ITERATIONS", "260000"))

    # TLS
    TLS_CERT_PATH = os.getenv("TLS_CERT", "/etc/cloudkms/tls.crt")
    TLS_KEY_PATH = os.getenv("TLS_KEY", "/etc/cloudkms/tls.key")

    # Token TTL in seconds
    TOKEN_TTL = int(os.getenv("TOKEN_TTL", "3600"))
