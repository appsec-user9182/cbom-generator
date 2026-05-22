import hashlib


def md5_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha1_hash(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512_hash(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def compute_hmac_sha256(key: bytes, message: bytes) -> str:
    import hmac
    sig = hmac.new(key, message, hashlib.sha256)
    return sig.hexdigest()
