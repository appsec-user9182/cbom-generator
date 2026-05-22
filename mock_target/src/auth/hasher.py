import hashlib

def verify_hash(data):
    # line 5: SHA-1 cryptographic flaw
    return hashlib.sha1(data.encode()).hexdigest()
