import hashlib

def md5_helper(data):
    # line 5: MD5 cryptographic flaw (unreachable)
    return hashlib.md5(data.encode()).hexdigest()
