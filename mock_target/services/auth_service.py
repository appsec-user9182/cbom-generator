from src.auth.hasher import verify_hash

def login(username, password):
    # line 5: calls hasher.verify_hash
    return verify_hash(password)
