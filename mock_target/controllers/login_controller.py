from services.auth_service import login

def do_login(req):
    username = req.get("username")
    password = req.get("password")
    return login(username, password)
