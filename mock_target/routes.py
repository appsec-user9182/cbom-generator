from controllers.login_controller import do_login

# This is a public API entrypoint
def handle_login_route(request):
    return do_login(request)
