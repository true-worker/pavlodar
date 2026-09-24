from identity import authenticate

def profile(request):
    account = authenticate(request.headers.get("Authorization", ""), request.signing_key, request.accounts)
    if account is None:
        return 401, {"error": "unauthorized"}
    return 200, {"email": account.email, "name": account.name}

ROUTES = {("GET", "/profile"): profile}
