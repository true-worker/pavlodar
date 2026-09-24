from functools import wraps

def administration(view):
    @wraps(view)
    def wrapped(request):
        user = request.user
        if not user.is_authenticated or not user.is_active or not user.is_staff:
            return 403, {"error": "forbidden"}
        return view(request)
    return wrapped
