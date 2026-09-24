from functools import wraps
from contextvars import ContextVar

actor = ContextVar("actor", default="system")
EVENTS = []

def record(action, result):
    EVENTS.append({"actor": actor.get(), "action": action, "result": result})

def audited(action):
    def decorate(operation):
        @wraps(operation)
        def wrapped(request):
            token = actor.set(request.user.id)
            try:
                response = operation(request)
                record(action, "success")
                return response
            except Exception:
                record(action, "error")
                raise
            finally:
                actor.reset(token)
        return wrapped
    return decorate
