import hashlib, uuid
from django.conf import settings
from .audit import actor, record

class ActorMiddleware:
    def __init__(self, get_response): self.get_response = get_response
    def __call__(self, request):
        token = actor.set(request.user.pk if request.user.is_authenticated else 'anonymous')
        try: return self.get_response(request)
        finally: actor.reset(token)

class AuditMiddleware:
    """ИБ-07: one audit event per request to any route, including API, exports, bulk and refusals.

    Records the operation (view name), object id from the URL, result (HTTP status), request id and a
    keyed hash of the source address. Query strings, bodies and exported content are never logged.
    """
    def __init__(self, get_response): self.get_response = get_response
    def __call__(self, request):
        request_id = uuid.uuid4().hex
        response = self.get_response(request)
        match = getattr(request, 'resolver_match', None)
        if match is not None and not request.path.startswith(settings.STATIC_URL):
            source = hashlib.sha256(settings.SECRET_KEY.encode() + (request.META.get('REMOTE_ADDR') or '').encode()).hexdigest()[:16]
            record('request', match.view_name or 'unknown', method=request.method,
                   object={k: str(v) for k, v in match.kwargs.items()}, result=response.status_code,
                   request_id=request_id, source=source)
        return response
