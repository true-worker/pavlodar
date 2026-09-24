import json
import ssl
from pathlib import Path

CONFIG = json.loads(Path(__file__).with_name("transport.json").read_text())

def tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = getattr(ssl.TLSVersion, CONFIG["minimum_tls"])
    context.set_ciphers(CONFIG["ciphers"])
    return context

def dispatch(request, application):
    if not request.is_tls and CONFIG["redirect_http"]:
        return 308, {"Location": "https://support.example.test" + request.path}
    return application(request)
