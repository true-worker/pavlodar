import json
import os
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = Path(os.environ["SERVICE_PRIVATE_ROOT"])
KEY = BASE / "keys" / "audit.key"
PENDING = BASE / "pending"

def initialize():
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(BASE, 0o755)
    KEY.parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(KEY.parent, 0o700)
    PENDING.mkdir(mode=0o700, exist_ok=True)
    os.chmod(PENDING, 0o777)
    if not KEY.exists():
        descriptor = os.open(KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(os.urandom(32))
    os.chmod(KEY, 0o600)

def append(event):
    nonce = os.urandom(12)
    payload = nonce + AESGCM(KEY.read_bytes()).encrypt(nonce, json.dumps(event).encode(), b"audit")
    path = PENDING / (uuid.uuid4().hex + ".evt")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)

def forward(path, receiver):
    payload = path.read_bytes()
    AESGCM(KEY.read_bytes()).decrypt(payload[:12], payload[12:], b"audit")
    receiver.accept_authenticated_bytes(payload)
    path.unlink()
