import os
import stat
from pathlib import Path

def read_service_only_key(name, expected_bytes):
    folder = Path(os.environ["KEY_DIRECTORY"])
    if stat.S_IMODE(folder.stat().st_mode) != 0o700:
        raise PermissionError("key directory permissions")
    path = folder / name
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise PermissionError("key file permissions")
    key = path.read_bytes()
    if len(key) != expected_bytes:
        raise ValueError("key size")
    return key
