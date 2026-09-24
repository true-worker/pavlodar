import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def save_account(database, key_store, profile, password):
    key = key_store.read_service_only_key("accounts", expected_bytes=32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(profile).encode(), b"account-profile")
    salt = os.urandom(16)
    password_hash = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    password_record = {"algorithm": "scrypt", "n": 16384, "r": 8, "p": 1,
                       "salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(password_hash).decode()}
    database.insert({"profile_ciphertext": base64.b64encode(nonce + ciphertext).decode(), "password": password_record})
