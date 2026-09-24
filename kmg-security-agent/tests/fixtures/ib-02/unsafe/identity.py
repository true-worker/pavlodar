import hashlib
import hmac
import time

def authenticate(token, signing_key, accounts):
    try:
        uid, expiry, signature = token.split(".")
        expires_at = int(expiry)
        message = f"{uid}.{expiry}".encode()
        expected = hmac.new(signing_key, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return None
        account = accounts.find(uid)
        if account is None or not account.is_active:
            return None
        return account
    except (ValueError, TypeError):
        return None
