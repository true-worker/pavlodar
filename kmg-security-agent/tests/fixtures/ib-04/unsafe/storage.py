import hashlib

def save_account(database, key_store, profile, password):
    database.insert({"profile": profile, "password": hashlib.sha256(password.encode()).hexdigest()})
