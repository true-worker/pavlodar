from storage import save_account

def register(request, database, key_store):
    profile = {name: request.body[name] for name in ("login", "first_name", "last_name", "middle_name", "email")}
    save_account(database, key_store, profile, request.body["password"])
