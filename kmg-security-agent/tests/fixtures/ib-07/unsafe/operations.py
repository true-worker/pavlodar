from audit import audited

def items(request):
    return request.database.execute("SELECT id, title FROM item").fetchall()

@audited("items.create")
def create_item(request):
    request.database.execute("INSERT INTO item(title) VALUES (?)", (request.body["title"],))
    request.database.commit()
    return 201

ROUTES = {("GET", "/items"): items, ("POST", "/items"): create_item}
