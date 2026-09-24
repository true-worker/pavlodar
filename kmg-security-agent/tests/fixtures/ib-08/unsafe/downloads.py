import json
from access import administrator

@administrator
def people_download(request):
    rows = request.directory.list_profiles(fields=("login", "first_name", "last_name", "email"))
    return 200, json.dumps({"people": rows})

ROUTES = {("GET", "/downloads/people.json"): people_download}
