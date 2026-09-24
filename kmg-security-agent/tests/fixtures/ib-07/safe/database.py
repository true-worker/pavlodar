import sqlite3
from audit import record

def connect(path):
    try:
        database = sqlite3.connect(path)
    except sqlite3.Error:
        record("database.connection", "error")
        raise
    record("database.connection", "success")
    return database

def create_schema(database):
    database.execute("CREATE TABLE IF NOT EXISTS item (id INTEGER PRIMARY KEY, title TEXT)")
    record("database.schema", "success")

def change_file_access(path, mode):
    import os
    os.chmod(path, mode)
    record("database.file_permissions", "success")
