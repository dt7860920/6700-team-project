import sqlite3


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
    return conn


def find_user(uid: str) -> "str | None":  # quoted: must import under Python 3.9 too
    conn = connect()
    cur = conn.cursor()
    cur.execute(f"SELECT name FROM users WHERE id = {uid}")
    row = cur.fetchone()
    return str(row[0]) if row else None
