"""Front controller for an item search endpoint whose query is parameterized (safe)."""

import sqlite3

_CONN: "sqlite3.Connection | None" = None


def _conn() -> sqlite3.Connection:
    global _CONN
    if _CONN is None:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.execute("CREATE TABLE items (name TEXT)")
        conn.executemany("INSERT INTO items VALUES (?)", [("widget",), ("gadget",)])
        conn.commit()
        _CONN = conn
    return _CONN


def search(term: str) -> list:
    cur = _conn().cursor()
    # Flagged by a (false-positive) SAST hit, but the term is a BOUND parameter: it never
    # enters the SQL text, so it cannot be proven injectable.
    cur.execute("SELECT name FROM items WHERE name = ?", (term,))
    return cur.fetchall()


def handle(request: dict) -> list:
    if request.get("path") == "/search":
        return search(request.get("args", {}).get("q", ""))
    raise LookupError("no such route")
