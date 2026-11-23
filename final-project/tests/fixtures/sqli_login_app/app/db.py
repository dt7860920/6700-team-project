"""A tiny in-memory user store (stdlib sqlite3), shared across requests for the process."""

import sqlite3

_CONN: "sqlite3.Connection | None" = None


def get_connection() -> sqlite3.Connection:
    """Return the process-wide connection, seeding it on first use."""
    global _CONN
    if _CONN is None:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)"
        )
        conn.executemany(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            [
                ("admin", "s3cret", "admin@example.com"),
                ("bob", "hunter2", "bob@example.com"),
            ],
        )
        conn.commit()
        _CONN = conn
    return _CONN
