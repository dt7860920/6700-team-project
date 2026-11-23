"""Front controller for the account service.

Routes:
  POST /login     {username, password}        -> a session token (or None)
  GET  /account   ?q=<term>  (requires token) -> user rows matching the term

The /account search interpolates the attacker-controlled term straight into the SQL text
(CWE-89). It is only reachable with a valid token issued by /login, so a proof MUST log in
first and then drive /account - the sink cannot be reached otherwise.
"""

import hashlib

from app import config  # import-time: requires ACCOUNT_SECRET_KEY
from app.db import get_connection

_SESSIONS: dict[str, str] = {}


def _issue_token(username: str) -> str:
    token = hashlib.sha256((config.SECRET_KEY + username).encode()).hexdigest()[:16]
    _SESSIONS[token] = username
    return token


def login(username: str, password: str) -> "str | None":
    cur = get_connection().cursor()
    # Parameterized on purpose: the login path is NOT the vulnerability.
    cur.execute(
        "SELECT username FROM users WHERE username = ? AND password = ?", (username, password)
    )
    row = cur.fetchone()
    return _issue_token(username) if row is not None else None


def account_search(token: str, term: str) -> list:
    if token not in _SESSIONS:  # login precondition
        raise PermissionError("authentication required")
    cur = get_connection().cursor()
    # VULNERABLE (CWE-89): the search term is concatenated into the SQL text.
    cur.execute("SELECT id, username, email FROM users WHERE username LIKE '%" + term + "%'")
    return cur.fetchall()


def handle(request: dict):
    """Dispatch a parsed request dict ({path, args, token}) to a route."""
    path = request.get("path", "/")
    args = request.get("args", {})
    if path == "/login":
        return login(args.get("username", ""), args.get("password", ""))
    if path == "/account":
        return account_search(request.get("token", ""), args.get("q", ""))
    raise LookupError("no such route: " + path)
