"""Framework-free request handlers: a request is a dict ``{"args": {...}}``."""

from app.db import find_user
from app.shell import announce


def user_view(request: dict) -> str:
    uid = request["args"].get("id", "")
    return str(find_user(uid))


def ping_view(request: dict) -> str:
    host = request["args"].get("host", "localhost")
    return str(announce(host))
