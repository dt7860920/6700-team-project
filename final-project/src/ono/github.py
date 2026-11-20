"""Our own session token for a GitHub-authenticated user (used by ``ono.auth``).

``sign_session`` produces ``<base64url(payload)>.<base64url(hmac-sha256)>`` with the GitHub
``login`` and a 12-hour ``exp``; ``verify_session`` checks the signature in constant time
and the expiry, and returns the login or ``None``. No GitHub token is ever inside.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign_session(login: str, secret: str, *, now: int | None = None) -> str:
    payload = json.dumps(
        {"login": login, "exp": (now or int(time.time())) + 12 * 60 * 60},
        separators=(",", ":"),
    ).encode()
    encoded = _b64encode(payload)
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
    return f"{encoded}.{_b64encode(signature)}"


def verify_session(token: str | None, secret: str, *, now: int | None = None) -> str | None:
    if not token:
        return None
    try:
        encoded, supplied_signature = token.split(".", 1)
        expected = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64decode(supplied_signature)):
            return None
        payload = json.loads(_b64decode(encoded))
        if not isinstance(payload, dict) or payload.get("exp", 0) <= (now or int(time.time())):
            return None
        login = payload.get("login")
        if not isinstance(login, str) or not login or len(login) > 39:
            return None
        return login
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
