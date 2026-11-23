"""Front controller for a static-asset download endpoint.

Route:
  GET /download ?file=<name>  (requires a session) -> the file's bytes

The requested name is joined onto the asset base directory with no containment check, so a
``../`` prefix escapes it (CWE-22). The route needs a session, so a proof must supply one and
drive the route; the open() fires (and the oracle records it) before any file-missing error.
"""

import os

_BASE = os.path.join(os.path.dirname(__file__), "public")


def read_asset(session: str, name: str) -> bytes:
    if not session:  # session precondition
        raise PermissionError("a session is required")
    path = os.path.join(_BASE, name)
    # VULNERABLE (CWE-22): no containment check, so name may traverse out of _BASE.
    with open(path, "rb") as handle:
        return handle.read()


def handle(request: dict) -> bytes:
    path = request.get("path", "/")
    args = request.get("args", {})
    if path == "/download":
        return read_asset(request.get("session", ""), args.get("file", ""))
    raise LookupError("no such route: " + path)
