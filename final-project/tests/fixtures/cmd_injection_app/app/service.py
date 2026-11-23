"""Front controller for an ops diagnostics endpoint.

Route:
  GET /admin/diagnostics ?host=<host>  (requires an admin token) -> runs a ping

The host is concatenated into a shell command string and run through ``os.system`` (CWE-78).
The route is gated behind an admin role, so a proof must supply a valid admin token and
drive the route - calling os.system directly does not count (the flagged line must be on the
call stack).
"""

import os

_ADMIN_TOKENS = frozenset({"ops-token-7f3a"})


def run_diagnostic(token: str, host: str) -> int:
    if token not in _ADMIN_TOKENS:  # role precondition
        raise PermissionError("admin role required")
    # VULNERABLE (CWE-78): host is concatenated into a shell command string.
    return os.system("ping -c 1 " + host)


def handle(request: dict) -> int:
    path = request.get("path", "/")
    args = request.get("args", {})
    if path == "/admin/diagnostics":
        return run_diagnostic(request.get("token", ""), args.get("host", "localhost"))
    raise LookupError("no such route: " + path)
