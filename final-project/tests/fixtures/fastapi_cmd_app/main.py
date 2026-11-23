"""A minimal REAL FastAPI diagnostics service - importing it needs ``fastapi``.

GET /admin/ping?host=<host>  with header  X-Token: ops-token-7f3a

The handler concatenates the attacker-controlled host into a shell command (CWE-78). It is
reachable only with the right token, so a proof must drive the app through its own
TestClient with the header set.
"""

import subprocess

from fastapi import FastAPI, Header, HTTPException

app = FastAPI()
_OPS_TOKEN = "ops-token-7f3a"


@app.get("/admin/ping")
def ping(host: str, x_token: str = Header(default="")):
    if x_token != _OPS_TOKEN:  # role precondition
        raise HTTPException(status_code=403, detail="ops token required")
    # VULNERABLE (CWE-78): the host is concatenated into a shell command string.
    result = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return {"rc": result.returncode}
