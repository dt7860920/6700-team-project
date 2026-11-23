"""Framework-aware PoC scaffolding handed to the PROVER.

The prover's job is to drive the application's OWN entry point so an attacker-controlled
value reaches the flagged sink (see :mod:`ono.verifier`). On a real framework app the sink
sits inside a route handler, and a from-scratch script that tries to re-reach it usually
dies at import time: importing the app runs module-level code that needs a database, an
environment variable or a network service the egress-blocked jail does not have, so the
script never gets near the sink and the oracle reports "no instrumented sink saw the
payload". That was the dominant failure mode of the live run (prove-rate 0).

This module turns the finding's data-flow trace (which the detector already produced) into
concrete, framework-specific guidance: *which* entry point to drive, *how* to drive it with
the framework's own test client, and *how* to get past import-time dependencies and route
preconditions (login / session / role) so execution actually reaches the sink.

Crucially this is NOT an answer key. It never contains the oracle's canary and never a
pre-written exploit payload: it tells the prover to read ``os.environ["ONO_PAYLOAD"]`` and
place it where attacker input enters, and to drive the real request path. The oracle still
picks the canary at verify time and still requires the flagged line to be on the call stack
with the canary in the sink's dangerous argument, so a cheating PoC is rejected exactly as
before.
"""

from __future__ import annotations

from ono.models import Finding, TraceStep

__all__ = ["detect_framework", "entry_hint", "scaffold_for"]

# Substrings that identify a Python web framework from the code the analyst read. Order
# matters only for the label we show; the generic front-controller recipe is always added.
_PY_FRAMEWORK_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("flask", ("flask", "@app.route", "Blueprint(", "flask.Flask", "current_app", "request.form")),
    ("django", ("django", "HttpResponse", "request.GET", "request.POST", "urls.py", "views.py")),
    ("fastapi", ("fastapi", "APIRouter", "@app.get", "@app.post", "@router.")),
    ("starlette", ("starlette", "Starlette(", "JSONResponse", "PlainTextResponse")),
    ("aiohttp", ("aiohttp", "web.Application", "web.RouteTableDef")),
)
_JS_FRAMEWORK_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("express", ("express(", "require('express')", 'require("express")', "app.get(", "app.post(")),
)


def detect_framework(finding: Finding, window_text: str) -> str:
    """Best-effort framework label from the sink window + trace, or ``""`` if unknown."""
    hay = (window_text + "\n" + "\n".join(t.symbol for t in finding.trace)).lower()
    markers = _JS_FRAMEWORK_MARKERS if not finding.file.endswith(".py") else _PY_FRAMEWORK_MARKERS
    for name, needles in markers:
        if any(needle.lower() in hay for needle in needles):
            return name
    return ""


def entry_hint(finding: Finding) -> str:
    """The most likely attacker entry point, read off the data-flow trace.

    The first hop of a source->sink trace is where attacker input enters (the detector's
    own evidence); the last is the sink. We surface the first as the entry point so the
    prover drives *that*, not the sink directly.
    """
    if not finding.trace:
        return f"the function containing {finding.location} (no data-flow trace was recorded)"
    source: TraceStep = finding.trace[0]
    where = f"{source.file}:{source.line}"
    note = f" ({source.note})" if source.note else ""
    return f"{source.symbol} at {where}{note}"


# ---------------------------------------------------------------------------
# Scaffolds (reference recipes, not payloads)
# ---------------------------------------------------------------------------

_IMPORT_STUB_RECIPE = """\
Handle import-time dependencies FIRST. Importing the app often runs module-level code that
needs a database, a secret or a service the jail does not have, raising before the sink is
reached. Satisfy it rather than giving up:
  - a required env var:  os.environ.setdefault("THE_VAR", "x")  BEFORE the import
  - a module-level DB/client call: stub it with unittest.mock, e.g.
      import unittest.mock as m
      m.patch("pkg.module.create_engine", return_value=m.MagicMock()).start()
    (patch the name as the module imports it; start() it before you import the app)
  - wrap the whole drive in try/except: the oracle records AT the sink call, so an error
    that happens AFTER the sink (a bad-SQL error, a missing file) does not matter."""

_GENERIC_SCAFFOLD = """\
Generic front-controller / handler drive (works without a framework test client):
  import os
  os.environ.setdefault(...)        # satisfy import-time config, see above
  from <app module> import <front controller or handler>
  payload = os.environ["ONO_PAYLOAD"]
  # 1) satisfy any precondition the route checks (log in, open a session, set a role)
  token = handle({"path": "/login", "args": {"username": "...", "password": "..."}})
  # 2) drive the vulnerable route, putting the payload where attacker input enters
  handle({"path": "<vulnerable route>", "token": token, "args": {"<field>": payload}})"""

_FRAMEWORK_SCAFFOLDS: dict[str, str] = {
    "flask": """\
Flask - use the app's OWN test client so the real route runs:
  import os
  os.environ.setdefault(...)                  # satisfy import-time config first
  from <module> import app                    # the Flask() object (grep for 'Flask(')
  client = app.test_client()
  payload = os.environ["ONO_PAYLOAD"]
  client.post("/login", data={"username": "...", "password": "..."})  # precondition
  client.get("/search", query_string={"q": payload})  # payload enters via the request""",
    "django": """\
Django - configure settings, then drive django.test.Client:
  import os, django
  os.environ.setdefault("DJANGO_SETTINGS_MODULE", "<project>.settings")
  django.setup()
  from django.test import Client
  payload = os.environ["ONO_PAYLOAD"]
  c = Client()
  c.post("/login/", {"username": "...", "password": "..."})  # precondition
  c.get("/search/", {"q": payload})""",
    "fastapi": """\
FastAPI / Starlette - use starlette.testclient.TestClient (no server, no network):
  import os
  os.environ.setdefault(...)
  from fastapi.testclient import TestClient    # or: from starlette.testclient import TestClient
  from <module> import app
  payload = os.environ["ONO_PAYLOAD"]
  client = TestClient(app)
  client.post("/login", json={...})            # precondition
  client.get("/search", params={"q": payload})""",
    "starlette": """\
Starlette - starlette.testclient.TestClient(app) and GET/POST the vulnerable route with
the payload in the query/body/header where attacker input enters.""",
    "express": """\
Express (JS/TS) - driven with supertest against the exported app, e.g.
  const request = require("supertest");
  const app = require("./server");
  await request(app).get("/run").query({ host: process.env.ONO_PAYLOAD });
NOTE: the dynamic sink oracle is Python-only for now, so a JS finding is reported honestly
as 'skipped', not proven. This scaffold is for completeness / future work.""",
}


def scaffold_for(finding: Finding, window_text: str) -> str:
    """The scaffold block injected into the prover's task prompt for this finding."""
    framework = detect_framework(finding, window_text)
    parts: list[str] = [
        "HOW TO REACH THE SINK (drive the application, do not call the sink yourself):",
        f"- Attacker entry point (drive THIS): {entry_hint(finding)}",
        f"- Flagged sink to reach: {finding.location} ({finding.cwe})",
        "",
        _IMPORT_STUB_RECIPE,
        "",
    ]
    if framework and framework in _FRAMEWORK_SCAFFOLDS:
        parts.append(f"Detected framework: {framework}.")
        parts.append(_FRAMEWORK_SCAFFOLDS[framework])
        parts.append("")
    parts.append(_GENERIC_SCAFFOLD)
    return "\n".join(parts)
