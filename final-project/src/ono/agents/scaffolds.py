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
pre-written exploit payload: it tells the prover to read the ``ONO_PAYLOAD`` environment
variable (``os.environ["ONO_PAYLOAD"]`` in Python, ``process.env.ONO_PAYLOAD`` in JS/TS) and
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
    (
        "nestjs",
        ("@nestjs/common", "@controller(", "@injectable(", "@get(", "@post(", "nestfactory"),
    ),
    (
        "next",
        (
            "next/server",
            "nextresponse",
            "getserversideprops",
            "export default function handler",
            "pages/api",
            "app/api/",
        ),
    ),
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

_IMPORT_STUB_RECIPE_JS = """\
Handle import-time (require-time) dependencies FIRST. Requiring the app often runs
module-level code that needs an env var, a secret or a service the jail does not have,
throwing before the sink is reached. Satisfy it rather than giving up:
  - a required env var:  process.env.THE_VAR = process.env.THE_VAR || "x";  BEFORE the
    require() of the app module
  - a module-level client (DB, etc.): overwrite the exported constructor/function on the
    cached module object before requiring the app, e.g.
      const db = require('some-db-client'); db.connect = () => ({ query: () => {} });
    or: require.cache[require.resolve('some-db-client')] = { exports: { ... } };
  - wrap the drive in try/catch: the oracle records AT the sink call, so an error that
    happens AFTER the sink (a bad-SQL error, a missing file) does not matter."""

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

_GENERIC_SCAFFOLD_JS = """\
Generic Express/Node drive with NO extra packages (works even when the target declares no
test-only dependencies like supertest): start the app's own exported `app` on an EPHEMERAL
loopback port and issue a real request to it with Node's built-in `http` module - this is
exactly what `supertest` does internally, so it works whether or not supertest is installed.
The jail blocks all egress EXCEPT loopback, so this always works:
  const http = require('http');
  process.env.THE_VAR = process.env.THE_VAR || "x";   // satisfy import-time config first
  const app = require('<module>');                     // the exported Express app/router
  const payload = process.env.ONO_PAYLOAD;
  const srv = app.listen(0, '127.0.0.1', () => {
    const port = srv.address().port;
    // 1) satisfy any precondition the route checks (a header, a cookie, a prior request)
    // 2) drive the vulnerable route, putting the payload where attacker input enters
    http.get({ hostname: '127.0.0.1', port, path: '/search?q=' + encodeURIComponent(payload),
               headers: { /* e.g. 'x-api-key': '...' */ } },
      (res) => { res.on('data', () => {}); res.on('end', () => srv.close()); }
    ).on('error', () => srv.close());
  });
If `supertest` IS declared by the target (check package.json), `require('supertest')(app).get(...)`
is a shorter equivalent - use whichever is available."""

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
Express (JS/TS) - require the exported app and drive it on an ephemeral loopback port (or,
if the target declares supertest, `require("supertest")(app).get(...)`):
  const request = require("supertest");   // only if package.json declares it
  const app = require("./server");        // the module exporting the Express app
  await request(app).get("/run").query({ host: process.env.ONO_PAYLOAD });
See the generic Node drive below for the no-supertest form (always works).""",
    "nestjs": """\
NestJS - bootstrap the app with NestFactory and drive it the same way as Express (Nest sits
on top of Express/Fastify under the hood):
  const { NestFactory } = require('@nestjs/core');
  const { AppModule } = require('./app.module');     // or wherever the root module lives
  (async () => {
    const app = await NestFactory.create(AppModule);
    await app.init();
    const server = app.getHttpServer();
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const http = require('http');
      http.get({ hostname: '127.0.0.1', port, path: '/<route>?q=' +
        encodeURIComponent(process.env.ONO_PAYLOAD) }, (res) => { res.on('end', () => {}); });
    });
  })();""",
    "next": """\
Next.js API route - the handler is usually a plain `(req, res) => {...}` (pages/api) or a
Request/Response-based function (app/api/.../route.js); import and call it directly with a
minimal mock request/response rather than running the whole `next` server:
  const handler = require('./pages/api/<route>').default;
  const payload = process.env.ONO_PAYLOAD;
  let body = '';
  const req = { method: 'GET', query: { q: payload }, headers: {} };
  const res = { status() { return this; }, json(v) { body = JSON.stringify(v); },
                send(v) { body = String(v); }, setHeader() {} };
  await handler(req, res);""",
}


# Per-CWE guidance on WHERE the payload must land for the oracle to observe it. This is
# technique, never an answer key: it still tells the prover to read os.environ["ONO_PAYLOAD"]
# and drive the real request path, and the oracle still picks the canary and requires the
# flagged line on the stack. A hint only names the shape of the dangerous argument so the
# prover aims the payload at it (e.g. an off-site URL for open redirect, markup for XSS).
_CWE_HINTS: dict[str, str] = {
    "CWE-1336": "SSTI: the payload must land in the TEMPLATE BODY that is rendered (e.g. the "
    "string passed to render_template_string / Environment.from_string), not merely in the "
    "render context.",
    "CWE-917": "SSTI: put the payload in the template STRING that is compiled/rendered.",
    "CWE-643": "XPath injection: the payload must be concatenated into the XPath EXPRESSION text "
    "(.xpath(...) / findall(...)), not bound as a variable.",
    "CWE-90": "LDAP injection: the payload must reach the search FILTER string unescaped - the "
    "oracle's payload carries metacharacters that a proper escaper would remove.",
    "CWE-943": "NoSQL injection: the payload must reach a query OPERATOR position (a $where JS "
    "string, or a $-prefixed operator key), not a plain parameterised field value.",
    "CWE-611": "XXE: send XML whose DOCTYPE declares an entity built from the payload to the "
    "parser (e.g. lxml.etree.fromstring / minidom.parseString) - a DTD-forbidding parser is safe.",
    "CWE-601": "Open redirect: drive the route with an OFF-SITE absolute URL that contains the "
    'payload (e.g. next="//attacker.example/<payload>"); a fixed internal path is not a redirect.',
    "CWE-73": "File-path control: the payload must make the opened path escape its intended "
    'directory (a "../" traversal or an attacker-controlled directory component).',
    "CWE-79": "Reflected output: the payload (which carries HTML markup) must appear UNESCAPED in "
    "the response body built at the flagged line (Response(...) / make_response(...)).",
}


def _cwe_hint(cwe: str) -> str:
    return _CWE_HINTS.get(cwe, "")


def scaffold_for(finding: Finding, window_text: str) -> str:
    """The scaffold block injected into the prover's task prompt for this finding."""
    is_js = not finding.file.endswith(".py")
    framework = detect_framework(finding, window_text)
    parts: list[str] = [
        "HOW TO REACH THE SINK (drive the application, do not call the sink yourself):",
        "- Import and drive the TARGET's OWN app object. Do NOT define a new application "
        "(no fresh Flask(__name__) / express() / new route of your own): a re-implemented app "
        "does not contain the flagged line, so the oracle never sees it and the finding cannot "
        "be proven. You must exercise the real code at the sink.",
        f"- Attacker entry point (drive THIS): {entry_hint(finding)}",
        f"- Flagged sink to reach: {finding.location} ({finding.cwe})",
        "- Language: JavaScript/TypeScript - read the payload with process.env.ONO_PAYLOAD "
        "and write the script for `node` (CommonJS require(), not ESM import)."
        if is_js
        else '- Language: Python - read the payload with os.environ["ONO_PAYLOAD"].',
        "",
        _IMPORT_STUB_RECIPE_JS if is_js else _IMPORT_STUB_RECIPE,
        "",
    ]
    hint = _cwe_hint(finding.cwe)
    if hint:
        parts.append(hint)
        parts.append("")
    if framework and framework in _FRAMEWORK_SCAFFOLDS:
        parts.append(f"Detected framework: {framework}.")
        parts.append(_FRAMEWORK_SCAFFOLDS[framework])
        parts.append("")
    parts.append(_GENERIC_SCAFFOLD_JS if is_js else _GENERIC_SCAFFOLD)
    return "\n".join(parts)
