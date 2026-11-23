"""A REAL Flask app whose routes host the added dynamically-provable CWE families. Importing
it needs the provisioned ``flask`` (and ``lxml`` for the XPath route). Every vulnerable route
sits behind a precondition (a logged-in session or an ops token), so a proof MUST drive the
app's own test client through the real request path - a precondition-skipping PoC is stopped
by the route's own 401/403 before the sink runs.

Each family also has a SAFE sibling route (the real defense) that must NOT be proven.
"""

import os
import xml.etree.ElementTree as ET

from flask import Flask, Response, abort, redirect, request, session
from jinja2 import Environment

app = Flask(__name__)
app.secret_key = "family-fixture-secret"
_OPS_TOKEN = "ops-token-7f3a"
_BASE = "/tmp/ono-family-assets"
_USERS = ET.fromstring("<users><u name='admin'/><u name='bob'/></users>")
_JINJA = Environment()


def _require_login():
    if "user" not in session:
        abort(401)


def _require_token():
    if request.headers.get("x-token") != _OPS_TOKEN:
        abort(403)


@app.post("/login")
def login():
    if request.form.get("password") != "s3cret":
        abort(401)
    session["user"] = request.form.get("username", "")
    return {"ok": True}


@app.get("/render")
def render():  # SSTI (CWE-1336), reachable only after login
    _require_login()
    tpl = request.args.get("tpl", "")
    return _JINJA.from_string("Report: " + tpl).render(user="admin")


@app.get("/render_safe")
def render_safe():  # SAFE: the value is template CONTEXT, not template body
    _require_login()
    name = request.args.get("name", "")
    return _JINJA.from_string("Report: {{ name }}").render(name=name)


@app.get("/go")
def go():  # open redirect (CWE-601), reachable only with the ops token
    _require_token()
    nxt = request.args.get("next", "")
    return redirect(nxt)


@app.get("/show")
def show():  # reflected unescaped output (CWE-79), reachable only after login
    _require_login()
    comment = request.args.get("comment", "")
    return Response("<div class='c'>" + comment + "</div>", mimetype="text/html")


@app.get("/fetch")
def fetch():  # external control of file path (CWE-73), reachable only with the ops token
    _require_token()
    name = request.args.get("path", "")
    with open(os.path.join(_BASE, name)) as handle:
        return Response(handle.read(), mimetype="text/plain")


@app.get("/xpath")
def xpath():  # XPath injection (CWE-643), reachable only after login
    _require_login()
    name = request.args.get("name", "")
    return {"hits": len(_USERS.findall(".//u[@name='" + name + "']"))}
