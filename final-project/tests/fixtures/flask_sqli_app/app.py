"""A minimal REAL Flask account service - importing it needs the third-party ``flask``.

Routes:
  POST /login            form {username, password}       -> session cookie (or 401)
  GET  /account/search   ?q=<term>  (login required)     -> users whose name matches
  GET  /items            ?name=<name>                    -> parameterized lookup (SAFE)

The /account/search handler interpolates the attacker-controlled term into the SQL text
(CWE-89) and is reachable only with a logged-in session, so a proof MUST drive the app's
own test client: log in, then hit the route. Without ``flask`` in the jail the import
itself fails and nothing can be proven - the real-app wall this fixture exists to measure.
"""

import sqlite3

from flask import Flask, abort, jsonify, request, session

app = Flask(__name__)
app.secret_key = "fixture-secret-key"

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
_DB.execute("INSERT INTO users (username, password) VALUES ('admin', 's3cret'), ('bob', 'pw')")
_DB.execute("CREATE TABLE items (name TEXT)")
_DB.execute("INSERT INTO items VALUES ('widget'), ('gadget')")
_DB.commit()


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    cur = _DB.cursor()
    # Parameterized on purpose: the login path is NOT the vulnerability.
    cur.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, password))
    if cur.fetchone() is None:
        abort(401)
    session["user"] = username
    return jsonify({"ok": True})


@app.get("/account/search")
def account_search():
    if "user" not in session:  # login precondition
        abort(401)
    term = request.args.get("q", "")
    cur = _DB.cursor()
    # VULNERABLE (CWE-89): the search term is concatenated into the SQL text.
    cur.execute("SELECT id, username FROM users WHERE username LIKE '%" + term + "%'")
    return jsonify(cur.fetchall())


@app.get("/items")
def items():
    name = request.args.get("name", "")
    cur = _DB.cursor()
    # Flagged by a (false-positive) SAST hit, but the name is a BOUND parameter.
    cur.execute("SELECT name FROM items WHERE name = ?", (name,))
    return jsonify(cur.fetchall())
