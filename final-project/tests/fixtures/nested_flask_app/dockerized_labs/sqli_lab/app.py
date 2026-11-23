"""A nested, self-contained Flask SQLi lab - the pygoat ``dockerized_labs/<lab>/app.py``
shape. Importing it needs the ``flask`` declared by THIS directory's requirements.txt, not
the Django at the repository root. The /account/search route interpolates the search term
into the SQL text (CWE-89) and is reachable only after login, so a proof must drive the app's
own test client with the nearest-manifest Flask provisioned.
"""

import sqlite3

from flask import Flask, abort, jsonify, request, session

app = Flask(__name__)
app.secret_key = "nested-lab-secret"

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
_DB.execute("INSERT INTO users (username, password) VALUES ('admin', 's3cret'), ('bob', 'pw')")
_DB.commit()


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    cur = _DB.cursor()
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
