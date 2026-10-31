"""Tiny intentionally-vulnerable Flask-style module used by the ingest/SAST tests."""

import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    return str(cur.fetchone())


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    return os.system("ping -c 1 " + host)


@app.route("/healthz")
def healthz():
    return "ok"
