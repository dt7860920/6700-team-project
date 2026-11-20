"""A clean Flask app: every flag on this file is a false positive."""

import ast
import json
import os
import shlex
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
ALLOWED = {"docs": "https://docs.example.com", "api": "https://api.example.com"}
QUERY = "SELECT * FROM users WHERE id = ?"
UPLOAD_DIR = "/srv/uploads"


@app.route("/user")
def user():
    uid = int(request.args.get("id", "0"))
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(QUERY, (uid,))
    return str(cur.fetchone())


@app.route("/user-fstring")
def user_fstring():
    # the value is coerced to int before it is formatted: not injectable
    uid = int(request.args.get("id", "0"))
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    return str(cur.fetchone())


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False)
    return out.stdout


@app.route("/ping-quoted")
def ping_quoted():
    host = shlex.quote(request.args.get("host", "localhost"))
    return os.popen("ping -c 1 " + host).read()


@app.route("/config", methods=["POST"])
def config():
    cfg = yaml.safe_load(request.data)
    other = yaml.load(request.data, Loader=yaml.SafeLoader)
    return json.dumps([cfg, other])


@app.route("/literal")
def literal():
    value = ast.literal_eval(request.args.get("v", "0"))
    return str(value)


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    name = secure_filename(f.filename)
    with open(os.path.join(UPLOAD_DIR, name), "wb") as fh:
        fh.write(f.read())
    return "ok"


@app.route("/site")
def site():
    url = ALLOWED[request.args["site"]]
    return requests.get(url, timeout=5).text


@app.route("/hello")
def hello():
    return render_template("hello.html", name=request.args.get("name", ""))


def housekeeping():
    cmd = "ls -la /tmp"
    subprocess.run(cmd, shell=True, check=False)
    os.system("df -h")
    return subprocess.run(["ls", "-la"], check=False)
