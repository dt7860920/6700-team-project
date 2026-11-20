"""Planted vulnerabilities in a Flask app. ``# VULN: CWE-x`` marks every intended sink line.

Tags: ``regex-miss`` = the pre-existing regex fallback is known to miss this one;
``known-gap`` = the threat map is expected to miss it too (documented limitation).
"""

import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request, send_file

from helpers import fetch_remote, read_upload, run_query

app = Flask(__name__)
BASE = "/srv/files"
STATE: dict[str, str] = {}


@app.route("/user")
def user():
    uid = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")  # VULN: CWE-89
    return str(cur.fetchone())


@app.route("/user2")
def user_via_variable():
    uid = request.args.get("id", "")
    query = "SELECT * FROM users WHERE id = " + uid
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(query)  # VULN: CWE-89 regex-miss
    return str(cur.fetchone())


@app.route("/user3")
def user_percent_variable():
    name = request.form["name"]
    sql = "SELECT * FROM users WHERE name = '%s'"
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(sql % name)  # VULN: CWE-89 regex-miss
    return "ok"


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    return os.popen("ping -c 1 " + host).read()  # VULN: CWE-78


@app.route("/archive", methods=["POST"])
def archive():
    name = request.form["name"]
    cmd = "tar czf /tmp/out.tgz " + name
    proc = subprocess.Popen(  # VULN: CWE-78 regex-miss
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
    )
    return proc.communicate()[0]


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "0")))  # VULN: CWE-95


@app.route("/session", methods=["POST"])
def session():
    data = pickle.loads(request.data)  # VULN: CWE-502
    return str(data)


@app.route("/config", methods=["POST"])
def config():
    cfg = yaml.load(request.data, Loader=yaml.Loader)  # VULN: CWE-502
    return str(cfg)


@app.route("/download")
def download():
    name = request.args["f"]
    with open(os.path.join(BASE, name)) as fh:  # VULN: CWE-22 regex-miss
        return fh.read()


@app.route("/attachment")
def attachment():
    return send_file(request.args["path"])  # VULN: CWE-22 regex-miss


@app.route("/proxy")
def proxy():
    target = request.args["url"]
    return requests.get(target, timeout=5).text  # VULN: CWE-918 regex-miss


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return render_template_string("<h1>Hello " + name + "</h1>")  # VULN: CWE-79 regex-miss


@app.route("/lookup")
def lookup():
    # one hop: the sink is in helpers.run_query, fed by this request value
    conn = sqlite3.connect("app.db")
    return str(run_query(conn, request.form["u"]))


@app.route("/fetch")
def fetch():
    return fetch_remote(request.args["u"])


@app.route("/upload/<name>")
def upload(name):
    return read_upload(name)


def _name_from_request():
    return request.args["n"]


@app.route("/byname")
def by_name():
    cur = sqlite3.connect("app.db").cursor()
    # the taint flows through a return value, which the one-hop engine does not model;
    # the regex fallback still catches the string concatenation on this line
    cur.execute("SELECT * FROM users WHERE name = '" + _name_from_request() + "'")  # VULN: CWE-89
    return "ok"


@app.route("/set-cmd")
def set_cmd():
    STATE["cmd"] = request.args["cmd"]
    return "stored"


def run_stored():
    # two-step flow through module state: documented gap of the one-hop engine
    return os.system(STATE["cmd"])  # VULN: CWE-78 known-gap
