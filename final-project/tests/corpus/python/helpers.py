"""Helpers whose sinks are only reachable through their callers (one-hop cases)."""

import os
import pickle

import requests

UPLOADS = "/srv/uploads"


def run_query(conn, username):
    cur = conn.cursor()
    return cur.execute("SELECT * FROM users WHERE username = '%s'" % username).fetchone()  # VULN: CWE-89


def fetch_remote(url):
    return requests.get(url, timeout=3).text  # VULN: CWE-918 regex-miss


def read_upload(name):
    with open(os.path.join(UPLOADS, name), "rb") as fh:  # VULN: CWE-22 regex-miss
        return fh.read()


def load_session(blob):
    # no caller in the corpus passes attacker data: reported at the "param" tier
    return pickle.loads(blob)  # VULN: CWE-502


def _run(sql):
    import sqlite3

    return sqlite3.connect("x.db").execute(sql)  # VULN: CWE-89 regex-miss


def find_by_name(name):
    # two hops from any request value: _run's parameter is reached via find_by_name's parameter
    return _run("SELECT * FROM t WHERE name = '%s'" % name)
