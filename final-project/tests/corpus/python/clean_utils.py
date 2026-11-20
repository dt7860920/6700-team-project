"""Clean utility code: dangerous-looking APIs on constant or local data only."""

import pickle
import sqlite3

import yaml

CACHE_FILE = "/var/cache/app/model.pkl"
SETTINGS_FILE = "/etc/app/settings.yml"
REPORT_SQL = "SELECT count(*) FROM events WHERE day = ?"


def load_model():
    with open(CACHE_FILE, "rb") as fh:
        return pickle.loads(fh.read())


def load_settings():
    with open(SETTINGS_FILE) as fh:
        return yaml.load(fh.read(), Loader=yaml.SafeLoader)


def count_events(day):
    cur = sqlite3.connect("events.db").cursor()
    cur.execute(REPORT_SQL, (day,))
    return cur.fetchone()[0]


def answer():
    return eval("2 + 2")


class Model:
    def eval(self):
        return "evaluating"


def evaluate(model: Model):
    return model.eval()
