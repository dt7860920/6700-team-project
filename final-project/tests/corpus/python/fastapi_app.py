"""Planted vulnerabilities in a FastAPI app: handler parameters *are* the attacker input."""

import sqlite3
import subprocess

import httpx
from fastapi import APIRouter, Body, FastAPI

app = FastAPI()
router = APIRouter()


@app.get("/items/{item_id}")
async def read_item(item_id: str):
    cur = sqlite3.connect("items.db").cursor()
    cur.execute(f"SELECT * FROM items WHERE id = {item_id}")  # VULN: CWE-89
    return cur.fetchone()


@app.post("/run")
def run(cmd: str = Body(...)):
    return subprocess.call(cmd, shell=True)  # VULN: CWE-78


@router.get("/fetch")
async def fetch(url: str):
    async with httpx.AsyncClient() as client:
        # ``client.get`` on a session object is not modelled (".get" is too generic): a gap
        return (await client.get(url)).text  # VULN: CWE-918 known-gap


@router.get("/fetch2")
def fetch_sync(url: str):
    return httpx.get(url).text  # VULN: CWE-918 regex-miss


@router.post("/exec")
def execute(code: str = Body(...)):
    exec(code)  # VULN: CWE-95
    return {"ok": True}
