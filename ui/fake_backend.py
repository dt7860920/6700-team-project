"""In-process fake of the backend so the UI runs before the backend exists.

Enabled with MOCK_API=1. Each job moves one pipeline step per `step_seconds`.
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from client import PIPELINE_STEPS, BackendError

MOCK_FINDINGS: list[dict[str, Any]] = [
    {
        "id": "f1",
        "file": "app/db.py",
        "line": 14,
        "cwe": "CWE-89",
        "title": "SQL injection in user lookup",
        "explanation": (
            "The username from the request is pasted directly into the SQL "
            "string, so an attacker can change the query."
        ),
        "trigger": "GET /users?name=' OR '1'='1",
        "patch": (
            "--- a/app/db.py\n"
            "+++ b/app/db.py\n"
            "@@ -12,5 +12,5 @@\n"
            " def find_user(conn, name):\n"
            "     cur = conn.cursor()\n"
            "-    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
            '+    cur.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
            "     return cur.fetchone()\n"
        ),
    },
    {
        "id": "f2",
        "file": "app/config.py",
        "line": 3,
        "cwe": "CWE-489",
        "title": "Debug mode enabled",
        "explanation": (
            "The web framework runs in debug mode, which exposes an interactive "
            "console that can run arbitrary code."
        ),
        "trigger": "Trigger any unhandled exception and open the debugger page.",
        "patch": (
            "--- a/app/config.py\n"
            "+++ b/app/config.py\n"
            "@@ -1,4 +1,4 @@\n"
            " import os\n"
            " \n"
            "-DEBUG = True\n"
            '+DEBUG = os.environ.get("DEBUG") == "1"\n'
            ' SECRET_KEY = os.environ["SECRET_KEY"]\n'
        ),
    },
    {
        "id": "f3",
        "file": "app/cache.py",
        "line": 22,
        "cwe": "CWE-502",
        "title": "Unsafe deserialization of cached data",
        "explanation": (
            "pickle.loads runs code embedded in the data. If an attacker can "
            "write to the cache, they can run code on the server."
        ),
        "trigger": "Write a crafted pickle payload to the cache key 'session:1'.",
        "patch": None,
    },
]


@dataclass
class _MockJob:
    filename: str
    created: float = field(default_factory=time.monotonic)


class MockClient:
    def __init__(self, step_seconds: float = 1.0) -> None:
        self.step_seconds = step_seconds
        self.jobs: dict[str, _MockJob] = {}

    def health(self) -> bool:
        return True

    def submit(self, filename: str, data: bytes) -> str:
        job_id = uuid.uuid4().hex
        self.jobs[job_id] = _MockJob(filename)
        return job_id

    def _job(self, job_id: str) -> _MockJob:
        if job_id not in self.jobs:
            raise BackendError("Backend error 404: job not found")
        return self.jobs[job_id]

    def status(self, job_id: str) -> dict[str, Any]:
        elapsed = time.monotonic() - self._job(job_id).created
        last = len(PIPELINE_STEPS) - 1
        if self.step_seconds <= 0:
            return {"job_id": job_id, "status": PIPELINE_STEPS[last], "detail": None}
        step = min(int(elapsed / self.step_seconds), last)
        return {"job_id": job_id, "status": PIPELINE_STEPS[step], "detail": None}

    def results(self, job_id: str) -> dict[str, Any]:
        if self.status(job_id)["status"] != "done":
            raise BackendError("Backend error 409: job is not finished")
        return {
            "job_id": job_id,
            "backend": "mock",
            "files_scanned": 12,
            "findings": MOCK_FINDINGS,
        }

    def delete(self, job_id: str) -> None:
        self._job(job_id)
        del self.jobs[job_id]
