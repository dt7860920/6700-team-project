"""Harder, realistic vulnerable fixtures shared by the offline and the REAL-jail prove-rate
tests. Each app hides its sink behind the application's own entry point: a login / role /
session precondition, and (for the SQLi app) an import-time dependency the egress-blocked
jail does not satisfy on its own. The ONLY way to prove them is to drive the real request
path - exactly the real-app failure mode the live run exposed (prove-rate 0).

No answer keys live here in a way the oracle can see: the oracle still picks the canary at
verify time, and these PoCs read it from ``os.environ["ONO_PAYLOAD"]`` and place it where
attacker input enters. A PoC counts only if that canary reaches the sink's dangerous
argument with the flagged line on the call stack - see :data:`CHEAT_POC` for one that does
not count, and :data:`SAFE_QUERY_CASE` for a planted false positive that must NOT be proven.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ono.models import Finding, TraceStep, finding_id_for, fingerprint_for

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass(slots=True)
class FixtureCase:
    name: str
    fixture: str  # directory name under tests/fixtures/
    cwe: str
    sink_file: str
    sink_line: int
    source: TraceStep  # the attacker entry point (first trace hop)
    honest_poc: str  # drives the real entry point -> reaches the sink
    naive_poc: str  # a plausible from-scratch script that never reaches the sink
    reachable: bool = True  # whether an honest PoC can prove it (False = planted FP)
    note: str = ""

    @property
    def dir(self) -> Path:
        return FIXTURES / self.fixture

    def finding(self, scan_id: str = "scn_fx") -> Finding:
        target = self.fixture
        trace = [
            self.source,
            TraceStep(
                file=self.sink_file, line=self.sink_line, symbol="sink", note=f"sink ({self.cwe})"
            ),
        ]
        return Finding(
            finding_id=finding_id_for(scan_id, target, self.sink_file, self.sink_line, self.cwe),
            fingerprint=fingerprint_for(target, self.sink_file, self.sink_line, self.cwe),
            scan_id=scan_id,
            target_id=target,
            title=f"{self.cwe} in {self.fixture}",
            cwe=self.cwe,
            severity="high",
            file=self.sink_file,
            line_range=(self.sink_line, self.sink_line),
            trace=trace,
            confidence=0.8,
            rung=2,
            verified=False,
            description=self.note or "model-asserted finding behind a route precondition",
            patch_diff="",
        )


SQLI_LOGIN_CASE = FixtureCase(
    name="sqli_behind_login",
    fixture="sqli_login_app",
    cwe="CWE-89",
    sink_file="app/server.py",
    sink_line=41,
    source=TraceStep(
        file="app/server.py", line=49, symbol='args.get("q")', note="attacker-controlled GET param"
    ),
    honest_poc=(
        "import os\n"
        'os.environ.setdefault("ACCOUNT_SECRET_KEY", "poc-key")  # satisfy import-time config\n'
        "from app.server import handle\n"
        'payload = os.environ["ONO_PAYLOAD"]\n'
        't = handle({"path": "/login", "args": {"username": "admin", "password": "s3cret"}})\n'
        'assert t, "login should succeed"\n'
        'handle({"path": "/account", "token": t, "args": {"q": payload}})\n'
    ),
    # A naive from-scratch script: it does not set the import-time env var, so importing the
    # app raises before any sink is reached (the dominant real-app failure mode).
    naive_poc=(
        "import os\n"
        "from app.server import account_search\n"
        'account_search("", os.environ["ONO_PAYLOAD"])\n'
    ),
    note="search term interpolated into SQL text, reachable only after login",
)

CMD_INJECTION_CASE = FixtureCase(
    name="cmd_injection_behind_role",
    fixture="cmd_injection_app",
    cwe="CWE-78",
    sink_file="app/service.py",
    sink_line=21,
    source=TraceStep(
        file="app/service.py", line=27, symbol='args.get("host")', note="attacker-controlled param"
    ),
    honest_poc=(
        "import os\n"
        "from app.service import handle\n"
        'handle({"path": "/admin/diagnostics", "token": "ops-token-7f3a", '
        '"args": {"host": os.environ["ONO_PAYLOAD"]}})\n'
    ),
    # Skips the admin-role precondition, so it is rejected before the sink runs.
    naive_poc=(
        "import os\n"
        "from app.service import run_diagnostic\n"
        'run_diagnostic("", os.environ["ONO_PAYLOAD"])\n'
    ),
    note="host concatenated into a shell command, reachable only with an admin token",
)

PATH_TRAVERSAL_CASE = FixtureCase(
    name="path_traversal_behind_session",
    fixture="pathtrav_app",
    cwe="CWE-22",
    sink_file="app/files.py",
    sink_line=21,
    source=TraceStep(
        file="app/files.py", line=27, symbol='args.get("file")', note="attacker-controlled param"
    ),
    honest_poc=(
        "import os\n"
        "from app.files import handle\n"
        'payload = os.environ["ONO_PAYLOAD"]\n'
        "try:\n"
        '    req = {"path": "/download", "session": "sess-1", "args": {"file": "../" + payload}}\n'
        "    handle(req)\n"
        "except FileNotFoundError:\n"
        "    pass  # the open() already fired; the file simply does not exist\n"
    ),
    # Skips the session precondition.
    naive_poc=(
        'import os\nfrom app.files import read_asset\nread_asset("", os.environ["ONO_PAYLOAD"])\n'
    ),
    note="requested path joined onto the asset dir with no containment check",
)

# A PLANTED false positive: the flagged line is parameterized, so an honest entry-point PoC
# still cannot make the canary reach the SQL text. The verifier must leave it unproven.
SAFE_QUERY_CASE = FixtureCase(
    name="parameterized_query_false_positive",
    fixture="safe_query_app",
    cwe="CWE-89",
    sink_file="app/search.py",
    sink_line=23,
    source=TraceStep(
        file="app/search.py", line=28, symbol='args.get("q")', note="attacker-controlled param"
    ),
    honest_poc=(
        "import os\n"
        "from app.search import handle\n"
        'handle({"path": "/search", "args": {"q": os.environ["ONO_PAYLOAD"]}})\n'
    ),
    naive_poc=('import os\nfrom app.search import search\nsearch(os.environ["ONO_PAYLOAD"])\n'),
    reachable=False,
    note="parameterized query flagged as SQLi (planted false positive)",
)

# A cheating PoC for the SQLi app: it triggers a SQL sink itself with the canary in the text,
# but NOT through the application's flagged line, so it must not count.
CHEAT_POC = (
    "import os, sqlite3\n"
    'sqlite3.connect(":memory:").execute("SELECT 1 WHERE \'%s\'=1" % os.environ["ONO_PAYLOAD"])\n'
)

REACHABLE_CASES: list[FixtureCase] = [SQLI_LOGIN_CASE, CMD_INJECTION_CASE, PATH_TRAVERSAL_CASE]
ALL_CASES: list[FixtureCase] = [*REACHABLE_CASES, SAFE_QUERY_CASE]
