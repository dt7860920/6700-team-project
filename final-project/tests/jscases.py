"""JS/TS fixture cases for the Node sink oracle - the JS sibling of ``fixturecases.py``.

:data:`EXPRESS_CMDI_CASE` / :data:`EXPRESS_EVAL_CASE` sit behind the SAME precondition
real-app failure mode as the Python framework fixtures (an import-time secret the module
refuses to start without, plus a header-based auth check): a from-scratch PoC that never
``require()``s ``server.js``, or that calls ``child_process``/``eval`` itself, must not
prove anything - only driving the real Express route does. :data:`EXPRESS_SAFE_CASE` is the
planted false positive (the argv form of ``spawnSync`` - never a shell, never tainted) and
:data:`JS_CHEAT_POC` is the deliberate self-contained "cheat" a PoC must not get away with.

No answer keys: these PoCs read the canary from ``process.env.ONO_PAYLOAD`` (handed out at
verify time) and place it where attacker input enters; they never know what the oracle will
check for beyond that.
"""

from __future__ import annotations

from fixturecases import FixtureCase
from ono.models import TraceStep

FIXTURE = "express_cmdi_app"

_IMPORT_SECRET = 'process.env.APP_SECRET = process.env.APP_SECRET || "fixture-secret";'

_DRIVE_ROUTE = """\
const http = require('http');
{set_secret}
const app = require('./server.js');
const payload = process.env.ONO_PAYLOAD;
const srv = app.listen(0, '127.0.0.1', () => {{
  const port = srv.address().port;
  const path = '{route}?host=' + encodeURIComponent(payload);
  const req = http.get(
    {{ hostname: '127.0.0.1', port, path, headers: {{ 'x-api-key': process.env.APP_SECRET }} }},
    (res) => {{
      res.on('data', () => {{}});
      res.on('end', () => {{ srv.close(); }});
    }}
  );
  req.on('error', () => {{ srv.close(); }});
}});
"""

EXPRESS_CMDI_CASE = FixtureCase(
    name="express_cmdi_behind_api_key",
    fixture=FIXTURE,
    cwe="CWE-78",
    sink_file="server.js",
    sink_line=33,
    source=TraceStep(
        file="server.js", line=32, symbol="req.query.host", note="attacker-controlled GET param"
    ),
    honest_poc=_DRIVE_ROUTE.format(set_secret=_IMPORT_SECRET, route="/diagnose"),
    # The dominant real-app failure: a plausible-but-naive PoC that requires the module
    # without first satisfying its import-time secret - it never even reaches the sink.
    naive_poc=("const app = require('./server.js');\nconst payload = process.env.ONO_PAYLOAD;\n"),
    note="command injection behind an import-time secret and an API-key route guard",
    needs_deps=True,
    expected_packages=("express",),
)

EXPRESS_SAFE_CASE = FixtureCase(
    name="express_argv_form_false_positive",
    fixture=FIXTURE,
    cwe="CWE-78",
    sink_file="server.js",
    sink_line=42,
    source=TraceStep(
        file="server.js", line=41, symbol="req.query.host", note="attacker-controlled GET param"
    ),
    honest_poc=_DRIVE_ROUTE.format(set_secret=_IMPORT_SECRET, route="/diagnose-safe"),
    naive_poc="const app = require('./server.js');\n",
    reachable=False,
    note="spawnSync with an argv array (no shell) - never a command-injection sink",
    needs_deps=True,
    expected_packages=("express",),
)

EXPRESS_EVAL_CASE = FixtureCase(
    name="express_eval_behind_api_key",
    fixture=FIXTURE,
    cwe="CWE-94",
    sink_file="server.js",
    sink_line=49,
    source=TraceStep(
        file="server.js", line=48, symbol="req.query.expr", note="attacker-controlled GET param"
    ),
    honest_poc=(
        "const http = require('http');\n"
        f"{_IMPORT_SECRET}\n"
        "const app = require('./server.js');\n"
        "const payload = process.env.ONO_PAYLOAD;\n"
        "const srv = app.listen(0, '127.0.0.1', () => {\n"
        "  const port = srv.address().port;\n"
        "  const path = '/calc?expr=' + encodeURIComponent(payload);\n"
        "  const req = http.get(\n"
        "    { hostname: '127.0.0.1', port, path, "
        "headers: { 'x-api-key': process.env.APP_SECRET } },\n"
        "    (res) => { res.on('data', () => {}); res.on('end', () => { srv.close(); }); }\n"
        "  );\n"
        "  req.on('error', () => { srv.close(); });\n"
        "});\n"
    ),
    naive_poc="const app = require('./server.js');\n",
    note="code injection (eval) behind an import-time secret and an API-key route guard",
    needs_deps=True,
    expected_packages=("express",),
)

JS_REACHABLE_CASES: list[FixtureCase] = [EXPRESS_CMDI_CASE, EXPRESS_EVAL_CASE]
JS_ALL_CASES: list[FixtureCase] = [*JS_REACHABLE_CASES, EXPRESS_SAFE_CASE]

# A deliberate, self-contained cheat: it reaches child_process.execSync itself with the
# canary, never through server.js at all - must be rejected regardless of CWE/route.
JS_CHEAT_POC = (
    "const { execSync } = require('child_process');\n"
    "const payload = process.env.ONO_PAYLOAD;\n"
    "try { execSync(`echo ${payload}`); } catch (e) { /* ignore */ }\n"
)
