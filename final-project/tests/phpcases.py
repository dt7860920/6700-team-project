"""PHP fixture cases for the PHP sink oracle - the PHP sibling of ``jscases.py``.

:data:`PHP_CMDI_CASE` sits behind the SAME precondition real-app failure mode as the JS and
Python framework fixtures (an include-time secret the module refuses to load without, plus an
API-key check): a from-scratch PoC that never ``require``s ``app.php``, or that calls
``system()`` itself, must not prove anything - only driving the real ``handle()`` route does.
:data:`PHP_SAFE_CASE` is the planted false positive (the argv form of ``proc_open`` - never a
shell, never tainted) and :data:`PHP_CHEAT_POC` is the deliberate self-contained "cheat" a
PoC must not get away with.

No answer keys: these PoCs read the canary from ``getenv('ONO_PAYLOAD')`` (handed out at
verify time) and place it where attacker input enters; they never know what the oracle will
check for beyond that.
"""

from __future__ import annotations

from fixturecases import FixtureCase
from ono.models import TraceStep

FIXTURE = "php_cmdi_app"
_SECRET = "php-fixture-secret"

# Satisfy the include-time secret (the app throws without it), then drive the real route with
# the canary in the "host" input. Written as if poc.php lived at the repository root: the
# oracle chdir()s there, so getcwd() is the workspace root.
_DRIVE_ROUTE = """\
<?php
putenv('APP_SECRET={secret}');
$_ENV['APP_SECRET'] = '{secret}';
require getcwd() . '/app.php';
$payload = getenv('ONO_PAYLOAD');
try {{
    handle(['path' => '{route}', 'api_key' => '{secret}', 'args' => ['host' => $payload]]);
}} catch (\\Throwable $e) {{
    // the oracle records AT the sink call; an error after it (ping missing) does not matter
}}
"""

PHP_CMDI_CASE = FixtureCase(
    name="php_cmdi_behind_api_key",
    fixture=FIXTURE,
    cwe="CWE-78",
    sink_file="app.php",
    sink_line=32,
    source=TraceStep(
        file="app.php", line=28, symbol="$_GET['host']", note="attacker-controlled GET param"
    ),
    honest_poc=_DRIVE_ROUTE.format(secret=_SECRET, route="/diagnose"),
    # The dominant real-app failure: a plausible-but-naive PoC that requires the module without
    # first satisfying its include-time secret - it throws before any sink is reached.
    naive_poc="<?php\nrequire getcwd() . '/app.php';\n$payload = getenv('ONO_PAYLOAD');\n",
    note="command injection behind an include-time secret and an API-key route guard",
)

PHP_SAFE_CASE = FixtureCase(
    name="php_proc_open_argv_false_positive",
    fixture=FIXTURE,
    cwe="CWE-78",
    sink_file="app.php",
    sink_line=39,
    source=TraceStep(
        file="app.php", line=37, symbol="$_GET['host']", note="attacker-controlled GET param"
    ),
    honest_poc=_DRIVE_ROUTE.format(secret=_SECRET, route="/diagnose-safe"),
    naive_poc="<?php\nrequire getcwd() . '/app.php';\n",
    reachable=False,
    note="proc_open with an argv array (no shell) - never a command-injection sink",
)

# A deliberate, self-contained cheat: it reaches system() itself with the canary, never
# through app.php at all - must be rejected (the flagged file:line is never on the stack).
PHP_CHEAT_POC = "<?php\n$payload = getenv('ONO_PAYLOAD');\n@system('echo ' . $payload);\n"

PHP_REACHABLE_CASES: list[FixtureCase] = [PHP_CMDI_CASE]
PHP_ALL_CASES: list[FixtureCase] = [*PHP_REACHABLE_CASES, PHP_SAFE_CASE]
