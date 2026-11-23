"""Dynamically-proven CWE families, offline: the added sink-oracle hooks exercised through
the REAL in-jail oracle (a subprocess ``python3 -I`` via :class:`LocalExecSandbox`), one
family per test. Each family proves three things against the real oracle:

* a VULNERABLE sink driven through the app's entry point -> the canary reaches the dangerous
  argument with the flagged line on the stack -> rung 3;
* a SAFE variant (the family's real defense: parameter/variable binding, escaping, a confined
  path, an entity-forbidding parser, a fixed redirect) -> the canary never lands in the
  dangerous argument -> stays rung <= 2 (no false positive);
* a CHEATING PoC that triggers the sink ITSELF (not through the flagged line) -> rejected.

Integrity is identical to the original families: the oracle picks the canary at verify time,
the PoC only reads ``os.environ["ONO_PAYLOAD"]``, and a hit counts only with the flagged line
on the call stack. Libraries that are not importable in the subprocess skip their test (the
family is then proven in the REAL docker jail instead - see test_verifier_families_docker).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from agentfakes import FakeExecExecutor, ScriptedModel, action
from ono.agents.definitions import FIXER, PROVER
from ono.config import Settings
from ono.models import Finding, TraceStep, finding_id_for, fingerprint_for
from ono.verifier import GradedVerifier
from ono.verifier._oracle import SUPPORTED_CWES, _nosql_tainted, _State
from ono.verifier.oracle import new_canary, oracle_supports, skip_reason

_NOOP_PATCH = "--- a/does/not/exist.py\n+++ b/does/not/exist.py\n@@ -1 +1 @@\n-x\n+y\n"


def _finding(cwe: str, sink_file: str, sink_line: int, source_line: int) -> Finding:
    trace = [
        TraceStep(file=sink_file, line=source_line, symbol="source", note="attacker-controlled"),
        TraceStep(file=sink_file, line=sink_line, symbol="sink", note=f"sink ({cwe})"),
    ]
    return Finding(
        finding_id=finding_id_for("scn_fam", "t", sink_file, sink_line, cwe),
        fingerprint=fingerprint_for("t", sink_file, sink_line, cwe),
        scan_id="scn_fam",
        target_id="t",
        title=f"{cwe} family case",
        cwe=cwe,
        severity="high",
        file=sink_file,
        line_range=(sink_line, sink_line),
        trace=trace,
        confidence=0.8,
        rung=2,
        verified=False,
        description="family fixture",
        patch_diff="",
    )


def _prove(
    tmp_path: Path,
    files: dict[str, str],
    *,
    cwe: str,
    sink_file: str,
    sink_line: int,
    source_line: int,
    poc: str,
    name: str = "ws",
) -> Finding:
    ws = tmp_path / name
    ws.mkdir()
    for rel, content in files.items():
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == PROVER.system_prompt:
            return action("submit_poc", code=poc, how="drive the entry point")
        if system == FIXER.system_prompt:
            return action("submit_patch", diff=_NOOP_PATCH, summary="noop")
        raise AssertionError("unexpected role")

    settings = Settings(
        _env_file=None,
        model_backend="service",
        model_service_url="http://model.test/v1",
        executor_token=SecretStr("unit-test-token-0123456789"),
        workspace_dir=tmp_path,
        context_lines=6,
        verifier_poc_timeout_s=60.0,
        max_verifier_retries=1,
    )
    verifier = GradedVerifier(
        settings, model=ScriptedModel(script=script), executor=FakeExecExecutor()
    )
    report = verifier.verify("scn_fam", ws, [_finding(cwe, sink_file, sink_line, source_line)])
    return report.findings[0]


# ---------------------------------------------------------------------------
# SSTI (CWE-1336) - Jinja2
# ---------------------------------------------------------------------------

_SSTI_APP = (
    "from jinja2 import Environment\n"
    "ENV = Environment()\n"
    "def render_user_template(tpl):\n"
    "    return ENV.from_string(tpl).render(user='bob')\n"
    "def render_with_context(name):\n"
    "    return ENV.from_string('Hello {{ name }}').render(name=name)\n"
)


def test_ssti_jinja2_is_proven(tmp_path: Path) -> None:
    pytest.importorskip("jinja2")
    poc = (
        "import os\nimport app\napp.render_user_template('Welcome ' + os.environ['ONO_PAYLOAD'])\n"
    )
    proven = _prove(
        tmp_path,
        {"app.py": _SSTI_APP},
        cwe="CWE-1336",
        sink_file="app.py",
        sink_line=4,
        source_line=3,
        poc=poc,
    )
    assert proven.verified is True and proven.rung >= 3
    assert proven.verification is not None and proven.verification.evidence


def test_ssti_safe_context_is_not_proven(tmp_path: Path) -> None:
    pytest.importorskip("jinja2")
    poc = "import os\nimport app\napp.render_with_context(os.environ['ONO_PAYLOAD'])\n"
    proven = _prove(
        tmp_path,
        {"app.py": _SSTI_APP},
        cwe="CWE-1336",
        sink_file="app.py",
        sink_line=6,
        source_line=6,
        poc=poc,
    )
    assert proven.verified is False and proven.rung <= 2


def test_ssti_cheating_poc_is_rejected(tmp_path: Path) -> None:
    pytest.importorskip("jinja2")
    # Renders the payload as a template ITSELF, not through the flagged app function.
    poc = (
        "import os\n"
        "from jinja2 import Environment\n"
        "Environment().from_string('x' + os.environ['ONO_PAYLOAD'])\n"
    )
    proven = _prove(
        tmp_path,
        {"app.py": _SSTI_APP},
        cwe="CWE-1336",
        sink_file="app.py",
        sink_line=4,
        source_line=3,
        poc=poc,
    )
    assert proven.verified is False and proven.rung <= 2


# ---------------------------------------------------------------------------
# XPath (CWE-643) - stdlib ElementTree
# ---------------------------------------------------------------------------

_XPATH_APP = (
    "import xml.etree.ElementTree as ET\n"
    'TREE = ET.fromstring(\'<users><u name="admin"/><u name="bob"/></users>\')\n'
    "def lookup(name):\n"
    '    return TREE.findall(".//u[@name=\'" + name + "\']")\n'
    "def lookup_safe(name):\n"
    "    return [u for u in TREE.findall('.//u') if u.get('name') == name]\n"
)


def test_xpath_injection_is_proven(tmp_path: Path) -> None:
    poc = "import os\nimport app\napp.lookup(os.environ['ONO_PAYLOAD'])\n"
    proven = _prove(
        tmp_path,
        {"app.py": _XPATH_APP},
        cwe="CWE-643",
        sink_file="app.py",
        sink_line=4,
        source_line=3,
        poc=poc,
    )
    assert proven.verified is True and proven.rung >= 3


def test_xpath_safe_filtering_is_not_proven(tmp_path: Path) -> None:
    poc = "import os\nimport app\napp.lookup_safe(os.environ['ONO_PAYLOAD'])\n"
    proven = _prove(
        tmp_path,
        {"app.py": _XPATH_APP},
        cwe="CWE-643",
        sink_file="app.py",
        sink_line=6,
        source_line=6,
        poc=poc,
    )
    assert proven.verified is False and proven.rung <= 2


# ---------------------------------------------------------------------------
# LDAP injection (CWE-90) - ldap3 (the canary carries a ")(|" probe that escaping removes)
# ---------------------------------------------------------------------------

_LDAP_APP = (
    "import ldap3\n"
    "from ldap3.utils.conv import escape_filter_chars\n"
    "SERVER = ldap3.Server('ldap://localhost', get_info=None)\n"
    "def _conn():\n"
    "    return ldap3.Connection(SERVER, client_strategy=ldap3.MOCK_SYNC)\n"
    "def search(name):\n"
    "    return _conn().search('dc=x', '(uid=' + name + ')')\n"
    "def search_safe(name):\n"
    "    return _conn().search('dc=x', '(uid=' + escape_filter_chars(name) + ')')\n"
)


def test_ldap_injection_is_proven(tmp_path: Path) -> None:
    pytest.importorskip("ldap3")
    poc = (
        "import os\nimport app\n"
        "try:\n    app.search(os.environ['ONO_PAYLOAD'])\nexcept Exception:\n    pass\n"
    )
    proven = _prove(
        tmp_path,
        {"app.py": _LDAP_APP},
        cwe="CWE-90",
        sink_file="app.py",
        sink_line=7,
        source_line=6,
        poc=poc,
    )
    assert proven.verified is True and proven.rung >= 3


def test_ldap_escaped_filter_is_not_proven(tmp_path: Path) -> None:
    pytest.importorskip("ldap3")
    poc = (
        "import os\nimport app\n"
        "try:\n    app.search_safe(os.environ['ONO_PAYLOAD'])\nexcept Exception:\n    pass\n"
    )
    proven = _prove(
        tmp_path,
        {"app.py": _LDAP_APP},
        cwe="CWE-90",
        sink_file="app.py",
        sink_line=9,
        source_line=8,
        poc=poc,
    )
    assert proven.verified is False and proven.rung <= 2


# ---------------------------------------------------------------------------
# Open redirect (CWE-601) - werkzeug
# ---------------------------------------------------------------------------

_REDIRECT_APP = (
    "from werkzeug.utils import redirect\n"
    "def go(nxt):\n"
    "    return redirect(nxt)\n"
    "def go_safe(nxt):\n"
    "    return redirect('/dashboard')\n"
)


def test_open_redirect_is_proven(tmp_path: Path) -> None:
    pytest.importorskip("werkzeug")
    poc = "import os\nimport app\napp.go('//attacker.example/' + os.environ['ONO_PAYLOAD'])\n"
    proven = _prove(
        tmp_path,
        {"app.py": _REDIRECT_APP},
        cwe="CWE-601",
        sink_file="app.py",
        sink_line=3,
        source_line=2,
        poc=poc,
    )
    assert proven.verified is True and proven.rung >= 3


def test_open_redirect_fixed_target_is_not_proven(tmp_path: Path) -> None:
    pytest.importorskip("werkzeug")
    poc = "import os\nimport app\napp.go_safe(os.environ['ONO_PAYLOAD'])\n"
    proven = _prove(
        tmp_path,
        {"app.py": _REDIRECT_APP},
        cwe="CWE-601",
        sink_file="app.py",
        sink_line=5,
        source_line=4,
        poc=poc,
    )
    assert proven.verified is False and proven.rung <= 2


# ---------------------------------------------------------------------------
# Reflected unescaped output (CWE-79) - werkzeug Response built at the flagged line
# ---------------------------------------------------------------------------

_XSS_APP = (
    "from werkzeug.wrappers import Response\n"
    "from markupsafe import escape\n"
    "def page(name):\n"
    "    return Response('<h1>' + name + '</h1>', mimetype='text/html')\n"
    "def page_safe(name):\n"
    "    return Response('<h1>' + str(escape(name)) + '</h1>', mimetype='text/html')\n"
)


def test_reflected_unescaped_output_is_proven(tmp_path: Path) -> None:
    pytest.importorskip("werkzeug")
    poc = "import os\nimport app\napp.page(os.environ['ONO_PAYLOAD'])\n"
    proven = _prove(
        tmp_path,
        {"app.py": _XSS_APP},
        cwe="CWE-79",
        sink_file="app.py",
        sink_line=4,
        source_line=3,
        poc=poc,
    )
    assert proven.verified is True and proven.rung >= 3


def test_html_escaped_output_is_not_proven(tmp_path: Path) -> None:
    pytest.importorskip("werkzeug")
    poc = "import os\nimport app\napp.page_safe(os.environ['ONO_PAYLOAD'])\n"
    proven = _prove(
        tmp_path,
        {"app.py": _XSS_APP},
        cwe="CWE-79",
        sink_file="app.py",
        sink_line=6,
        source_line=5,
        poc=poc,
    )
    assert proven.verified is False and proven.rung <= 2


# ---------------------------------------------------------------------------
# Arbitrary file write (CWE-73) - stdlib open() (write mode, traversal out of a base dir)
# ---------------------------------------------------------------------------

_FILEWRITE_APP = (
    "import os\n"
    "BASE = '/tmp/ono-fam-uploads'\n"
    "def save(name, data):\n"
    "    with open(os.path.join(BASE, name), 'w') as f:\n"
    "        f.write(data)\n"
    "def save_safe(name, data):\n"
    "    with open(os.path.join(BASE, os.path.basename(name)), 'w') as f:\n"
    "        f.write(data)\n"
)


def test_arbitrary_file_write_is_proven(tmp_path: Path) -> None:
    poc = (
        "import os\nos.makedirs('/tmp/ono-fam-uploads', exist_ok=True)\nimport app\n"
        "app.save('../' + os.environ['ONO_PAYLOAD'], 'x')\n"
    )
    proven = _prove(
        tmp_path,
        {"app.py": _FILEWRITE_APP},
        cwe="CWE-73",
        sink_file="app.py",
        sink_line=4,
        source_line=3,
        poc=poc,
    )
    assert proven.verified is True and proven.rung >= 3


def test_confined_file_write_is_not_proven(tmp_path: Path) -> None:
    poc = (
        "import os\nos.makedirs('/tmp/ono-fam-uploads', exist_ok=True)\nimport app\n"
        "app.save_safe(os.environ['ONO_PAYLOAD'], 'x')\n"
    )
    proven = _prove(
        tmp_path,
        {"app.py": _FILEWRITE_APP},
        cwe="CWE-73",
        sink_file="app.py",
        sink_line=8,
        source_line=7,
        poc=poc,
    )
    assert proven.verified is False and proven.rung <= 2


# ---------------------------------------------------------------------------
# XXE (CWE-611) - stdlib minidom (DOCTYPE/ENTITY reaches an entity-expanding parser)
# ---------------------------------------------------------------------------

_XXE_APP = "from xml.dom import minidom\ndef parse(xml):\n    return minidom.parseString(xml)\n"


def test_xxe_tainted_doctype_is_proven(tmp_path: Path) -> None:
    poc = (
        "import os\n"
        "p = os.environ['ONO_PAYLOAD']\n"
        "import app\n"
        "xml = '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY e \"' + p + '\">]><r>&e;</r>'\n"
        "try:\n    app.parse(xml)\nexcept Exception:\n    pass\n"
    )
    proven = _prove(
        tmp_path,
        {"app.py": _XXE_APP},
        cwe="CWE-611",
        sink_file="app.py",
        sink_line=3,
        source_line=2,
        poc=poc,
    )
    assert proven.verified is True and proven.rung >= 3


def test_xxe_plain_xml_without_doctype_is_not_proven(tmp_path: Path) -> None:
    poc = (
        "import os\n"
        "p = os.environ['ONO_PAYLOAD']\n"
        "import app\n"
        "app.parse('<?xml version=\"1.0\"?><r>' + p + '</r>')\n"
    )
    proven = _prove(
        tmp_path,
        {"app.py": _XXE_APP},
        cwe="CWE-611",
        sink_file="app.py",
        sink_line=3,
        source_line=2,
        poc=poc,
    )
    assert proven.verified is False and proven.rung <= 2


# ---------------------------------------------------------------------------
# NoSQL (CWE-943) - pymongo is not a host dependency, so the OPERATOR-position
# classifier is unit-tested directly (the docker matrix exercises the full hook).
# ---------------------------------------------------------------------------


def test_nosql_operator_position_classifier() -> None:
    state = _State({"canary": new_canary("CWE-943"), "sink_file": "a.py", "poc": "x"}, "/tmp")
    core = state.core
    assert _nosql_tainted(state, {"$where": "this.name == '" + core + "'"}) is True
    assert _nosql_tainted(state, {"user": {"$regex": "^" + core}}) is False  # value, not operator
    assert _nosql_tainted(state, {"$" + core: 1}) is True  # injected operator key
    assert _nosql_tainted(state, {"name": core}) is False  # a plain field value is parameterised
    assert _nosql_tainted(state, {"a": [{"$expr": core}]}) is True


# ---------------------------------------------------------------------------
# Honest classification: the supported families, and the skipped ones with reasons.
# ---------------------------------------------------------------------------


def test_added_families_are_in_the_supported_set() -> None:
    added = {"CWE-1336", "CWE-643", "CWE-90", "CWE-943", "CWE-611", "CWE-601", "CWE-73", "CWE-79"}
    assert added <= SUPPORTED_CWES


@pytest.mark.parametrize(
    "cwe", ["CWE-327", "CWE-798", "CWE-285", "CWE-306", "CWE-862", "CWE-352", "CWE-113"]
)
def test_unprovable_cwes_skip_with_a_clear_reason(cwe: str) -> None:
    assert cwe not in SUPPORTED_CWES
    assert skip_reason(cwe)
    finding = _finding(cwe, "app.py", 1, 1)
    message = oracle_supports(finding)
    assert "not dynamically provable" in message and skip_reason(cwe)[:20] in message
