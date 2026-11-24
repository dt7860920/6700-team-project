"""PHP front-end: tree-sitter lowering, superglobal / request taint, catalog sinks, entries.

Mirrors the JavaScript/TypeScript suite in ``test_planning.py`` - the point of the PHP
prove-depth piece is that PHP plugs into the IR / taint engine / catalog / threat map through
the SAME seams as JS, so these tests exercise it the same way.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

from ono.planning import php_frontend, threat_map
from ono.planning.ir import chain
from ono.planning.php_frontend import lower_php
from ono.planning.taint import analyze_module


def _php(source: str, file: str = "app.php") -> Any:
    return lower_php(textwrap.dedent(source), file)


def _hits(module: Any) -> list[tuple[str, int, str, str]]:
    out = []
    for ctx in analyze_module(module).values():
        out.extend((h.file, h.line, h.cwe, h.state) for h in ctx.hits)
    return sorted(out)


# ---------------------------------------------------------------------------
# Lowering + superglobal sources
# ---------------------------------------------------------------------------


def test_php_lowering_functions_params_and_calls() -> None:
    module = _php(
        """
        <?php
        function outer($a) {
            $x = $_GET['q'];
            $cb = function () use ($x) { return system($x); };
            return $db->query($a);
        }
        """
    )
    names = [f.name for f in module.functions]
    assert names[:2] == ["<module>", "outer"]
    outer = module.functions[1]
    assert outer.params == ("$a",)
    assert [a.targets for a in outer.assigns] == [("$x",), ("$cb",)]
    assert [chain(c) for c in outer.calls] == ["$db.query"]
    # the closure (named after the variable it is assigned to) inherits ``outer``'s scope as
    # its parent, so taint propagates into it.
    closure = module.functions[2]
    assert closure.name == "$cb" and closure.parent is outer


def test_php_superglobal_to_system_is_a_command_injection_sink(tmp_path: Path) -> None:
    source = """
        <?php
        $id = $_GET['id'];
        system("ping " . $id);
    """
    module = _php(source)
    # the one-hop/direct taint lands a CWE-78 command-injection sink...
    assert _hits(module) == [("app.php", 4, "CWE-78", "tainted")]

    # ...and through the stage, the superglobal read becomes an entry point.
    (tmp_path / "app.php").write_text(textwrap.dedent(source))
    result = threat_map(tmp_path, [], max_candidates=20)
    assert [(c.file, c.line, c.cwe_hint, c.reach) for c in result.queue] == [
        ("app.php", 4, "CWE-78", "direct")
    ]
    assert [e.kind for e in result.entry_points] == ["input"]
    assert result.entry_points[0].detail.startswith("HTTP GET parameter ($_GET)")
    assert result.summary().startswith("threat map: 1 entry point(s) in 1 file(s) (1 php)")


def test_php_constant_command_yields_no_sink() -> None:
    module = _php('<?php\nsystem("ls -la");\n')
    assert _hits(module) == []


def test_php_sanitizers_downgrade_taint_below_reachable() -> None:
    # an ``(int)`` cast and ``escapeshellarg`` both neutralise the payload: the sink argument
    # is no longer attacker-controlled, so nothing is reported as reachable (``tainted``).
    module = _php(
        """
        <?php
        $n = (int) $_GET['n'];
        system("top -p " . $n);
        system("echo " . escapeshellarg($_GET['c']));
        """
    )
    assert [h for h in _hits(module) if h[3] == "tainted"] == []


# ---------------------------------------------------------------------------
# Catalog sink families (data rows, one per CWE)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "cwe"),
    [
        ('$db->query("SELECT * FROM u WHERE id=" . $_POST["id"]);', "CWE-89"),
        ('mysqli_query($conn, "SELECT " . $_GET["q"]);', "CWE-89"),
        ("eval($_REQUEST['code']);", "CWE-95"),
        ("preg_replace('/x/e', $_GET['r'], $subject);", "CWE-95"),
        ("include $_GET['page'];", "CWE-98"),
        ("require_once $_GET['tpl'];", "CWE-98"),
        ("unserialize($_COOKIE['c']);", "CWE-502"),
        ("echo $_GET['name'];", "CWE-79"),
        ("print($_GET['name']);", "CWE-79"),
    ],
)
def test_php_sink_families_map_to_the_right_cwe(source: str, cwe: str) -> None:
    module = _php(f"<?php\n{source}\n")
    assert [(c, s) for _f, _l, c, s in _hits(module)] == [(cwe, "tainted")]


def test_php_path_and_ssrf_sinks_are_taint_gated() -> None:
    # file_get_contents on attacker input is both path (CWE-22) and SSRF (CWE-918);
    # a constant argument fires neither (taint-gated).
    module = _php(
        """
        <?php
        file_get_contents($_GET['u']);
        file_get_contents("/etc/config");
        """
    )
    assert _hits(module) == [
        ("app.php", 3, "CWE-22", "tainted"),
        ("app.php", 3, "CWE-918", "tainted"),
    ]


def test_php_backtick_operator_is_a_shell_sink() -> None:
    module = _php(
        """
        <?php
        function run($host) { return `ping -c1 $host`; }
        """
    )
    # the backtick operator lowers to a synthetic ``shell_exec`` call; the parameter is
    # potential taint (``param``) resolvable one hop up.
    assert _hits(module) == [("app.php", 3, "CWE-78", "param")]


# ---------------------------------------------------------------------------
# Entry points: routes, attributes, request parameters
# ---------------------------------------------------------------------------


def test_php_route_registration_marks_inline_handlers_and_refs() -> None:
    module = _php(
        """
        <?php
        Route::post('/run', function (Request $request) {
            system($request->input('cmd'));
        });
        $app->get('/show', 'HomeController@show');
        $router->post('/save', [Ctrl::class, 'save']);
        """
    )
    closure = next(f for f in module.functions if f.name.startswith("<anonymous"))
    assert closure.entry is not None and (closure.entry.kind, closure.entry.detail) == (
        "route",
        "POST /run",
    )
    assert _hits(module) == [("app.php", 4, "CWE-78", "tainted")]
    assert [(r.name, r.detail) for r in module.handler_refs] == [
        ("show", "GET /show"),
        ("save", "POST /save"),
    ]


def test_php_symfony_attribute_route_taints_all_request_data() -> None:
    module = _php(
        """
        <?php
        class PageController {
            #[Route('/page/{id}', methods: ['GET'])]
            public function page(Request $request) {
                return eval($request->query->get('code'));
            }
        }
        """
    )
    page = module.functions[1]
    assert page.entry is not None and (page.entry.kind, page.entry.detail) == (
        "route",
        "GET /page/{id}",
    )
    assert _hits(module) == [("app.php", 6, "CWE-95", "tainted")]


def test_php_controller_request_parameter_is_an_entry_point() -> None:
    module = _php(
        """
        <?php
        class UserController extends Controller {
            public function destroy(Request $request) {
                system($request->input('target'));
            }
        }
        """
    )
    destroy = module.functions[1]
    assert destroy.entry is not None and destroy.entry.kind == "request-param"
    assert destroy.entry.request_params == ("$request",)
    assert _hits(module) == [("app.php", 5, "CWE-78", "tainted")]


# ---------------------------------------------------------------------------
# Robustness: syntax errors + graceful degradation when the grammar is absent
# ---------------------------------------------------------------------------


def test_php_syntax_error_keeps_the_rest_of_the_file() -> None:
    module = _php("<?php\nfunction ok() { eval($_GET['e']); }\nfunction broken( {\n")
    assert module.parse_error == "syntax errors (partial tree used)"
    assert ("app.php", 2, "CWE-95", "tainted") in _hits(module)


def test_php_frontend_degrades_gracefully_without_the_grammar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(php_frontend, "AVAILABLE", False)
    monkeypatch.setattr(
        php_frontend, "_IMPORT_ERROR", "No module named 'tree_sitter_php'", raising=False
    )
    module = lower_php("<?php system($_GET['x']);", "x.php")
    assert module.language == "php"
    assert module.parse_error.startswith("tree-sitter-php unavailable")
    assert module.functions == []  # bails before parsing; no crash, no PHP coverage
    assert _hits(module) == []
