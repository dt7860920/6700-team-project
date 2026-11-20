"""The threat-mapping stage: IR front-ends, the taint engine, ranking + union, planner seeding."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

import pytest

from agentfakes import FakeExecutor, ScriptedModel, action
from ono import sast
from ono.agents.definitions import PLANNER
from ono.agents.model import CallBudget
from ono.agents.planner import default_plan, plan_from_dict, run_planner
from ono.agents.trajectory import Trajectory
from ono.analyzer import ServiceAnalyzer
from ono.config import Settings
from ono.models import ScanOptions
from ono.planning import threat_map
from ono.planning.evaluate import Planted, compare, planted_vulns, render_table, score
from ono.planning.ir import chain
from ono.planning.js_frontend import lower_js
from ono.planning.python_frontend import lower_python
from ono.planning.taint import analyze_module
from ono.sast import Candidate
from ono.targets import Target

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"
CORPUS = Path(__file__).parent / "corpus"


def _py(source: str, file: str = "app.py") -> Any:
    return lower_python(textwrap.dedent(source), file)


def _js(source: str, file: str = "app.js") -> Any:
    return lower_js(
        textwrap.dedent(source),
        file,
        language="typescript" if file.endswith(".ts") else "javascript",
    )


def _hits(module: Any) -> list[tuple[str, int, str, str]]:
    out = []
    for ctx in analyze_module(module).values():
        out.extend((h.file, h.line, h.cwe, h.state) for h in ctx.hits)
    return sorted(out)


# ---------------------------------------------------------------------------
# Python front-end
# ---------------------------------------------------------------------------


def test_python_lowering_functions_params_imports_and_calls() -> None:
    module = _py(
        """
        import subprocess as sp
        from os import system
        from flask import request

        def outer(a, *rest, key=None, **kw):
            x = request.args.get("q")
            def inner():
                return system(x)
            return sp.run(a, shell=True)
        """
    )
    names = [f.name for f in module.functions]
    assert names == ["<module>", "outer", "inner"]
    outer, inner = module.functions[1], module.functions[2]
    assert outer.params == ("a", "rest", "key", "kw")
    assert inner.parent is outer
    assert module.imports == {"sp": "subprocess", "system": "os.system", "request": "flask.request"}
    assert module.resolve("sp.run") == "subprocess.run" and module.resolve("system") == "os.system"
    assert [a.targets for a in outer.assigns] == [("x",)]
    assert [chain(c) for c in outer.calls] == ["request.args.get", "sp.run"]
    assert [chain(c) for c in inner.calls] == ["system"]


@pytest.mark.parametrize(
    ("source", "kind", "detail"),
    [
        ('@app.route("/x", methods=["POST"])\ndef h(): ...', "route", "POST /x"),
        ('@bp.get("/items/<int:i>")\ndef h(i): ...', "route", "GET /items/<int:i>"),
        ("@csrf_exempt\ndef h(request): ...", "view", "@csrf_exempt"),
        ("@click.command()\ndef h(name): ...", "cli", "@click.command"),
        ("def h(request, pk): ...", "request-param", "parameter 'request'"),
        ("class V(View):\n    def post(self, request): ...", "class-view", "POST V"),
    ],
)
def test_python_entry_point_markers(source: str, kind: str, detail: str) -> None:
    module = _py(source)
    fn = module.functions[-1]
    assert fn.entry is not None and (fn.entry.kind, fn.entry.detail) == (kind, detail)


def test_python_route_parameters_are_attacker_controlled() -> None:
    module = _py(
        """
        @app.get("/items/{item_id}")
        async def read_item(item_id: str):
            cur.execute("SELECT 1 WHERE id = " + item_id)
        """
    )
    assert module.functions[1].entry is not None
    assert module.functions[1].entry.tainted_params == ("item_id",)
    assert _hits(module) == [("app.py", 4, "CWE-89", "tainted")]


def test_python_url_map_refs_are_collected() -> None:
    module = _py(
        """
        from django.urls import path
        urlpatterns = [path("a/", views.detail), path("b/", views.Thing.as_view())]
        app.add_url_rule("/c", view_func=handler)
        """
    )
    assert [(r.name, r.kind) for r in module.handler_refs] == [
        ("detail", "url-map"),
        ("Thing", "class-view"),
        ("handler", "url-map"),
    ]


def test_python_syntax_error_is_reported_not_raised() -> None:
    module = _py("def broken(:\n    pass\n")
    assert module.parse_error.startswith("SyntaxError") and module.functions[0].is_module


# ---------------------------------------------------------------------------
# JavaScript / TypeScript front-end
# ---------------------------------------------------------------------------


def test_js_require_and_import_bindings_resolve_sinks() -> None:
    module = _js(
        """
        const cp = require("node:child_process");
        const { exec, execSync: es } = require("child_process");
        import fs from "fs";
        import { readFile as rf } from "fs/promises";
        import * as vm from "vm";
        function run(cmd) {
          cp.exec(cmd); exec(cmd); es(cmd); fs.readFile(cmd); rf(cmd); vm.runInNewContext(cmd);
          require("fs").unlink(cmd);
        }
        """
    )
    assert module.imports == {
        "cp": "child_process",
        "exec": "child_process.exec",
        "es": "child_process.execSync",
        "fs": "fs",
        "rf": "fs/promises.readFile",
        "vm": "vm",
    }
    run = module.functions[1]
    assert [module.resolve(chain(c)) for c in run.calls] == [
        "child_process.exec",
        "child_process.exec",
        "child_process.execSync",
        "fs.readFile",
        "fs/promises.readFile",
        "vm.runInNewContext",
        "fs.unlink",
    ]


def test_js_destructuring_taints_the_bound_names() -> None:
    module = _js(
        """
        app.post("/login", (req, res) => {
          const { email, nested: { name } } = req.body;
          const [first] = req.query.items;
          db.query("SELECT 1 WHERE e = '" + email + "'");
          db.query("SELECT 2 WHERE n = '" + name + "'");
          db.query("SELECT 3 WHERE f = '" + first + "'");
        });
        """
    )
    assert _hits(module) == [
        ("app.js", 5, "CWE-89", "tainted"),
        ("app.js", 6, "CWE-89", "tainted"),
        ("app.js", 7, "CWE-89", "tainted"),
    ]


def test_js_route_registrations_mark_inline_handlers_and_refs() -> None:
    module = _js(
        """
        const router = require("express").Router();
        router.get("/a", (req, res) => res.send("a"));
        router.route("/b").post(function b(req, res) {});
        app.use(auth, controller.list);
        http.createServer((req, res) => {});
        exports.handler = async (event) => {};
        export default function page(req, res) {}
        """
    )
    entries = {fn.name: (fn.entry.kind, fn.entry.detail) for fn in module.functions if fn.entry}
    assert entries["<anonymous@3:17>"] == ("route", "GET /a")
    assert entries["b"] == ("route", "POST /b")
    assert entries["<anonymous@6:18>"] == ("handler", "http.createServer request handler")
    assert entries["handler"] == ("lambda", "exported handler(event)")
    assert entries["page"] == ("exported-handler", "exported page(req)")
    assert [(r.name, r.detail) for r in module.handler_refs] == [("list", "USE *")]


def test_ts_decorators_types_and_casts_are_transparent() -> None:
    module = _js(
        """
        import { exec } from "child_process";
        @Controller("x")
        export class X {
          @Get(":id")
          find(@Param("id") id: string) {
            return this.repo.query("SELECT " + (id as string)!);
          }
          @Post()
          run(@Body() body: Dto) { exec(body.cmd); }
        }
        """,
        file="c.ts",
    )
    find, run = module.functions[1], module.functions[2]
    assert find.entry is not None and (find.entry.kind, find.entry.detail) == ("route", "GET :id")
    assert run.entry is not None and run.entry.detail == "POST *"
    assert _hits(module) == [("c.ts", 7, "CWE-89", "tainted"), ("c.ts", 10, "CWE-78", "tainted")]


def test_js_syntax_error_keeps_the_rest_of_the_file() -> None:
    module = _js("function ok(req) { eval(req.query.x) }\nfunction broken( {\n")
    assert module.parse_error == "syntax errors (partial tree used)"
    assert ("app.js", 1, "CWE-95", "tainted") in _hits(module)


# ---------------------------------------------------------------------------
# Taint engine
# ---------------------------------------------------------------------------


def test_sanitizers_constants_and_non_input_request_members() -> None:
    module = _py(
        """
        import os, shlex, yaml, subprocess
        QUERY = "SELECT 1"
        @app.route("/x")
        def h():
            n = int(request.args["n"])
            cur.execute(f"SELECT {n}")                      # sanitized -> dynamic
            os.system("ls " + shlex.quote(request.args["d"]))  # sanitized -> dynamic
            cur.execute(QUERY, (request.args["k"],))       # constant SQL -> no hit
            os.system(request.user.name)                   # not input -> dynamic
            url = ALLOWED[request.args["site"]]            # index never taints
            requests.get(url)                              # gated -> no hit
            yaml.load(request.data, Loader=yaml.SafeLoader)  # safe loader -> no hit
            subprocess.run(["ls", request.args["d"]])      # argv list -> no hit
            subprocess.run(request.args["c"], shell=True)
        """
    )
    assert _hits(module) == [
        ("app.py", 7, "CWE-89", "dynamic"),
        ("app.py", 8, "CWE-78", "dynamic"),
        ("app.py", 10, "CWE-78", "dynamic"),
        ("app.py", 15, "CWE-78", "tainted"),
    ]


def test_closures_inherit_taint_and_multiline_calls_are_sinks() -> None:
    module = _py(
        """
        import subprocess
        @app.route("/x")
        def h():
            cmd = "tar " + request.form["f"]
            def later():
                return subprocess.Popen(
                    cmd,
                    shell=True,
                )
            return later()
        """
    )
    assert _hits(module) == [("app.py", 7, "CWE-78", "tainted")]
    ctx = next(c for c in analyze_module(module).values() if c.fn.name == "later")
    hop_lines = [h.line for h in ctx.hits[0].best.hops] if ctx.hits[0].best else []
    assert hop_lines == [5, 5]  # source read, then the ``cmd`` assignment, both on line 5


def test_parameters_are_potential_taint_and_argv_env_are_sources() -> None:
    module = _py(
        """
        import os, sys, pickle
        def helper(blob):
            return pickle.loads(blob)
        def main():
            os.system("rm " + sys.argv[1])
            os.popen(os.environ["CMD"])
        """
    )
    assert _hits(module) == [
        ("app.py", 4, "CWE-502", "param"),
        ("app.py", 6, "CWE-78", "tainted"),
        ("app.py", 7, "CWE-78", "tainted"),
    ]


# ---------------------------------------------------------------------------
# The stage: ranking, union, cap, one hop
# ---------------------------------------------------------------------------


def test_fixture_repo_is_ranked_by_reachability_with_traces() -> None:
    candidates = sast.dedupe(sast.regex_scan(FIXTURE_REPO))
    assert candidates[0].file == "app/util.py"  # SAST order: severity, then path
    result = threat_map(FIXTURE_REPO, candidates, max_candidates=20)
    assert [(c.file, c.line, c.reach) for c in result.queue] == [
        ("app/views.py", 16, "direct"),
        ("app/views.py", 23, "direct"),
        ("app/util.py", 5, "param"),
    ]
    sqli = result.queue[0]
    assert sqli.entry == "ANY /user -> app/views.py:12 user()"
    assert sqli.source == 'request.args.get("id", "") at app/views.py:13'
    assert sqli.path == (
        "app/views.py:13 request.args - attacker-controlled request data",
        'app/views.py:13 uid - uid = request.args.get("id", "")',
        'app/views.py:16 cur.execute(f"SELECT * FROM users WHERE id = {uid}") - sink (CWE-89)',
    )
    assert [e.detail for e in result.entry_points] == ["ANY /user", "ANY /ping", "ANY /healthz"]
    assert result.added == 0 and result.matched == 3 and result.cut == 0
    assert result.summary().startswith("threat map: 3 entry point(s) in 2 file(s) (2 python)")


def test_union_adds_reachable_sinks_sast_missed_and_honours_the_cap(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        textwrap.dedent(
            """
            import os
            from flask import request
            @app.route("/a")
            def a():
                q = "SELECT * FROM t WHERE x = " + request.args["x"]
                cur.execute(q)                 # regex misses: the string is built elsewhere
            @app.route("/b")
            def b():
                os.system("ls " + request.args["d"])
            def helper(path):
                return open(path).read()       # taint-gated and no tainted caller: dropped
            """
        )
    )
    sast_only = sast.dedupe(sast.regex_scan(tmp_path))
    assert [(c.line, c.cwe_hint) for c in sast_only] == [(10, "CWE-78")]
    result = threat_map(tmp_path, sast_only, max_candidates=20)
    assert [(c.line, c.cwe_hint, c.rule, c.reach) for c in result.queue] == [
        (7, "CWE-89", "ono.threatmap.sql-query-built-from-input", "direct"),
        (10, "CWE-78", "shell-command-from-string", "direct"),
    ]
    assert result.added == 1 and [s.cwe for s in result.sinks] == ["CWE-89", "CWE-78"]
    capped = threat_map(tmp_path, sast_only, max_candidates=1)
    assert [c.line for c in capped.queue] == [7] and capped.cut == 1
    assert "1 cut by max_candidates" in capped.summary()


def test_one_hop_links_a_caller_to_a_helper_sink(tmp_path: Path) -> None:
    (tmp_path / "lib.py").write_text(
        "def login(conn, user):\n"
        "    return conn.execute(\"SELECT 1 WHERE u = '%s'\" % user)\n"
        "def unused(x):\n"
        "    return open(x)\n"
    )
    (tmp_path / "web.py").write_text(
        "from flask import request\nfrom lib import login\n"
        '@app.route("/login", methods=["POST"])\n'
        "def view():\n"
        '    return login(db, request.form["user"])\n'
    )
    result = threat_map(tmp_path, [], max_candidates=20)
    assert [(c.file, c.line, c.reach) for c in result.queue] == [("lib.py", 2, "one-hop")]
    link = result.links[0]
    assert link.entry is not None and link.entry.detail == "POST /login"
    assert [h.symbol for h in link.hops] == [
        "request.form",
        "login(user=...)",
        "user",
        "conn.execute(\"SELECT 1 WHERE u = '%s'\" % user)",
    ]
    assert result.queue[0].entry == "POST /login -> web.py:4 view()"


def test_sast_candidates_get_constant_in_entry_and_unmapped_tiers(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(
        "import os, subprocess\n"
        "CMD = 'ls -la'\n"
        "@app.route('/x')\n"
        "def view():\n"
        "    subprocess.run(CMD, shell=True)\n"
        "    weird()\n"
        "def plain():\n"
        "    other()\n"
    )
    given = [
        Candidate("m.py", 5, "CWE-78", "r1", severity="ERROR"),
        Candidate("m.py", 6, "CWE-704", "r2", severity="ERROR"),
        Candidate("m.py", 8, "CWE-704", "r3", severity="ERROR"),
        Candidate("missing.py", 1, "CWE-89", "r4", severity="ERROR"),
    ]
    result = threat_map(tmp_path, given, max_candidates=20)
    assert [(c.line, c.reach) for c in result.queue] == [
        (6, "in-entry"),
        (8, "unmapped"),
        (1, "unmapped"),
        (5, "constant"),
    ]
    assert result.queue[-1].source == "the sink argument is a constant (no input dependency found)"
    assert result.matched == 2


def test_empty_and_unparsable_workspaces_never_fail(tmp_path: Path) -> None:
    assert (
        threat_map(tmp_path, [], max_candidates=5)
        .summary()
        .startswith("threat map: 0 entry point(s) in 0 file(s) (no source files)")
    )
    (tmp_path / "bad.py").write_text("def (:\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("eval(process.argv[2])\n")
    result = threat_map(tmp_path, [], max_candidates=5)
    assert result.files == 1 and result.parse_errors == 1 and result.queue == []
    assert "1 file(s) with parse errors" in result.summary()


def test_deadline_stops_parsing_with_a_note(tmp_path: Path) -> None:
    for i in range(3):
        (tmp_path / f"f{i}.py").write_text("x = 1\n")
    result = threat_map(tmp_path, [], max_candidates=5, deadline_s=-1.0)
    assert result.files == 0 and result.notes == ["stopped after -1s wall clock (0 files parsed)"]


# ---------------------------------------------------------------------------
# Planner seeding
# ---------------------------------------------------------------------------


def _mapped_candidate() -> Candidate:
    return threat_map(
        FIXTURE_REPO, sast.dedupe(sast.regex_scan(FIXTURE_REPO)), max_candidates=9
    ).queue[0]


def test_default_plan_and_planner_prompt_carry_the_threat_map() -> None:
    c = _mapped_candidate()
    plan = default_plan(c)
    assert plan.source.startswith(
        'threat map: direct; request.args.get("id", "") at app/views.py:13'
    )
    assert "entry point ANY /user -> app/views.py:12 user()" in plan.source
    assert plan.trace == list(c.path) and "Threat-map trace" in plan.render()
    kept = plan_from_dict({"hypothesis": "h"}, c)
    assert kept.trace == list(c.path) and kept.origin == "planner"

    model = ScriptedModel([json.dumps({"hypothesis": "sqli"})])
    traj = Trajectory(scan_id="s", role="planner", candidate="x")
    run_planner(
        model,
        PLANNER,
        candidate=c,
        window_text="16 | x",
        budget=CallBudget(limit=1),
        trajectory=traj,
    )
    prompt = model.calls[0]["messages"][1]["content"]
    assert "Threat map (static entry-point / data-flow analysis): reach = direct" in prompt
    assert "  hop: app/views.py:13 request.args - attacker-controlled request data" in prompt
    unmapped = default_plan(Candidate("a.py", 1, "CWE-89", "r"))
    assert unmapped.source.startswith("unknown") and unmapped.trace == []


# ---------------------------------------------------------------------------
# The service pipeline: JS-only repo with no SAST candidates still gets analyzed
# ---------------------------------------------------------------------------


@pytest.fixture
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(root: Path, rulesets: Any) -> dict[str, object]:
        raise sast.SemgrepUnavailableError("semgrep disabled in tests")

    monkeypatch.setattr(sast, "run_semgrep", unavailable)


def _settings(workspace: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "model_backend": "service",
        "model_service_url": "http://localhost:11434/v1",
        "executor_token": "unit-test-token-0123456789",
        "workspace_dir": workspace,
        "context_lines": 5,
    }
    return Settings(_env_file=None, **{**base, **overrides})


@pytest.mark.usefixtures("_offline")
def test_js_repo_with_no_sast_candidates_is_analyzed_via_the_threat_map(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "server.js").write_text(
        'const { exec } = require("child_process");\n'
        'app.get("/ping", (req, res) => {\n'
        '  exec("ping " + req.query.host, (e, out) => res.send(out));\n'
        "});\n"
    )
    target = Target(
        target_id="js",
        name="js",
        kind="repo",
        languages=["javascript"],
        source=str(repo),
        snapshot="x",
    )
    model = ScriptedModel(default=action("dismiss", reason="not reachable"))
    analyzer = ServiceAnalyzer(
        _settings(tmp_path / "ws", planner_enabled=False), model=model, executor=FakeExecutor()
    )
    result = analyzer.run("scn_js", target, ScanOptions())
    assert result.stages[1].summary == "0 candidate(s)"  # the regex fallback is Python-only
    assert result.stages[2].summary.startswith(
        "threat map: 1 entry point(s) in 1 file(s) (1 javascript); 1 sink(s), 1 reachable "
        "(1 direct, 0 one-hop); queue 1 = 0 from SAST (0 mapped) + 1 added"
    )
    assert result.stages[3].status == "ok" and result.candidate_count == 1 and model.n_calls == 1
    task = model.calls[0]["messages"][1]["content"]
    assert "file: server.js\n  line: 3\n  suspected CWE: CWE-78" in task
    assert "entry point GET /ping -> server.js:2 <anonymous@2:17>()" in task


@pytest.mark.usefixtures("_offline")
def test_threat_map_failure_keeps_the_sast_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("engine bug")

    monkeypatch.setattr("ono.analyzer.threat_map", boom)
    target = Target(
        target_id="f",
        name="f",
        kind="repo",
        languages=["python"],
        source=str(FIXTURE_REPO),
        snapshot="x",
    )
    model = ScriptedModel(default=action("dismiss", reason="no"))
    analyzer = ServiceAnalyzer(
        _settings(tmp_path / "ws", planner_enabled=False), model=model, executor=FakeExecutor()
    )
    result = analyzer.run("scn_boom", target, ScanOptions())
    assert result.stages[2].status == "ok"
    assert (
        result.stages[2].summary == "threat map failed (RuntimeError: engine bug); SAST order kept"
    )
    assert result.stages[3].status == "ok" and model.n_calls == 3  # the scan still ran
    assert "file: app/util.py\n  line: 5\n" in model.calls[0]["messages"][1]["content"]


def test_taint_engine_failure_on_one_file_is_counted_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ok.py").write_text('@app.route("/x")\ndef h():\n    eval(request.args["e"])\n')
    (tmp_path / "bad.py").write_text("x = 1\n")
    import ono.planning.threatmap as tm_module

    real = tm_module.analyze_module

    def flaky(module: Any) -> Any:
        if module.file == "bad.py":
            raise ValueError("engine bug")
        return real(module)

    monkeypatch.setattr(tm_module, "analyze_module", flaky)
    result = threat_map(tmp_path, [], max_candidates=5)
    assert [(c.file, c.line, c.reach) for c in result.queue] == [("ok.py", 3, "direct")]
    assert result.parse_errors == 1 and "1 file(s) with parse errors" in result.summary()


@pytest.mark.usefixtures("_offline")
def test_threat_map_can_be_disabled(tmp_path: Path) -> None:
    target = Target(
        target_id="f",
        name="f",
        kind="repo",
        languages=["python"],
        source=str(FIXTURE_REPO),
        snapshot="x",
    )
    model = ScriptedModel(default=action("dismiss", reason="no"))
    analyzer = ServiceAnalyzer(
        _settings(tmp_path / "ws", planner_enabled=False, threat_map_enabled=False),
        model=model,
        executor=FakeExecutor(),
    )
    result = analyzer.run("scn_off", target, ScanOptions())
    assert result.stages[2].summary.startswith("analyst app/util.py:5 (CWE-502)")  # SAST order kept
    assert analyzer.last_threat_map is None and model.n_calls == 3


# ---------------------------------------------------------------------------
# Corpus scoring helpers
# ---------------------------------------------------------------------------


def test_planted_markers_and_scoring(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "x = 1  # VULN: CWE-89 regex-miss\ny = 2\nz = 3  # VULN: CWE-78\n"
    )
    (tmp_path / "b.js").write_text("eval(x) // VULN: CWE-95 known-gap extra\n")
    planted = planted_vulns(tmp_path)
    assert planted == [
        Planted("a.py", 1, "CWE-89", frozenset({"regex-miss"})),
        Planted("a.py", 3, "CWE-78", frozenset()),
        Planted("b.js", 1, "CWE-95", frozenset({"known-gap", "extra"})),
    ]
    found = [
        Candidate("a.py", 1, "CWE-89", "r", reach="direct"),
        Candidate(
            "a.py", 2, "CWE-78", "r", reach="dynamic"
        ),  # one line off: FP + FN at tolerance 0
        Candidate("c.py", 9, "CWE-89", "r"),
    ]
    s = score("e", planted, found)
    assert (s.tp, s.fp, s.fn) == (1, 2, 2) and s.recall == pytest.approx(1 / 3)
    assert s.precision == pytest.approx(1 / 3) and s.by_reach() == {
        "direct": (1, 0),
        "dynamic": (0, 1),
        "(none)": (0, 1),
    }
    assert s.restricted("javascript").missed == [planted[2]]
    tolerant = score("e", planted, found, tolerance=1)
    assert (tolerant.tp, tolerant.fp, tolerant.fn) == (2, 1, 1)
    movement = compare(s, tolerant)
    assert (
        movement.fixed == [planted[1]]
        and movement.regressed == []
        and len(movement.removed_false_positives) == 1
    )
    table = render_table([s, tolerant])
    assert table.splitlines()[2] == "| e | all | 1 | 2 | 2 | 33% | 33% | 0.33 |"
