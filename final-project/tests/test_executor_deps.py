"""Dependency provisioning: the builder flags, the in-builder installer, ``provision()``
on the fake Docker, the Executor route + client, the oracle's ``sys_path`` and the
verifier's fallback behaviour. Real containers: ``test_executor_docker.py`` and
``test_verifier_fixtures_docker.py``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import shutil
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from agentfakes import FakeExecExecutor, ScriptedModel, action
from conftest import start_live_server
from fakedocker import FakeDocker, read_build_result
from fixturecases import FLASK_SQLI_CASE, SQLI_LOGIN_CASE
from ono.config import Settings
from ono.executor import _builder
from ono.executor._builder import (
    Build,
    find_manifests,
    is_pinned,
    manifest_install_sets,
    manifest_kind,
    nearest_manifests,
    plan_installs,
    plan_pipfile,
    plan_pyproject,
    plan_setup_cfg,
    poetry_constraint,
    requirement_lines,
    requirement_name,
)
from ono.executor.app import create_executor_app
from ono.executor.archive import pack_workspace
from ono.executor.client import ExecutorClient, ExecutorRequestError
from ono.executor.models import SANDBOX_DEPS, ProvisionResult
from ono.executor.sandbox import (
    BUILD_SITE,
    BUILD_SRC,
    KEEPER_UID,
    KEEPER_USER,
    LABEL_BUILDER,
    LABEL_CREATED,
    LABEL_SANDBOX,
    LABEL_TTL,
    SANDBOX_USER,
    JailConfig,
    Sandbox,
    SandboxManager,
    builder_kwargs,
    jail_kwargs,
    snapshot_manifests,
)
from ono.models import Finding
from ono.verifier import GradedVerifier
from ono.verifier._oracle import run_oracle
from ono.verifier.verify import environment_note

FIXTURES = Path(__file__).parent / "fixtures"
FLASK_APP = FIXTURES / "flask_sqli_app"
FASTAPI_APP = FIXTURES / "fastapi_cmd_app"
NO_MANIFEST_APP = FIXTURES / "sqli_login_app"
NESTED_FLASK_APP = FIXTURES / "nested_flask_app"
NESTED_SINK = "dockerized_labs/sqli_lab/app.py"
TOKEN = "unit-test-token-0123456789"


# ---------------------------------------------------------------------------
# 1. The builder flags: a jail with network, and nothing else relaxed
# ---------------------------------------------------------------------------


def test_builder_kwargs_are_the_jail_flags_plus_network() -> None:
    cfg = JailConfig(mem_mb=256, cpus=0.5, pids_limit=64, workspace_mb=128, deps_mb=64)
    jail = jail_kwargs(cfg, scan_id="scn_1", sandbox_id="sbx_1")
    bld = builder_kwargs(cfg, scan_id="scn_1", sandbox_id="sbx_1")
    assert bld["network_mode"] == "bridge" and jail["network_mode"] == "none"
    for flag in ("read_only", "cap_drop", "security_opt", "privileged", "init", "user"):
        assert bld[flag] == jail[flag], flag
    assert bld["cap_drop"] == ["ALL"] and bld["read_only"] is True
    assert bld["user"] == KEEPER_USER and KEEPER_UID != 0
    for limit in ("mem_limit", "memswap_limit", "nano_cpus", "pids_limit", "oom_score_adj"):
        assert bld[limit] == jail[limit], limit
    assert bld["mem_limit"] == "256m" and bld["memswap_limit"] == "256m"
    # bounded scratch only: the snapshot + install target, and pip's temp dir
    assert set(bld["tmpfs"]) == {"/build", "/tmp"}
    assert "size=192m" in bld["tmpfs"]["/build"] and "nosuid" in bld["tmpfs"]["/build"]
    assert "size=64m" in bld["tmpfs"]["/tmp"] and "nodev" in bld["tmpfs"]["/tmp"]
    # nothing from the host, ever - in particular no Docker socket
    for forbidden in ("volumes", "mounts", "binds", "devices", "device_requests", "ports"):
        assert forbidden not in bld
    assert "docker.sock" not in repr(bld)
    # pip never sees a cache, never self-upgrades, never prompts; index is PyPI by default
    env = bld["environment"]
    assert env["PIP_NO_CACHE_DIR"] == "1" and env["PIP_DISABLE_PIP_VERSION_CHECK"] == "1"
    assert env["PIP_NO_INPUT"] == "1" and "PIP_INDEX_URL" not in env
    assert "PIP_NO_INDEX" not in env  # the builder is the one place pip may fetch
    # labelled for the sweeper, with a TTL much shorter than a jail's
    labels = bld["labels"]
    assert labels[LABEL_SANDBOX] == "1" and labels[LABEL_BUILDER] == "1"
    assert float(labels[LABEL_TTL]) == 2 * cfg.deps_timeout_s + 180
    assert float(labels[LABEL_CREATED]) == pytest.approx(time.time(), abs=5)
    assert bld["name"].startswith("ono-bld-")


def test_builder_uses_the_configured_index_and_seccomp() -> None:
    cfg = JailConfig(deps_index_url="https://mirror.internal/simple", seccomp_profile="{}")
    bld = builder_kwargs(cfg, scan_id="s", sandbox_id="x")
    assert bld["environment"]["PIP_INDEX_URL"] == "https://mirror.internal/simple"
    assert bld["security_opt"] == ["no-new-privileges:true", "seccomp={}"]


def test_jail_gets_a_keeper_owned_deps_tmpfs_and_stays_network_none() -> None:
    cfg = JailConfig(deps_mb=96)
    kw = jail_kwargs(cfg, scan_id="s", sandbox_id="x")
    deps = kw["tmpfs"][SANDBOX_DEPS]
    assert f"uid={KEEPER_UID},gid={KEEPER_UID}" in deps and "mode=0755" in deps
    assert "size=96m" in deps and "nosuid" in deps and "nodev" in deps
    assert "rw,exec," in deps  # native wheels (.so) must be mmap'able; keeper-owned, so safe
    assert "exec" not in kw["tmpfs"]["/workspace"] and "exec" not in kw["tmpfs"]["/tmp"]
    assert kw["environment"]["PYTHONPATH"] == SANDBOX_DEPS
    assert kw["environment"]["PIP_NO_INDEX"] == "1"  # the jail's pip still cannot fetch
    assert kw["network_mode"] == "none" and kw["cap_drop"] == ["ALL"] and kw["read_only"]
    assert "docker.sock" not in repr(kw)


def test_jail_config_carries_the_deps_settings() -> None:
    s = Settings(
        _env_file=None,
        sandbox_deps_enabled=False,
        sandbox_deps_timeout_s=42,
        sandbox_deps_max_mb=33,
        sandbox_deps_index_url="https://pypi.example/simple",
    )
    cfg = JailConfig.from_settings(s)
    assert (cfg.deps_enabled, cfg.deps_timeout_s, cfg.deps_mb) == (False, 42.0, 33)
    assert cfg.deps_index_url == "https://pypi.example/simple"
    assert cfg.deps_max_bytes == 33_000_000
    defaults = JailConfig.from_settings(Settings(_env_file=None))
    assert defaults.deps_enabled is True and defaults.deps_mb == 256


# ---------------------------------------------------------------------------
# 2. The in-builder installer: detection + parsing (pure), then the build with a fake pip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("requirements.txt", "requirements"),
        ("requirements-dev.txt", "requirements"),
        ("requirements_test.txt", "requirements"),
        ("requirements/base.txt", "requirements"),
        ("backend/requirements.txt", "requirements"),
        ("./pyproject.toml", "pyproject"),
        ("setup.cfg", "setup_cfg"),
        ("setup.py", "setup_py"),
        ("Pipfile", "pipfile"),
        ("backend/pyproject.toml", None),  # project files only at the root
        ("a/b/requirements.txt", None),  # too deep
        (".venv/requirements.txt", None),
        ("node_modules/x/requirements.txt", None),
        ("requirements.md", None),
        ("app.py", None),
    ],
)
def test_manifest_kind(path: str, kind: str | None) -> None:
    assert manifest_kind(path) == kind


def test_find_manifests_orders_the_primary_file_first(tmp_path: Path) -> None:
    (tmp_path / "requirements-dev.txt").write_text("pytest\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "requirements.txt").write_text("flask\n")
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "requirements.txt").write_text("django\n")
    (tmp_path / "backend" / "deep").mkdir()
    (tmp_path / "backend" / "deep" / "requirements.txt").write_text("nope\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "requirements.txt").write_text("nope\n")
    assert find_manifests(str(tmp_path)) == [
        "requirements.txt",
        "pyproject.toml",
        "requirements-dev.txt",
        "backend/requirements.txt",
    ]
    assert find_manifests(str(NO_MANIFEST_APP)) == []
    assert find_manifests(str(FLASK_APP)) == ["requirements.txt"]


def test_requirement_lines_follow_nested_files_and_skip_options(tmp_path: Path) -> None:
    (tmp_path / "base.txt").write_text("flask>=3  # web\n--index-url https://x\n-c cons.txt\n")
    (tmp_path / "requirements.txt").write_text(
        "# comment\n\n-r base.txt\nrequests==2.32.3\ngunicorn ; python_version >= '3'\n"
    )
    assert requirement_lines(str(tmp_path / "requirements.txt")) == [
        "flask>=3",
        "requests==2.32.3",
        "gunicorn ; python_version >= '3'",
    ]
    assert requirement_lines(str(tmp_path / "missing.txt")) == []


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("*", ""),
        ("^1.2.3", ">=1.2.3,<2.0.0"),
        ("^0.2.3", ">=0.2.3,<0.3.0"),
        ("^0.0.3", ">=0.0.3,<0.0.4"),
        ("^2", ">=2,<3"),
        ("~1.2.3", ">=1.2.3,<1.3"),
        ("~1.2", ">=1.2,<1.3"),
        ("~1", ">=1,<2"),
        ("1.2.3", "==1.2.3"),
        (">=1,<2", ">=1,<2"),
        ("~=1.4", "~=1.4"),
    ],
)
def test_poetry_constraint(spec: str, expected: str) -> None:
    assert poetry_constraint(spec) == expected


def test_plan_pyproject_pep621_with_extras(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        textwrap.dedent(
            """
            [project]
            name = "svc"
            dependencies = ["fastapi>=0.115", "httpx"]
            [project.optional-dependencies]
            test = ["pytest>=8"]
            docs = ["sphinx"]
            """
        )
    )
    primary, secondary, warnings = plan_pyproject(str(path))
    assert primary == ["fastapi>=0.115", "httpx"] and warnings == []
    assert [(s.label, s.args, s.primary) for s in secondary] == [
        ("pyproject.toml [test]", ["pytest>=8"], False)
    ]
    assert plan_pyproject(str(FASTAPI_APP / "pyproject.toml"))[0] == [
        "fastapi>=0.115,<1",
        "httpx>=0.27",
    ]


def test_plan_pyproject_poetry_and_dynamic(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        textwrap.dedent(
            """
            [tool.poetry]
            name = "svc"
            [tool.poetry.dependencies]
            python = "^3.10"
            flask = "^3.0"
            requests = { version = "~2.31", extras = ["socks"] }
            private = { git = "https://example/private.git" }
            optional-thing = { version = "*", optional = true }
            uvloop = { version = ">=0.19", markers = "sys_platform != 'win32'" }
            [tool.poetry.group.dev.dependencies]
            pytest = "^8"
            [tool.poetry.dev-dependencies]
            black = "*"
            """
        )
    )
    primary, secondary, _ = plan_pyproject(str(path))
    assert primary == [
        "flask>=3.0,<4.0",
        "requests[socks]>=2.31,<2.32",
        "uvloop>=0.19; sys_platform != 'win32'",
    ]
    assert [s.args for s in secondary] == [["pytest>=8,<9"], ["black"]]
    path.write_text('[project]\nname = "svc"\ndynamic = ["dependencies"]\n')
    assert plan_pyproject(str(path))[0] is None
    path.write_text("not = [toml")
    primary, _, warnings = plan_pyproject(str(path))
    assert primary is None and "not valid TOML" in warnings[0]


def test_plan_setup_cfg_and_pipfile(tmp_path: Path) -> None:
    cfg = tmp_path / "setup.cfg"
    cfg.write_text(
        "[options]\ninstall_requires =\n    django>=4  # web\n    celery; python_version>'3'\n"
        "[options.extras_require]\ntest = pytest\n"
    )
    primary, secondary = plan_setup_cfg(str(cfg))
    assert primary == ["django>=4", "celery; python_version>'3'"]
    assert [(s.label, s.args) for s in secondary] == [("setup.cfg [test]", ["pytest"])]
    assert plan_setup_cfg(str(tmp_path / "missing.cfg")) == (None, [])
    pipfile = tmp_path / "Pipfile"
    pipfile.write_text(
        '[packages]\nflask = "*"\nrequests = "==2.32.3"\n'
        'sqlalchemy = { version = ">=2", extras = ["asyncio"] }\n'
        'local = { path = "." }\n[dev-packages]\npytest = "*"\n'
    )
    primary, secondary = plan_pipfile(str(pipfile))
    assert primary == ["flask", "requests==2.32.3", "sqlalchemy[asyncio]>=2"]
    assert [s.args for s in secondary] == [["pytest"]]


def test_plan_installs_priority(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname="x"\ndependencies=["django"]\n')
    sets, warnings, needs_build = plan_installs(str(tmp_path), find_manifests(str(tmp_path)))
    # requirements.txt wins as the primary; pyproject's list is NOT installed on top of it
    assert [(s.label, s.primary) for s in sets] == [
        ("requirements.txt", True),
        ("requirements-dev.txt", False),
    ]
    assert sets[0].args == ["-r", str(tmp_path / "requirements.txt")]
    assert warnings == [] and needs_build is False
    # a setup.py-only project has nothing static: it must be built for its metadata
    shutil.rmtree(tmp_path / "requirements.txt", ignore_errors=True)
    for name in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        (tmp_path / name).unlink()
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup(name='x')\n")
    sets, _, needs_build = plan_installs(str(tmp_path), find_manifests(str(tmp_path)))
    assert sets == [] and needs_build is True
    # ... unless setup.cfg declares install_requires statically
    (tmp_path / "setup.cfg").write_text("[options]\ninstall_requires = click\n")
    sets, _, needs_build = plan_installs(str(tmp_path), find_manifests(str(tmp_path)))
    assert [s.args for s in sets] == [["click"]] and needs_build is False


def test_nearest_manifests_walks_up_from_the_sink(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("django\n")
    lab = tmp_path / "dockerized_labs" / "sqli_lab"
    lab.mkdir(parents=True)
    (lab / "requirements.txt").write_text("flask\n")
    (lab / "app.py").write_text("x = 1\n")
    # the lab's OWN manifest wins for a sink inside it ...
    assert nearest_manifests(str(tmp_path), NESTED_SINK) == [
        "dockerized_labs/sqli_lab/requirements.txt"
    ]
    # ... a sink with no nearer manifest falls back to the repository root ...
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "x.py").write_text("x = 1\n")
    assert nearest_manifests(str(tmp_path), "other/x.py") == ["requirements.txt"]
    # ... and a tree with no manifest at all yields nothing.
    bare = tmp_path / "bare"
    (bare / "pkg").mkdir(parents=True)
    (bare / "pkg" / "m.py").write_text("x = 1\n")
    assert nearest_manifests(str(bare), "pkg/m.py") == []


def test_manifest_install_sets_for_a_nested_requirements(tmp_path: Path) -> None:
    lab = tmp_path / "labs" / "a"
    lab.mkdir(parents=True)
    (lab / "requirements.txt").write_text("flask>=3\n")
    sets, needs_build = manifest_install_sets(
        str(tmp_path), "labs/a/requirements.txt", primary=True
    )
    assert needs_build is False
    assert [(s.label, s.primary) for s in sets] == [("labs/a/requirements.txt", True)]
    assert sets[0].args == ["-r", str(lab / "requirements.txt")]


def test_build_provisions_from_the_nearest_manifest(tmp_path: Path) -> None:
    """The headline of the manifest fix: a Django root + a nested Flask lab provisions BOTH
    (Flask from the lab's own manifest, as PRIMARY, unioned with the root Django); without
    ``near`` the root scan sees only Django and the Flask lab would die at import."""
    src, site = tmp_path / "src", tmp_path / "site"
    shutil.copytree(NESTED_FLASK_APP, src)
    site.mkdir()
    result = Build(_build_config(src, site, near=[NESTED_SINK]), FakePip(site)).run()
    assert result["status"] == "provisioned", result
    installed = {p.split()[0].lower() for p in result["installed"]}
    assert "flask" in installed and "django" in installed  # nearest + root union
    # the nearest (nested) manifest is installed FIRST, as the primary set
    assert result["installed_from"][0] == "dockerized_labs/sqli_lab/requirements.txt"
    assert result["manifests"][0] == "dockerized_labs/sqli_lab/requirements.txt"
    # WITHOUT near (the pre-fix behaviour) the depth-bounded root scan sees only Django
    shutil.rmtree(site)
    site.mkdir()
    before = Build(_build_config(src, site), FakePip(site)).run()
    assert {p.split()[0].lower() for p in before["installed"]} == {"django"}


def test_provision_from_nearest_manifest_on_the_fake_docker(
    manager: SandboxManager, fake: FakeDocker
) -> None:
    sbx = manager.create("scn_near", NESTED_FLASK_APP)
    result = sbx.provision(near=[NESTED_SINK])
    assert result.status == "provisioned", result
    names = {p.split()[0].lower() for p in result.installed}
    assert "flask" in names and "django" in names
    assert "dockerized_labs/sqli_lab/requirements.txt" in result.manifests


def test_requirement_name_and_pins() -> None:
    assert requirement_name("Flask[async]>=2 ; python_version>'3'") == "Flask[async]"
    assert requirement_name("requests==2.32.3") == "requests"
    assert requirement_name("git+https://x/y.git") is None
    assert requirement_name("./local") is None and requirement_name("-e .") is None
    assert requirement_name("pkg @ https://x/pkg.whl") is None
    assert is_pinned("flask==3.0") and is_pinned("flask>=3,<4") and is_pinned("x~=1.2")
    assert not is_pinned("flask") and not is_pinned("flask[async]")


class FakePip:
    """A scripted pip: records calls, refuses what it is told to, lays down packages."""

    def __init__(self, site: Path, *, refuse: set[str] | None = None) -> None:
        self.site = site
        self.refuse = refuse or set()
        self.calls: list[list[str]] = []
        self.sleep_s = 0.0
        self.package_bytes = 32

    def __call__(self, args: list[str], timeout_s: float) -> tuple[int, str]:
        self.calls.append(list(args))
        if self.sleep_s:  # like the real runner: killed at the deadline, reported as 124
            time.sleep(min(self.sleep_s, timeout_s))
            if self.sleep_s > timeout_s:
                return 124, "pip timed out"
        reqs: list[str] = []
        i = 0
        while i < len(args):
            if args[i] == "-r":
                reqs.extend(requirement_lines(args[i + 1]))
                i += 2
            else:
                reqs.append(args[i])
                i += 1
        for req in reqs:
            if req in self.refuse:
                return 1, f"ERROR: No matching distribution found for {req}\n"
            name = requirement_name(req)
            if name is None:
                return 1, f"ERROR: cannot install {req}\n"
            bare = name.split("[")[0].lower()
            (self.site / bare).mkdir(parents=True, exist_ok=True)
            (self.site / bare / "__init__.py").write_text("x" * self.package_bytes)
            info = self.site / f"{bare}-1.0.dist-info"
            info.mkdir(exist_ok=True)
            (info / "METADATA").write_text(f"Name: {bare}\nVersion: 1.0\n")
        return 0, "ok\n"


def _build_config(src: Path, site: Path, **extra: Any) -> dict[str, Any]:
    return {"src": str(src), "site": str(site), "max_bytes": 10_000, "timeout_s": 30, **extra}


def test_build_installs_primary_then_secondary(tmp_path: Path) -> None:
    src, site = tmp_path / "src", tmp_path / "site"
    shutil.copytree(FLASK_APP, src)
    (src / "requirements-dev.txt").write_text("pytest\n")
    site.mkdir()
    pip = FakePip(site)
    result = Build(_build_config(src, site), pip).run()
    assert result["status"] == "provisioned" and result["ok"] is True
    assert result["manifests"] == ["requirements.txt", "requirements-dev.txt"]
    assert result["installed_from"] == ["requirements.txt", "requirements-dev.txt"]
    assert result["installed"] == ["flask 1.0", "pytest 1.0"]
    assert result["failed"] == [] and result["relaxed"] == [] and result["error"] == ""
    assert result["size_bytes"] > 0
    assert pip.calls == [
        ["-r", str(src / "requirements.txt")],
        ["-r", str(src / "requirements-dev.txt")],
    ]


def test_build_falls_back_per_line_and_relaxes_a_bad_pin(tmp_path: Path) -> None:
    src, site = tmp_path / "src", tmp_path / "site"
    src.mkdir()
    site.mkdir()
    (src / "requirements.txt").write_text("flask>=3\npsycopg2==2.9.9\nuwsgi\n")
    pip = FakePip(site, refuse={"psycopg2==2.9.9", "uwsgi"})
    result = Build(_build_config(src, site), pip).run()
    assert result["status"] == "provisioned"
    assert result["installed"] == ["flask 1.0", "psycopg2 1.0"]
    assert result["relaxed"] == ["psycopg2==2.9.9"]  # the pin failed, the bare name worked
    assert result["failed"] == [
        "uwsgi (requirements.txt): ERROR: No matching distribution found for uwsgi"
    ]
    assert result["installed_from"] == ["requirements.txt (partial)"]
    # the whole file first, then line by line, then the relaxed retry
    assert pip.calls[0] == ["-r", str(src / "requirements.txt")]
    assert pip.calls[1:] == [["flask>=3"], ["psycopg2==2.9.9"], ["psycopg2"], ["uwsgi"]]


def test_build_fails_honestly(tmp_path: Path) -> None:
    src, site = tmp_path / "src", tmp_path / "site"
    src.mkdir()
    site.mkdir()
    # nothing installable at all
    (src / "requirements.txt").write_text("nope\n")
    result = Build(_build_config(src, site), FakePip(site, refuse={"nope"})).run()
    assert result["status"] == "failed" and result["ok"] is False
    assert "nothing could be installed" in result["error"] and result["installed"] == []
    # over the size cap
    (src / "requirements.txt").write_text("big\n")
    pip = FakePip(site)
    pip.package_bytes = 20_000
    result = Build(_build_config(src, site), pip).run()
    assert result["status"] == "failed" and "above the cap" in result["error"]
    # out of time
    shutil.rmtree(site)
    site.mkdir()
    (src / "requirements.txt").write_text("slow\nslower\n")
    pip = FakePip(site)
    pip.sleep_s = 0.3
    result = Build(_build_config(src, site, timeout_s=0.2), pip).run()
    assert result["status"] == "failed" and "timed out" in result["error"]
    # no manifest: skipped, never a failure
    for name in ("requirements.txt",):
        (src / name).unlink()
    result = Build(_build_config(src, site), FakePip(site)).run()
    assert result["status"] == "skipped" and result["manifests"] == []
    # a failing secondary set is only a warning
    (src / "requirements.txt").write_text("flask\n")
    (src / "requirements-dev.txt").write_text("broken\n")
    result = Build(_build_config(src, site), FakePip(site, refuse={"broken"})).run()
    assert result["status"] == "provisioned"
    assert result["warnings"] == ["requirements-dev.txt: could not be installed (optional)"]


def test_builder_main_prints_one_result_line(tmp_path: Path) -> None:
    src, site = tmp_path / "src", tmp_path / "site"
    shutil.copytree(FASTAPI_APP, src)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = _builder.main([json.dumps(_build_config(src, site))], pip=FakePip(site))
    assert code == 0
    data = read_build_result(out.getvalue().encode())
    assert data["status"] == "provisioned" and data["manifests"] == ["pyproject.toml"]
    assert data["installed_from"] == ["pyproject.toml", "pyproject.toml [test]"]
    assert {p.split()[0] for p in data["installed"]} == {"fastapi", "httpx", "pytest"}
    with contextlib.redirect_stdout(out := io.StringIO()):
        assert _builder.main([]) == 2
    assert read_build_result(out.getvalue().encode())["ok"] is False
    with contextlib.redirect_stdout(out := io.StringIO()):
        assert _builder.main(["{not json"]) == 0
    assert "JSONDecodeError" in read_build_result(out.getvalue().encode())["error"]


# ---------------------------------------------------------------------------
# 3. provision() on the fake Docker: the whole path minus the daemon
# ---------------------------------------------------------------------------


@pytest.fixture
def fake(tmp_path: Path) -> FakeDocker:
    return FakeDocker(tmp_path / "jails")


@pytest.fixture
def manager(fake: FakeDocker) -> SandboxManager:
    return SandboxManager(
        JailConfig(cmd_timeout_s=10, output_cap_bytes=4096, deps_mb=1, deps_timeout_s=30), fake
    )


def _builder_execs(fake: FakeDocker, cid: str) -> list[list[str]]:
    return [e.cmd for e in fake.exec_log if e.container_id == cid]


def test_provision_builds_in_a_separate_container_and_ships_read_only(
    manager: SandboxManager, fake: FakeDocker
) -> None:
    sbx = manager.create("scn_deps", FLASK_APP)
    jail_cid = sbx.container_id
    assert jail_cid is not None and sbx.info().provisioned is False
    result = sbx.provision()
    assert result.status == "provisioned", result
    assert result.manifests == ["requirements.txt"] and result.installed == ["flask 1.0"]
    assert result.installed_from == ["requirements.txt"] and result.size_bytes > 0
    assert result.summary == "provisioned 1 package(s) from requirements.txt"
    # a SECOND container was used for the build - and it is gone
    assert len(fake.builders) == 1
    bld = fake.builders[0]
    assert bld != jail_cid and bld in fake.removed and bld not in fake.live
    bld_kwargs = next(kw for kw in fake.run_calls if kw["labels"].get(LABEL_BUILDER) == "1")
    assert bld_kwargs["network_mode"] == "bridge" and bld_kwargs["cap_drop"] == ["ALL"]
    assert bld_kwargs["read_only"] is True and "docker.sock" not in repr(bld_kwargs)
    # inside the builder: snapshot in, installer run as the sandbox user, site tarred out
    execs = _builder_execs(fake, bld)
    assert execs[0][:2] == ["sh", "-c"] and f"-C {BUILD_SRC}" in execs[0][2]
    assert execs[1][:3] == ["timeout", "-s", "KILL"] and execs[1][4:7] == ["python3", "-I", "-c"]
    assert json.loads(execs[1][8])["site"] == BUILD_SITE
    assert execs[2] == ["tar", "-cz", "-C", BUILD_SITE, "."]
    assert all(e.user == SANDBOX_USER for e in fake.exec_log if e.container_id == bld)
    # ... and into the jail as the KEEPER, into /deps: the inmate can read, not write
    ship = [e for e in fake.exec_log if e.container_id == jail_cid and e.user == KEEPER_USER]
    assert [e.cmd[0] for e in ship] == ["sh", "tar"]
    assert "find /deps -mindepth 1 -delete" in ship[0].cmd[2]
    assert ship[1].cmd[ship[1].cmd.index("-C") + 1] == SANDBOX_DEPS
    assert (fake.deps_dir(jail_cid) / "flask" / "__init__.py").is_file()
    assert not (fake.workspace(jail_cid) / "flask").exists()  # never into the workspace
    # bookkeeping: the deps archive is a validated on-disk snapshot next to the workspace's
    assert sbx.deps is not None and sbx.deps.path.parent == manager.snapshot_dir
    assert sbx.deps.path.is_file() and sbx.info().provisioned is True
    # the jail's own container was NOT recreated, and it is still network-none
    assert sbx.container_id == jail_cid and sbx.status == "running"
    assert fake.run_calls[0]["network_mode"] == "none"
    # reset() re-extracts the deps into the fresh jail
    sbx.reset()
    assert sbx.container_id != jail_cid
    assert (fake.deps_dir(sbx.container_id or "") / "flask").is_dir()
    ship = [e for e in fake.exec_log if e.container_id == sbx.container_id and e.cmd[0] == "tar"]
    assert [e.user for e in ship] == [SANDBOX_USER, KEEPER_USER]
    # destroy() removes both snapshots
    deps_path = sbx.deps.path
    sbx.destroy()
    assert not deps_path.exists() and list(manager.snapshot_dir.iterdir()) == []


def test_provision_skips_without_a_manifest_and_starts_no_builder(
    manager: SandboxManager, fake: FakeDocker
) -> None:
    sbx = manager.create("scn_nodeps", NO_MANIFEST_APP)
    result = sbx.provision()
    assert result.status == "skipped" and "no dependency manifest" in result.detail
    assert fake.builders == [] and len(fake.run_calls) == 1
    assert sbx.deps is None and sbx.status == "running" and sbx.info().provisioned is False
    assert sbx.read_file("app/server.py").content  # the jail is untouched
    assert result.summary.startswith("skipped: no dependency manifest")


def test_provision_is_refused_when_disabled(fake: FakeDocker) -> None:
    off = SandboxManager(JailConfig(deps_enabled=False), fake)
    sbx = off.create("scn_off", FLASK_APP)
    result = sbx.provision()
    assert result.status == "disabled" and "SANDBOX_DEPS_ENABLED" in result.detail
    assert fake.builders == [] and sbx.deps is None and sbx.status == "running"


def test_failed_build_leaves_the_jail_without_deps_and_no_builder_behind(
    manager: SandboxManager, fake: FakeDocker
) -> None:
    sbx = manager.create("scn_fail", FLASK_APP)
    fake.pip_fail_all = True
    result = sbx.provision()
    assert result.status == "failed" and "nothing could be installed" in result.detail
    assert result.manifests == ["requirements.txt"] and result.installed == []
    assert len(fake.builders) == 1 and fake.builders[0] in fake.removed
    assert sbx.deps is None and sbx.status == "running" and sbx.info().provisioned is False
    assert not any(e.user == KEEPER_USER for e in fake.exec_log)  # nothing was shipped
    assert [p.name for p in manager.snapshot_dir.iterdir()] == [f"{sbx.sandbox_id}.tar.gz"]
    assert sbx.run("true").exit_code == 0  # the jail still works


def test_oversized_build_is_discarded(manager: SandboxManager, fake: FakeDocker) -> None:
    sbx = manager.create("scn_big", FLASK_APP)
    fake.pip_package_bytes = 2_000_000  # > deps_mb=1 -> 1_000_000 bytes
    result = sbx.provision()
    assert result.status == "failed" and "cap" in result.detail
    assert sbx.deps is None and fake.builders[0] in fake.removed
    assert [p.name for p in manager.snapshot_dir.iterdir()] == [f"{sbx.sandbox_id}.tar.gz"]


def test_builder_that_produces_no_result_is_a_failed_build(
    manager: SandboxManager, fake: FakeDocker
) -> None:
    sbx = manager.create("scn_junk", FLASK_APP)
    fake.build_result_override = "Traceback: the installer blew up\n"
    result = sbx.provision()
    assert result.status == "failed" and "produced no result" in result.detail
    assert sbx.deps is None and sbx.status == "running"
    fake.build_result_override = (
        f'{_builder.RESULT_MARKER}{{"ok": false, "status": "failed", "error": "boom"}}'
    )
    result = sbx.provision()
    assert result.status == "failed" and result.detail == "boom"
    assert fake.builders and all(b in fake.removed for b in fake.builders)


def test_builder_start_failure_is_a_failed_build(manager: SandboxManager, fake: FakeDocker) -> None:
    from fakedocker import api_error

    sbx = manager.create("scn_nostart", FLASK_APP)
    fake.run_error = api_error(500, "no space on the daemon")
    result = sbx.provision()
    assert result.status == "failed" and "could not start the builder" in result.detail
    assert sbx.status == "running" and sbx.deps is None


def test_destroy_during_a_build_removes_the_builder_too(
    manager: SandboxManager, fake: FakeDocker
) -> None:
    sbx = manager.create("scn_race", FLASK_APP)
    seen: dict[str, str] = {}

    def pip(args: list[str], site: Path) -> tuple[int, str]:
        seen["builder"] = fake.builders[-1]
        assert fake.builders[-1] in fake.live
        sbx.destroy()  # teardown wins over the in-flight build
        return fake.fake_pip(args, site)

    fake.pip_handler = pip
    result = sbx.provision()
    assert result.status != "provisioned"
    assert seen["builder"] in fake.removed and not fake.live and sbx.status == "destroyed"


def test_reprovision_replaces_the_previous_set(manager: SandboxManager, fake: FakeDocker) -> None:
    sbx = manager.create("scn_again", FLASK_APP)
    first = sbx.provision()
    assert first.status == "provisioned" and sbx.deps is not None
    first_path = sbx.deps.path
    (fake.container_dir(sbx.container_id or "", "/deps") / "stale").mkdir()
    second = sbx.provision()
    assert second.status == "provisioned" and sbx.deps is not None
    assert sbx.deps.path != first_path and not first_path.exists()
    assert not (fake.deps_dir(sbx.container_id or "") / "stale").exists()


def test_snapshot_manifests_scans_headers(manager: SandboxManager) -> None:
    sbx = manager.create("scn_scan", FASTAPI_APP)
    assert snapshot_manifests(sbx.snapshot) == ["pyproject.toml"]
    sbx2 = manager.create("scn_scan2", NO_MANIFEST_APP)
    assert snapshot_manifests(sbx2.snapshot) == []


def test_sweeper_honours_a_shorter_ttl_label(manager: SandboxManager, fake: FakeDocker) -> None:
    """An orphaned builder (Executor died mid-build) is swept on ITS ttl, not the jail's."""
    stale = fake.add_orphan(
        "b" * 64,
        {
            LABEL_SANDBOX: "1",
            LABEL_BUILDER: "1",
            LABEL_TTL: "60",
            LABEL_CREATED: str(time.time() - 120),
        },
        "",
    )
    fresh = fake.add_orphan(
        "f" * 64,
        {
            LABEL_SANDBOX: "1",
            LABEL_BUILDER: "1",
            LABEL_TTL: "60",
            LABEL_CREATED: str(time.time() - 10),
        },
        "",
    )
    jail = fake.add_orphan(
        "j" * 64, {LABEL_SANDBOX: "1", LABEL_CREATED: str(time.time() - 120)}, ""
    )
    removed = manager.sweep()  # ttl_s=1800 for jails
    assert stale.id in removed and fresh.id not in removed and jail.id not in removed
    bad = fake.add_orphan(
        "x" * 64, {LABEL_SANDBOX: "1", LABEL_TTL: "nope", LABEL_CREATED: str(time.time() - 120)}, ""
    )
    assert bad.id not in manager.sweep()  # an unparsable label falls back to the jail ttl


# ---------------------------------------------------------------------------
# 4. The Executor route and the typed client
# ---------------------------------------------------------------------------


def test_provision_route_and_client(fake: FakeDocker, tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None, executor_token=SecretStr(TOKEN), max_clone_mb=1, sandbox_deps_max_mb=8
    )
    manager = SandboxManager(
        dataclasses.replace(JailConfig.from_settings(settings), cmd_timeout_s=5.0), fake
    )
    app = create_executor_app(settings, manager)
    auth = {"Authorization": f"Bearer {TOKEN}"}
    with TestClient(app) as api:
        r = api.post(
            "/sandboxes",
            params={"scan_id": "scn_route"},
            content=pack_workspace(FLASK_APP, max_bytes=10**7),
            headers={**auth, "Content-Type": "application/gzip"},
        )
        sid = r.json()["sandbox_id"]
        assert api.post(f"/sandboxes/{sid}/provision").status_code == 401
        r = api.post(f"/sandboxes/{sid}/provision", headers=auth)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "provisioned" and body["installed"] == ["flask 1.0"]
        assert api.get(f"/sandboxes/{sid}", headers=auth).json()["provisioned"] is True
        assert api.post("/sandboxes/sbx_nope/provision", headers=auth).status_code == 404
        r = api.post(f"/sandboxes/{sid}/provision", json={"timeout_s": 0}, headers=auth)
        assert r.status_code == 422
        r = api.post(f"/sandboxes/{sid}/provision", json={"bogus": 1}, headers=auth)
        assert r.status_code == 422
    # the typed client, over real HTTP against the same app
    live = start_live_server(app)
    try:
        with ExecutorClient(live.url, TOKEN, timeout_s=30) as client:
            info = client.create("scn_client", FLASK_APP)
            result = client.provision(info.sandbox_id, timeout_s=20)
            assert isinstance(result, ProvisionResult) and result.status == "provisioned"
            assert client.get(info.sandbox_id).provisioned is True
            with pytest.raises(ExecutorRequestError):
                client._request(
                    "POST", f"/sandboxes/{info.sandbox_id}/provision", json={"timeout_s": -1}
                )
            client.destroy(info.sandbox_id)
    finally:
        live.stop()


# ---------------------------------------------------------------------------
# 5. The oracle puts /deps on sys.path (after the workspace), only if it exists
# ---------------------------------------------------------------------------


def test_oracle_appends_existing_sys_path_entries(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    deps = tmp_path / "deps"
    (root / ".ono").mkdir(parents=True)
    (deps / "thirdparty").mkdir(parents=True)
    (deps / "thirdparty" / "__init__.py").write_text("VALUE = 'from-deps'\n")
    (root / "app.py").write_text(
        "import os\nimport thirdparty\nos.system('echo ' + os.environ['ONO_PAYLOAD'])\n"
    )
    (root / ".ono" / "poc.py").write_text("import app\n")
    config = {
        "cwe": "CWE-78",
        "sink_file": "app.py",
        "line_start": 3,
        "line_end": 3,
        "canary": "ONOdeadbeef",
        "poc": str(root / ".ono" / "poc.py"),
        "sys_path": [str(deps), str(tmp_path / "missing")],
    }
    import sys

    before = list(sys.path)
    cwd = Path.cwd()
    try:
        result = run_oracle(config, str(root))
    finally:
        os.chdir(cwd)
        sys.path[:] = before
        sys.modules.pop("app", None)
        sys.modules.pop("thirdparty", None)
    assert result["fired"] is True, result
    assert result["poc_error"] == ""
    assert str(tmp_path / "missing") not in before


# ---------------------------------------------------------------------------
# 6. The verifier: records what provisioning did and falls back honestly
# ---------------------------------------------------------------------------

_NOOP_PATCH = "--- a/does/not/exist.py\n+++ b/does/not/exist.py\n@@ -1 +1 @@\n-x\n+y\n"


def _verifier_settings(workspace: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "model_backend": "service",
        "model_service_url": "http://model.test/v1",
        "executor_token": SecretStr(TOKEN),
        "workspace_dir": workspace,
        "context_lines": 6,
        "verifier_poc_timeout_s": 60.0,
        "max_verifier_retries": 1,
    }
    return Settings(_env_file=None, **{**base, **overrides})


def _script(poc: str) -> Any:
    from ono.agents.definitions import FIXER, PROVER

    def script(messages: list[dict[str, Any]], tools: Any) -> str:
        system = messages[0]["content"]
        if system == PROVER.system_prompt:
            return action("submit_poc", code=poc, how="drive the entry point")
        if system == FIXER.system_prompt:
            return action("submit_patch", diff=_NOOP_PATCH, summary="noop")
        raise AssertionError("unexpected role")

    return script


def _verify(tmp_path: Path, case: Any, **overrides: Any) -> tuple[Finding, FakeExecExecutor, Any]:
    workspace = tmp_path / f"ws_{case.name}"
    shutil.copytree(case.dir, workspace)
    executor = FakeExecExecutor()
    model = ScriptedModel(script=_script(case.honest_poc))
    verifier = GradedVerifier(
        _verifier_settings(tmp_path, **overrides), model=model, executor=executor
    )
    progress: list[str] = []
    report = verifier.verify(
        "scn_dep", workspace, [case.finding("scn_dep")], progress=progress.append
    )
    return report.findings[0], executor, (report, progress, model)


def test_verifier_records_a_skipped_provisioning_and_still_proves(tmp_path: Path) -> None:
    proven, executor, (report, progress, model) = _verify(tmp_path, SQLI_LOGIN_CASE)
    assert proven.verified is True and proven.rung >= 3
    assert proven.verification is not None
    assert proven.verification.dependencies.startswith("skipped: no dependency manifest")
    assert report.dependencies is not None and report.dependencies.status == "skipped"
    assert "dependencies skipped" in report.summary
    assert executor.sandboxes[0].provision_calls == 1
    assert any(m.startswith("Provisioning the target") for m in progress)
    assert any(m.startswith("Dependencies: skipped") for m in progress)
    prompt = next(m["content"] for m in model.calls[0]["messages"] if m["role"] == "user")
    assert "NO third-party packages are installed" in prompt


def test_verifier_falls_back_when_the_build_fails(tmp_path: Path) -> None:
    """A manifest but no builder (offline double): the finding is verified WITHOUT deps if it
    can be, and the record says exactly what happened."""
    proven, _executor, (report, _progress, model) = _verify(tmp_path, FLASK_SQLI_CASE)
    assert report.dependencies is not None and report.dependencies.status == "failed"
    assert proven.verification is not None
    assert proven.verification.dependencies.startswith("failed: the offline test sandbox")
    prompt = next(m["content"] for m in model.calls[0]["messages"] if m["role"] == "user")
    assert "NO third-party packages are installed (failed:" in prompt
    try:
        import flask  # noqa: F401
    except ImportError:
        # the honest before: the real Flask app cannot even be imported without its deps
        assert proven.verified is False and proven.rung <= 2
        check = proven.verification.check("poc_reaches_sink")
        assert check is not None and check.status == "failed"
        assert "the script raised: ModuleNotFoundError: No module named 'flask'" in check.detail
        assert "stub an optional/third-party dependency" in check.detail  # the hint survives


def test_verifier_skips_provisioning_when_disabled(tmp_path: Path) -> None:
    proven, executor, (report, progress, _model) = _verify(
        tmp_path, SQLI_LOGIN_CASE, sandbox_deps_enabled=False
    )
    assert executor.sandboxes[0].provision_calls == 0
    assert report.dependencies is not None and report.dependencies.status == "disabled"
    assert proven.verification is not None
    assert proven.verification.dependencies.startswith("disabled:")
    assert not any(m.startswith("Provisioning") for m in progress)
    assert proven.verified is True  # the stdlib fixture still proves


def test_verifier_treats_an_executor_without_the_route_as_a_failed_build(tmp_path: Path) -> None:
    from ono.executor.client import SandboxNotFoundError

    workspace = tmp_path / "ws_old"
    shutil.copytree(SQLI_LOGIN_CASE.dir, workspace)
    executor = FakeExecExecutor()

    class OldExecutor(FakeExecExecutor):
        @contextlib.contextmanager
        def sandbox(self, scan_id: str, workspace_dir: Path, *, runtime: str = "python") -> Any:
            with super().sandbox(scan_id, workspace_dir, runtime=runtime) as sbx:
                sbx.fail_with = SandboxNotFoundError("sandbox 'x' not found")
                yield sbx

    executor = OldExecutor()
    model = ScriptedModel(script=_script(SQLI_LOGIN_CASE.honest_poc))
    verifier = GradedVerifier(_verifier_settings(tmp_path), model=model, executor=executor)
    report = verifier.verify("scn_old", workspace, [SQLI_LOGIN_CASE.finding("scn_old")])
    assert report.dependencies is not None and report.dependencies.status == "failed"
    assert "could not provision" in report.dependencies.detail
    assert report.findings[0].verified is True  # the stage carried on


def test_environment_note_is_technique_not_an_answer_key() -> None:
    assert "NO third-party packages" in environment_note(None)
    ok = ProvisionResult(
        status="provisioned",
        installed=["flask 3.1.0", "jinja2 3.1.4"],
        installed_from=["requirements.txt"],
        failed=["psycopg2==2.9.9 (requirements.txt): no wheel"],
    )
    note = environment_note(ok)
    assert "ARE installed (from requirements.txt): flask 3.1.0, jinja2 3.1.4" in note
    assert "NOT installed (build failed): psycopg2==2.9.9" in note
    assert "ONO_PAYLOAD" not in note and "ONO" not in note.replace("ONO_", "")
    failed = ProvisionResult(status="failed", detail="pip exploded")
    assert "(failed: pip exploded)" in environment_note(failed)


def test_sandbox_exec_protocol_includes_provision(tmp_path: Path) -> None:
    from agentfakes import LocalExecSandbox
    from ono.agents.tools import SandboxExecutor

    workspace = tmp_path / "ws"
    shutil.copytree(NO_MANIFEST_APP, workspace)
    sbx: SandboxExecutor = LocalExecSandbox(workspace)  # structural check of the Protocol
    assert sbx.provision().status == "skipped"


def test_sandbox_dataclass_keeps_the_deps_snapshot_typed() -> None:
    assert Sandbox.__dataclass_fields__["deps"].type == "Snapshot | None"
