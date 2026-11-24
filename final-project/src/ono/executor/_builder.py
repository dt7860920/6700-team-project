"""In-builder dependency installer: runs INSIDE the ephemeral BUILDER container.

The Executor ships this module's *source text* into a hardened, network-enabled builder
container (see ``sandbox.builder_kwargs``) and runs::

    python3 -I -c "<this file>" '<json config>'

with the target's validated workspace snapshot extracted under ``config["src"]``. It then

1. **detects** the manifests the repository declares (``requirements*.txt``,
   ``pyproject.toml`` PEP 621 / poetry, ``setup.cfg``, ``setup.py``, ``Pipfile``);
2. turns them into ``pip install`` argument sets - a *primary* set (what the app needs to
   import) and *secondary*, best-effort sets (dev / test extras, other requirement files);
3. runs ``pip install --target <site>`` for each set under the remaining wall-clock budget,
   falling back to one requirement at a time when a whole file fails (one unbuildable pin
   must not cost the framework the app imports), then relaxing a failed *pinned* line to
   its bare name (a modern wheel usually still makes the app importable);
4. measures the installed size against the cap and prints ONE line
   ``ONO_BUILD_RESULT <json>`` describing what was installed, what failed, and why.

Everything here runs as an unprivileged user with no host mounts and no Docker socket; the
only artefact that leaves the builder is the ``<site>`` directory, tarred by the Executor
and validated like any workspace archive before it reaches a verification jail.

Stdlib only. Python >= 3.11 for ``tomllib`` (the builder image is pinned to 3.13); must stay
importable on the host - the Executor imports :func:`manifest_kind` to scan a snapshot's
member names, and the unit tests exercise the parsers directly.
"""

from __future__ import annotations

import configparser
import contextlib
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

RESULT_MARKER = "ONO_BUILD_RESULT "
PRIMARY_REQUIREMENTS = "requirements.txt"
_REQ_FILE = re.compile(r"^requirements[A-Za-z0-9._-]*\.txt$")
_SKIP_DIRS = frozenset({"node_modules", "venv", ".venv", "env", "build", "dist", "site-packages"})
_EXTRA_KEYS = ("test", "tests", "testing", "dev", "develop", "development")
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(\[[^\]]*\])?\s*(.*)$")
_PIN_RE = re.compile(r"^[<>=!~]")
_MAX_NESTED_REQ = 3
_OUTPUT_TAIL = 1200

PipRunner = Callable[[list[str], float], tuple[int, str]]
"""``(pip args after 'install', timeout_s) -> (exit code, combined output)``."""


# ---------------------------------------------------------------------------
# Manifest detection (shared with the Executor's snapshot scan)
# ---------------------------------------------------------------------------


def manifest_kind(rel: str) -> str | None:
    """Classify a workspace-relative path as a dependency manifest, or ``None``.

    Requirement files are accepted at the root and one directory down (``requirements/*.txt``,
    ``backend/requirements.txt``); project manifests (``pyproject.toml``, ``setup.cfg``,
    ``setup.py``, ``Pipfile``) only at the root, where they define the project. Hidden and
    vendored directories never count.
    """
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or len(parts) > 2:
        return None
    if any(p.startswith(".") or p in _SKIP_DIRS for p in parts[:-1]):
        return None
    name = parts[-1]
    if len(parts) == 2:
        if _REQ_FILE.match(name) or (parts[0] == "requirements" and name.endswith(".txt")):
            return "requirements"
        return None
    if _REQ_FILE.match(name):
        return "requirements"
    return {
        "pyproject.toml": "pyproject",
        "setup.cfg": "setup_cfg",
        "setup.py": "setup_py",
        "Pipfile": "pipfile",
        "package.json": "package_json",
    }.get(name)


_PROJECT_MANIFESTS = {
    "pyproject.toml": "pyproject",
    "setup.cfg": "setup_cfg",
    "setup.py": "setup_py",
    "Pipfile": "pipfile",
    "package.json": "package_json",
}

NODE_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
"""Presence of either selects ``npm ci`` over ``npm install`` (see ``Build._install_node``)."""


def basename_manifest_kind(name: str) -> str | None:
    """Classify a manifest by its BASENAME alone (any depth) - for nearest-to-sink walking.

    Unlike :func:`manifest_kind` (which bounds depth for the root scan), this accepts a
    project manifest wherever it sits, because walking up from a sink deliberately visits
    nested application directories (a Flask app under ``dockerized_labs/<lab>/``).
    """
    if _REQ_FILE.match(name):
        return "requirements"
    return _PROJECT_MANIFESTS.get(name)


def manifests_in_dir(root: str, rel_dir: str) -> list[str]:
    """Manifest files directly inside ``root/rel_dir`` (workspace-relative, sorted)."""
    abs_dir = os.path.join(root, rel_dir) if rel_dir else root
    try:
        names = sorted(os.listdir(abs_dir))
    except OSError:
        return []
    out: list[str] = []
    for name in names:
        if basename_manifest_kind(name) is None:
            continue
        if not os.path.isfile(os.path.join(abs_dir, name)):
            continue
        out.append(f"{rel_dir}/{name}" if rel_dir else name)
    return out


def nearest_manifests(root: str, sink_rel: str) -> list[str]:
    """Walk UP from the sink file's directory to ``root``; return the manifests in the CLOSEST
    ancestor directory that declares any. Empty if none exist between the sink and the root.

    This is what lets a nested app's OWN requirements win over an unrelated root manifest:
    a Flask sink in ``dockerized_labs/lab/app.py`` provisions ``dockerized_labs/lab/
    requirements.txt`` (Flask), not the Django ``requirements.txt`` at the repository root.
    """
    rel = sink_rel.replace("\\", "/").strip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    dirs = parts[:-1]  # drop the filename itself
    while True:
        found = manifests_in_dir(root, "/".join(dirs))
        if found:
            return found
        if not dirs:
            return []
        dirs = dirs[:-1]


def nearest_node_manifest(root: str, sink_rel: str) -> str | None:
    """Walk UP from the sink file's directory to ``root`` for the CLOSEST ``package.json``.

    Deliberately a separate walk from :func:`nearest_manifests` (which stops at the first
    ancestor declaring ANY manifest, Python or Node): a full-stack repo's sink-nearest
    directory may have a ``requirements.txt`` with no ``package.json`` while an ancestor
    above it has the frontend's own ``package.json`` - this walk does not stop early just
    because a Python manifest was found at a lower level.
    """
    rel = sink_rel.replace("\\", "/").strip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    dirs = parts[:-1]
    while True:
        rel_dir = "/".join(dirs)
        candidate = (
            os.path.join(root, rel_dir, "package.json")
            if rel_dir
            else os.path.join(root, "package.json")
        )
        if os.path.isfile(candidate):
            return f"{rel_dir}/package.json" if rel_dir else "package.json"
        if not dirs:
            return None
        dirs = dirs[:-1]


def manifest_install_sets(root: str, rel: str, *, primary: bool) -> tuple[list[InstallSet], bool]:
    """``(install sets, needs_build)`` for ONE manifest at ``rel`` (any depth). ``needs_build``
    means the file declares no static dependency list and its metadata must be built."""
    path = os.path.join(root, rel)
    kind = basename_manifest_kind(os.path.basename(rel))
    if kind == "requirements":
        reqs = requirement_lines(path)
        return [InstallSet(rel, args=["-r", path], requirements=reqs, primary=primary)], False
    if kind == "pyproject":
        prim, extra, _ = plan_pyproject(path)
        if prim is not None:
            return [InstallSet(rel, args=prim, requirements=prim, primary=primary), *extra], False
        return list(extra), True
    if kind == "setup_cfg":
        prim, extra = plan_setup_cfg(path)
        if prim is not None:
            return [InstallSet(rel, args=prim, requirements=prim, primary=primary), *extra], False
        return list(extra), True
    if kind == "pipfile":
        prim, extra = plan_pipfile(path)
        if prim is not None:
            return [InstallSet(rel, args=prim, requirements=prim, primary=primary), *extra], False
        return list(extra), False
    if kind == "setup_py":
        return [], True
    return [], False


def find_manifests(root: str) -> list[str]:
    """Every manifest under ``root`` (relative paths, sorted, root files first)."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        dirnames[:] = sorted(
            d for d in dirnames if depth < 1 and not d.startswith(".") and d not in _SKIP_DIRS
        )
        for name in sorted(filenames):
            rel = name if rel_dir == "." else os.path.join(rel_dir, name).replace(os.sep, "/")
            if manifest_kind(rel) is not None:
                found.append(rel)
    return sorted(found, key=lambda r: (r.count("/"), r != PRIMARY_REQUIREMENTS, r))


# ---------------------------------------------------------------------------
# Manifest parsers (pure; no code from the repository is executed here)
# ---------------------------------------------------------------------------


class InstallSet:
    """One ``pip install`` invocation: where the requirements came from and what to pass."""

    __slots__ = ("args", "label", "primary", "requirements")

    def __init__(
        self, label: str, *, args: list[str], requirements: list[str], primary: bool
    ) -> None:
        self.label = label
        self.args = args
        self.requirements = requirements  # the individual lines, for the per-line fallback
        self.primary = primary


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def requirement_lines(path: str, _depth: int = 0) -> list[str]:
    """The individual requirements of a pip requirements file (nested ``-r`` followed)."""
    lines: list[str] = []
    try:
        text = _read(path)
    except OSError:
        return lines
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].split("\t#", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")) and _depth < _MAX_NESTED_REQ:
            nested = os.path.join(os.path.dirname(path), line.split(None, 1)[1].strip())
            lines.extend(requirement_lines(nested, _depth + 1))
            continue
        if line.startswith("-"):  # -c / --index-url / --hash options: pip-level, not a package
            continue
        lines.append(line.rstrip("\\").strip())
    return lines


def _poetry_spec(name: str, value: Any) -> str | None:
    """A ``[tool.poetry.dependencies]`` entry as a PEP 508 string (``None`` = skip)."""
    if isinstance(value, list):
        value = value[0] if value else None
    extras = ""
    markers = ""
    if isinstance(value, dict):
        if value.get("optional") or any(k in value for k in ("git", "path", "url", "file")):
            return None
        if value.get("extras"):
            extras = "[" + ",".join(str(e) for e in value["extras"]) + "]"
        if value.get("markers"):
            markers = "; " + str(value["markers"])
        value = value.get("version", "*")
    if not isinstance(value, str):
        return None
    return f"{name}{extras}{poetry_constraint(value)}{markers}"


def poetry_constraint(spec: str) -> str:
    """Poetry's ``^`` / ``~`` / bare-version constraints as PEP 440 specifiers."""
    spec = spec.strip()
    if spec in ("", "*"):
        return ""

    def parts_of(version: str) -> list[int]:
        return [int(p) for p in version.split(".") if p.isdigit()]

    if spec.startswith("^"):
        version = spec[1:]
        nums = parts_of(version)
        if not nums:
            return ""
        upper = list(nums)
        bump = next((i for i, n in enumerate(nums) if n != 0), len(nums) - 1)
        upper[bump] += 1
        for i in range(bump + 1, len(upper)):
            upper[i] = 0
        return f">={version},<{'.'.join(map(str, upper))}"
    if spec.startswith("~") and not spec.startswith("~="):
        version = spec[1:]
        nums = parts_of(version)
        if not nums:
            return ""
        upper = list(nums[:2]) if len(nums) >= 2 else [nums[0]]
        upper[-1] += 1
        return f">={version},<{'.'.join(map(str, upper))}"
    if spec[0].isdigit():
        return f"=={spec}"
    return spec.replace(" ", "")


def _pipfile_spec(name: str, value: Any) -> str | None:
    extras = ""
    if isinstance(value, dict):
        if any(k in value for k in ("git", "path", "file", "url")):
            return None
        if value.get("extras"):
            extras = "[" + ",".join(str(e) for e in value["extras"]) + "]"
        value = value.get("version", "*")
    if not isinstance(value, str):
        return None
    spec = value.strip()
    return f"{name}{extras}" if spec in ("", "*") else f"{name}{extras}{spec}"


def _toml(path: str) -> dict[str, Any] | None:
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (OSError, ValueError):
        return None


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


def plan_pyproject(path: str) -> tuple[list[str] | None, list[InstallSet], list[str]]:
    """``(primary requirements or None, secondary sets, warnings)`` from a pyproject.toml.

    ``None`` as the primary means the file declares nothing static (no ``[project]``
    dependencies, or ``dynamic = ["dependencies"]``) and the project must be *built* for
    its metadata (:func:`build_metadata`).
    """
    data = _toml(path)
    warnings: list[str] = []
    if data is None:
        return None, [], [f"{os.path.basename(path)}: not valid TOML (ignored)"]
    secondary: list[InstallSet] = []
    primary: list[str] | None = None
    project = data.get("project")
    if isinstance(project, dict):
        if "dependencies" in project and "dependencies" not in _strings(project.get("dynamic")):
            primary = _strings(project.get("dependencies"))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for key in _EXTRA_KEYS:
                reqs = _strings(optional.get(key))
                if reqs:
                    secondary.append(
                        InstallSet(
                            f"pyproject.toml [{key}]", args=reqs, requirements=reqs, primary=False
                        )
                    )
    poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        deps = poetry.get("dependencies")
        if isinstance(deps, dict) and primary is None:
            primary = [
                spec
                for name, value in deps.items()
                if name.lower() != "python" and (spec := _poetry_spec(name, value)) is not None
            ]
        for group_name, group in (poetry.get("group") or {}).items():
            group_deps = group.get("dependencies") if isinstance(group, dict) else None
            if group_name in _EXTRA_KEYS and isinstance(group_deps, dict):
                reqs = [s for n, v in group_deps.items() if (s := _poetry_spec(n, v)) is not None]
                if reqs:
                    secondary.append(
                        InstallSet(
                            f"pyproject.toml poetry group {group_name}",
                            args=reqs,
                            requirements=reqs,
                            primary=False,
                        )
                    )
        dev = poetry.get("dev-dependencies")
        if isinstance(dev, dict):
            reqs = [s for n, v in dev.items() if (s := _poetry_spec(n, v)) is not None]
            if reqs:
                secondary.append(
                    InstallSet(
                        "pyproject.toml poetry dev-dependencies",
                        args=reqs,
                        requirements=reqs,
                        primary=False,
                    )
                )
    return primary, secondary, warnings


def plan_setup_cfg(path: str) -> tuple[list[str] | None, list[InstallSet]]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(_read(path))
    except (OSError, configparser.Error):
        return None, []
    primary: list[str] | None = None
    if parser.has_option("options", "install_requires"):
        primary = _cfg_list(parser.get("options", "install_requires"))
    secondary: list[InstallSet] = []
    if parser.has_section("options.extras_require"):
        for key in _EXTRA_KEYS:
            if parser.has_option("options.extras_require", key):
                reqs = _cfg_list(parser.get("options.extras_require", key))
                if reqs:
                    secondary.append(
                        InstallSet(
                            f"setup.cfg [{key}]", args=reqs, requirements=reqs, primary=False
                        )
                    )
    return primary, secondary


def _cfg_list(value: str) -> list[str]:
    """A newline-separated setup.cfg list (``;`` stays: it introduces PEP 508 markers)."""
    out: list[str] = []
    for raw in value.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def plan_pipfile(path: str) -> tuple[list[str] | None, list[InstallSet]]:
    data = _toml(path)
    if data is None:
        return None, []
    packages = data.get("packages")
    primary = (
        [s for n, v in packages.items() if (s := _pipfile_spec(n, v)) is not None]
        if isinstance(packages, dict)
        else None
    )
    secondary: list[InstallSet] = []
    dev = data.get("dev-packages")
    if isinstance(dev, dict):
        reqs = [s for n, v in dev.items() if (s := _pipfile_spec(n, v)) is not None]
        if reqs:
            secondary.append(
                InstallSet("Pipfile [dev-packages]", args=reqs, requirements=reqs, primary=False)
            )
    return primary, secondary


def plan_installs(root: str, manifests: list[str]) -> tuple[list[InstallSet], list[str], bool]:
    """Turn the detected manifests into ordered install sets.

    Returns ``(sets, warnings, needs_build)``: ``needs_build`` is true when the project
    declares no static dependency list but ships a ``setup.py`` / ``setup.cfg`` /
    ``pyproject.toml`` whose metadata must be *built* to learn the dependencies.
    """
    sets: list[InstallSet] = []
    warnings: list[str] = []
    kinds = {m: manifest_kind(m) for m in manifests}
    primary_done = False
    needs_build = False

    if PRIMARY_REQUIREMENTS in kinds:
        path = os.path.join(root, PRIMARY_REQUIREMENTS)
        sets.append(
            InstallSet(
                PRIMARY_REQUIREMENTS,
                args=["-r", path],
                requirements=requirement_lines(path),
                primary=True,
            )
        )
        primary_done = True

    secondary: list[InstallSet] = []
    if "pyproject.toml" in kinds:
        primary, extra, notes = plan_pyproject(os.path.join(root, "pyproject.toml"))
        warnings += notes
        if primary is not None and not primary_done:
            sets.append(
                InstallSet("pyproject.toml", args=primary, requirements=primary, primary=True)
            )
            primary_done = True
        elif primary is None and not primary_done:
            needs_build = True
        secondary += extra
    if "setup.cfg" in kinds:
        primary, extra = plan_setup_cfg(os.path.join(root, "setup.cfg"))
        if primary is not None and not primary_done:
            sets.append(InstallSet("setup.cfg", args=primary, requirements=primary, primary=True))
            primary_done = True
            needs_build = False
        secondary += extra
    if "Pipfile" in kinds:
        primary, extra = plan_pipfile(os.path.join(root, "Pipfile"))
        if primary is not None and not primary_done:
            sets.append(InstallSet("Pipfile", args=primary, requirements=primary, primary=True))
            primary_done = True
            needs_build = False
        secondary += extra
    if "setup.py" in kinds and not primary_done:
        needs_build = True

    for rel, kind in kinds.items():
        if kind == "requirements" and rel != PRIMARY_REQUIREMENTS:
            path = os.path.join(root, rel)
            secondary.append(
                InstallSet(
                    rel, args=["-r", path], requirements=requirement_lines(path), primary=False
                )
            )
    sets.extend(secondary)
    return sets, warnings, needs_build and not primary_done


# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------


def uv_available() -> bool:
    """``uv`` on PATH (the Python builder image ships it); gates era-correct resolution."""
    return shutil.which("uv") is not None


def run_pip(site: str, cutoff: Callable[[], str | None] = lambda: None) -> PipRunner:
    """Install packages into ``site``; prefer ``uv`` with an era cutoff when it is available.

    ``cutoff()`` returns an ``--exclude-newer`` date (``YYYY-MM-DD``) or ``None``. When ``uv``
    is on PATH it runs ``uv pip install --exclude-newer <date>`` so a repo's *unpinned*
    transitive dependencies resolve to the era of its *pinned* ones - the general cure for
    "old app pins Flask but not Werkzeug, pip pulls a Werkzeug that the old Flask can't
    import" (see :func:`era_cutoff`). With no ``uv`` or no cutoff it is plain pip, unchanged.
    A configured mirror (``PIP_INDEX_URL``) forces plain pip so the mirror is still honoured.
    """
    use_uv = uv_available() and not os.environ.get("PIP_INDEX_URL")

    def runner(args: list[str], timeout_s: float) -> tuple[int, str]:
        when = cutoff() if use_uv else None
        if use_uv and when:
            cmd = [
                "uv",
                "pip",
                "install",
                "--target",
                site,
                "--no-cache",
                "--exclude-newer",
                when,
                *args,
            ]
        else:
            cmd = [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--target",
                site,
                "--no-cache-dir",
                "--no-compile",
                "--no-input",
                "--disable-pip-version-check",
                "--progress-bar",
                "off",
                "--prefer-binary",
                "--no-warn-script-location",
                *args,
            ]
        try:
            proc = subprocess.run(  # fixed argv built above, no shell
                cmd,
                capture_output=True,
                text=True,
                timeout=max(1.0, timeout_s),
                check=False,
                errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else ""
            return 124, out + "\npip timed out"
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")

    return runner


def build_metadata(root: str, timeout_s: float) -> tuple[list[str] | None, str]:
    """Dependencies of a project that must be *built* to know them (``setup.py`` & co).

    ``pip install --dry-run --report`` runs the project's build backend (arbitrary code -
    which is exactly why this happens only inside the builder container) and reports the
    built metadata; the ``Requires-Dist`` entries without an ``extra ==`` marker are the
    install requirements. Nothing is installed by this step.
    """
    with tempfile.TemporaryDirectory(prefix="ono-meta-") as tmp:
        report = os.path.join(tmp, "report.json")
        cmd = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--no-deps",
            "--no-cache-dir",
            "--no-input",
            "--disable-pip-version-check",
            "--progress-bar",
            "off",
            "--report",
            report,
            "--target",
            os.path.join(tmp, "unused"),
            root,
        ]
        try:
            proc = subprocess.run(  # fixed argv, no shell
                cmd,
                capture_output=True,
                text=True,
                timeout=max(1.0, timeout_s),
                check=False,
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            return None, "building the project metadata timed out"
        if proc.returncode != 0:
            return None, "building the project metadata failed: " + _tail(
                (proc.stdout or "") + (proc.stderr or "")
            )
        try:
            with open(report, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            return None, f"pip wrote no usable metadata report: {exc}"
    items = data.get("install") if isinstance(data, dict) else None
    if not isinstance(items, list) or not items:
        return None, "pip reported no project metadata"
    metadata = items[0].get("metadata") if isinstance(items[0], dict) else None
    requires = metadata.get("requires_dist") if isinstance(metadata, dict) else None
    return [r for r in _strings(requires) if "extra ==" not in r and "extra==" not in r], ""


def _tail(text: str) -> str:
    return text.strip()[-_OUTPUT_TAIL:]


def requirement_name(line: str) -> str | None:
    """``flask[async]>=2  ; python_version>'3'`` -> ``flask[async]``; ``None`` for URLs/paths."""
    if "://" in line or line.startswith((".", "/", "-")) or "@" in line.split(";")[0]:
        return None
    match = _NAME_RE.match(line.split(";", 1)[0])
    return match.group(1) + (match.group(2) or "") if match else None


def is_pinned(line: str) -> bool:
    match = _NAME_RE.match(line.split(";", 1)[0])
    return bool(match and match.group(3) and _PIN_RE.match(match.group(3).strip()))


_EXACT_PIN_RE = re.compile(r"^==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$")
_PINS_FOR_CUTOFF = 40  # bound the PyPI lookups; the newest few pins fix the era anyway
_PYPI_TIMEOUT_S = 4.0


def exact_pin(line: str) -> tuple[str, str] | None:
    """``flask==1.0 ; py>'3'`` -> ``("flask", "1.0")``; ``None`` for anything not ``==``-pinned.

    Only exact pins date an app's era, so only they drive the cutoff (``>=`` / ``~=`` do not).
    """
    head = line.split(";", 1)[0].strip()
    match = _NAME_RE.match(head)
    if not match or not match.group(3):
        return None
    pin = _EXACT_PIN_RE.match(match.group(3).strip().rstrip(","))
    return (match.group(1).lower(), pin.group(1)) if pin else None


def pypi_upload_date(name: str, version: str, timeout_s: float) -> _dt.date | None:
    """Newest file upload date for ``name==version`` on PyPI, or ``None`` (best effort)."""
    # Always the hardcoded-https PyPI JSON API; name/version are URL-quoted.
    url = f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json"
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    stamps = [
        f.get("upload_time_iso_8601") or f.get("upload_time")
        for f in (data.get("urls") or [])
        if isinstance(f, dict)
    ]
    dates: list[_dt.date] = []
    for stamp in stamps:
        if not isinstance(stamp, str):
            continue
        with contextlib.suppress(ValueError):
            dates.append(_dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")).date())
    return max(dates) if dates else None


def era_cutoff(lines: list[str], deadline: float) -> str | None:
    """A ``--exclude-newer`` date derived from the repo's OWN exact pins (newest + 1 day).

    The newest explicitly pinned dependency dates the app; resolving everything else no newer
    than that keeps an old app's unpinned transitive tree in its own era (so it still
    imports) and leaves a modern app untouched (its cutoff is ~today). Repo-derived, so it
    over-indexes on no particular framework. ``None`` when nothing is pinned or PyPI is
    unreachable - callers then resolve latest, exactly as before.
    """
    seen: dict[str, str] = {}
    for line in lines:
        pin = exact_pin(line)
        if pin and pin[0] not in seen:
            seen[pin[0]] = pin[1]
    newest: _dt.date | None = None
    for name, version in list(seen.items())[:_PINS_FOR_CUTOFF]:
        if time.monotonic() >= deadline:
            break
        when = pypi_upload_date(name, version, _PYPI_TIMEOUT_S)
        if when and (newest is None or when > newest):
            newest = when
    if newest is None:
        return None
    return (newest + _dt.timedelta(days=1)).isoformat()


# ---------------------------------------------------------------------------
# The build
# ---------------------------------------------------------------------------


class Build:
    """State of one dependency build: what was installed, what failed, the budget left."""

    def __init__(self, config: dict[str, Any], pip: PipRunner | None = None) -> None:
        self.src = str(config["src"])
        self.site = str(config["site"])
        self.max_bytes = int(config.get("max_bytes", 256_000_000))
        self.deadline = time.monotonic() + float(config.get("timeout_s", 300.0))
        # Era cutoff for uv's --exclude-newer, derived in run() from the repo's own pins.
        # Only on the real path (default runner); an injected runner (tests) never derives it,
        # so the unit tests stay offline regardless of whether uv is on the dev machine.
        self.exclude_newer: str | None = None
        self._derive_cutoff = pip is None
        self.pip = pip or run_pip(self.site, lambda: self.exclude_newer)
        # Sink files the verifier wants provisioned FROM the nearest manifest (workspace-rel).
        self.near: list[str] = [str(p) for p in (config.get("near") or []) if isinstance(p, str)]
        self.manifests: list[str] = []
        self.installed_from: list[str] = []
        self.failed: list[str] = []
        self.relaxed: list[str] = []
        self.warnings: list[str] = []
        self.error = ""

    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    def _install(self, args: list[str]) -> tuple[bool, str]:
        if self.remaining() <= 0:
            return False, "build timed out"
        code, out = self.pip(args, self.remaining())
        return code == 0, _tail(out)

    def install_set(self, item: InstallSet) -> bool:
        ok, out = self._install(item.args)
        if ok:
            self.installed_from.append(item.label)
            return True
        if self.remaining() <= 0 or "timed out" in out[-40:]:
            self.error = f"build timed out while installing {item.label}"
            return False
        if "No space left" in out:
            self.error = f"installed dependencies exceed the size cap ({self.max_bytes} bytes)"
            return False
        # One line at a time: a single unbuildable pin must not cost the rest of the file.
        any_ok = False
        for req in item.requirements:
            if self.remaining() <= 0:
                self.error = f"build timed out while installing {item.label}"
                return any_ok
            ok, line_out = self._install([req])
            if ok:
                any_ok = True
                continue
            name = requirement_name(req)
            if name is not None and is_pinned(req):
                ok, _ = self._install([name])
                if ok:
                    self.relaxed.append(req)
                    any_ok = True
                    continue
            self.failed.append(f"{req} ({item.label}): {_last_line(line_out)}")
        if any_ok:
            self.installed_from.append(f"{item.label} (partial)")
        elif item.primary and not item.requirements:
            self.failed.append(f"{item.label}: {_last_line(out)}")
        return any_ok

    def run(self) -> dict[str, Any]:
        started = time.perf_counter()
        root_manifests = find_manifests(self.src)
        # Manifests nearest each sink file come FIRST (installed as primary); the root manifest
        # is unioned in behind them so the app's own framework wins without losing shared deps.
        near_manifests: list[str] = []
        for sink in self.near:
            for rel in nearest_manifests(self.src, sink):
                if rel not in near_manifests and rel not in root_manifests:
                    near_manifests.append(rel)
        # Node: a SEPARATE nearest-package.json walk (see nearest_node_manifest's docstring)
        # falling back to a root package.json; at most one package.json is installed.
        node_manifest: str | None = None
        for sink in self.near:
            node_manifest = nearest_node_manifest(self.src, sink)
            if node_manifest is not None:
                break
        if node_manifest is None and "package.json" in root_manifests:
            node_manifest = "package.json"
        self.manifests = near_manifests + [m for m in root_manifests if m not in near_manifests]
        if node_manifest is not None and node_manifest not in self.manifests:
            self.manifests.append(node_manifest)
        if not self.manifests:
            return self.result(started, status="skipped")

        if node_manifest is not None:
            self._install_node(node_manifest)

        sets: list[InstallSet] = []
        for rel in near_manifests:
            near_sets, near_needs_build = manifest_install_sets(self.src, rel, primary=True)
            sets += near_sets
            if near_needs_build:
                self._build_into(sets, rel)
        root_sets, warnings, needs_build = plan_installs(self.src, root_manifests)
        self.warnings += warnings
        sets += root_sets
        if needs_build:
            reqs, why = build_metadata(self.src, self.remaining())
            if reqs is None:
                self.warnings.append(why)
            else:
                label = (
                    "setup.py (built metadata)"
                    if "setup.py" in root_manifests
                    else ("pyproject.toml (built metadata)")
                )
                sets.insert(0, InstallSet(label, args=reqs, requirements=reqs, primary=True))
        if not sets and node_manifest is None:
            self.error = "no installable dependency declaration found in " + ", ".join(
                self.manifests
            )
            return self.result(started, status="failed")
        # Era-correct resolution (uv only): date the app by its newest exact pin and resolve
        # everything no newer, so an old app's unpinned transitive deps stay in its own era.
        if self._derive_cutoff and uv_available() and sets:
            pins = [req for item in sets for req in item.requirements]
            budget = min(30.0, max(0.0, self.remaining() * 0.25))
            self.exclude_newer = era_cutoff(pins, time.monotonic() + budget)
            if self.exclude_newer:
                self.warnings.append(f"resolved dependencies as of {self.exclude_newer} (repo era)")
        for item in sets:
            if not self.pip_ok(item):
                break
        if not self.error:
            size = dir_size(self.site)
            if size > self.max_bytes:
                self.error = (
                    f"installed dependencies are {size} bytes, above the cap of "
                    f"{self.max_bytes} bytes"
                )
        if self.error:
            return self.result(started, status="failed")
        if not self.installed_from:
            self.error = "nothing could be installed: " + "; ".join(self.failed)[:600]
            return self.result(started, status="failed")
        return self.result(started, status="provisioned")

    def _install_node(self, rel: str) -> None:
        """``npm ci`` (a lockfile is present) else ``npm install``, in the package.json's OWN
        directory, then move the resulting ``node_modules`` into the shared ``site`` output -
        the exact same tar that ships Python's ``--target`` output into the jail's ``/deps``,
        so Node resolves it via ``NODE_PATH=/deps/node_modules`` (see ``sandbox.py``). Best
        effort and never raises: a failure is recorded in ``failed``/``warnings``, never
        fatal to the python side of the same build.
        """
        rel_dir = os.path.dirname(rel)
        work_dir = os.path.join(self.src, rel_dir) if rel_dir else self.src
        has_lock = any(os.path.isfile(os.path.join(work_dir, name)) for name in NODE_LOCKFILES)
        label = f"{rel} (npm {'ci' if has_lock else 'install'})"
        ok, output = self._npm_install(work_dir, ci=has_lock)
        if not ok and has_lock:
            # `npm ci` is strict about a lockfile matching package.json; a stale lockfile in
            # an otherwise-fine repo should not cost the app its dependencies entirely.
            label = f"{rel} (npm install, after ci failed)"
            ok, out2 = self._npm_install(work_dir, ci=False)
            output += "\n" + out2
        if not ok:
            # Last resort: skip lifecycle scripts. A single legacy native addon that cannot
            # compile against the current Node ABI (e.g. an old `nan`-based module on Node 20)
            # otherwise fails the WHOLE install, even though the finding's sink path usually
            # needs only pure-JS packages. --ignore-scripts installs the rest of the tree so
            # the app's vulnerable route can still boot.
            label = f"{rel} (npm install --ignore-scripts, after build failed)"
            ok, out3 = self._npm_install(work_dir, ci=False, ignore_scripts=True)
            output += "\n" + out3
            if ok:
                self.warnings.append(
                    f"{rel} (npm): native builds skipped (--ignore-scripts); "
                    f"a native dependency could not compile: {_npm_error(output)}"
                )
        if not ok:
            self.failed.append(f"{rel} (npm): {_npm_error(output)}")
            return
        node_modules = os.path.join(work_dir, "node_modules")
        if not os.path.isdir(node_modules):
            self.failed.append(f"{rel} (npm): npm reported success but no node_modules exists")
            return
        dest = os.path.join(self.site, "node_modules")
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        try:
            shutil.move(node_modules, dest)
        except OSError as exc:
            self.failed.append(f"{rel} (npm): could not collect node_modules: {exc}")
            return
        _strip_node_modules_symlinks(dest)
        self.installed_from.append(label)

    def _npm_install(
        self, work_dir: str, *, ci: bool, ignore_scripts: bool = False
    ) -> tuple[bool, str]:
        remaining = self.remaining()
        if remaining <= 0:
            return False, "build timed out before npm could run"
        cmd = [
            "npm",
            "ci" if ci else "install",
            "--no-audit",
            "--no-fund",
            "--loglevel=error",
        ]
        if ignore_scripts:
            cmd.append("--ignore-scripts")
        try:
            proc = subprocess.run(  # fixed argv, no shell
                cmd,
                cwd=work_dir,
                capture_output=True,
                text=True,
                timeout=max(1.0, remaining),
                check=False,
                errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else ""
            return False, out + "\nnpm timed out"
        except FileNotFoundError:
            return False, "npm is not available in this builder image"
        return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")

    def _build_into(self, sets: list[InstallSet], rel: str) -> None:
        """A nearest manifest (setup.py / dynamic pyproject) whose metadata must be built."""
        rel_dir = os.path.dirname(rel)
        build_dir = os.path.join(self.src, rel_dir) if rel_dir else self.src
        reqs, why = build_metadata(build_dir, self.remaining())
        if reqs is None:
            self.warnings.append(why)
        else:
            sets.insert(
                0,
                InstallSet(f"{rel} (built metadata)", args=reqs, requirements=reqs, primary=True),
            )

    def pip_ok(self, item: InstallSet) -> bool:
        """Install one set; a failing *secondary* set is a warning, a primary one is reported."""
        if not item.args:
            return True
        ok = self.install_set(item)
        if self.error:
            return False
        if not ok and not item.primary:
            self.warnings.append(f"{item.label}: could not be installed (optional)")
        return True

    def result(self, started: float, *, status: str) -> dict[str, Any]:
        return {
            "ok": status != "failed",
            "status": status,
            "manifests": self.manifests,
            "installed_from": self.installed_from,
            "installed": (
                installed_packages(self.site) + installed_node_packages(self.site)
                if status == "provisioned"
                else []
            ),
            "failed": self.failed,
            "relaxed": self.relaxed,
            "warnings": self.warnings,
            "size_bytes": dir_size(self.site),
            "duration_ms": (time.perf_counter() - started) * 1000,
            "error": self.error,
        }


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:200] if lines else "pip failed"


# npm's final lines are boilerplate ("A complete log...", the update "npm notice"); the real
# cause is an earlier `npm error` line. These skip the boilerplate and the giant JS stack
# frames so the recorded reason names the actual failure (a 404 prebuilt, a compile error).
_NPM_NOISE = re.compile(
    r"(complete log of this run|npm notice|gyp ERR! stack|gyp info|node_modules/npm/|"
    r"^npm error\s*$|^npm error code \d|install response status|Pre-built binaries)",
)
_NPM_ERROR_PREFIX = re.compile(r"^npm (error|ERR!)\s+")


def _npm_error(text: str) -> str:
    """The most informative line of an npm failure, past the trailing boilerplate."""
    substantive: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or _NPM_NOISE.search(line):
            continue
        stripped = _NPM_ERROR_PREFIX.sub("", line)
        if stripped and ("error" in line.lower() or "fail" in line.lower() or "not " in line):
            substantive.append(stripped)
    if substantive:
        return substantive[-1][:200]
    return _last_line(text)


def dir_size(root: str) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total


def _strip_node_modules_symlinks(node_modules: str) -> None:
    """Remove every symlink under a freshly-installed ``node_modules`` (CLI shims in
    ``.bin/`` - themselves symlinks to a package's own script - are the common case, but
    any stray symlink is removed the same way). The workspace-archive validator this
    builder's output goes through (shared with every snapshot, see ``archive.py``) rejects
    symlink members outright; `require()` never needs them, only a shell invoking a
    package's CLI binary would, which nothing in the jail or the oracle ever does.
    """
    for dirpath, dirnames, filenames in os.walk(node_modules, topdown=True):
        if os.path.basename(dirpath) == ".bin":
            shutil.rmtree(dirpath, ignore_errors=True)
            dirnames[:] = []  # already removed; do not descend into it
            continue
        for name in [*dirnames, *filenames]:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                if name in dirnames:
                    dirnames.remove(name)
                with contextlib.suppress(OSError):
                    os.remove(full)


def installed_node_packages(site: str) -> list[str]:
    """``name version`` for every top-level (and scoped ``@org/name``) package under
    ``<site>/node_modules`` - the npm sibling of :func:`installed_packages`."""
    found: list[str] = []
    node_modules = os.path.join(site, "node_modules")
    try:
        entries = sorted(os.listdir(node_modules))
    except OSError:
        return found
    for entry in entries:
        if entry.startswith("."):
            continue
        path = os.path.join(node_modules, entry)
        if not os.path.isdir(path):
            continue
        if entry.startswith("@"):
            try:
                scoped = sorted(os.listdir(path))
            except OSError:
                continue
            for sub in scoped:
                found_pkg = _node_package_name_version(os.path.join(path, sub), f"{entry}/{sub}")
                if found_pkg:
                    found.append(found_pkg)
            continue
        found_pkg = _node_package_name_version(path, entry)
        if found_pkg:
            found.append(found_pkg)
    return found


def _node_package_name_version(package_dir: str, fallback_name: str) -> str | None:
    pkg_path = os.path.join(package_dir, "package.json")
    try:
        with open(pkg_path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    name = str(data.get("name") or fallback_name)
    version = str(data.get("version") or "")
    return f"{name} {version}".strip()


def installed_packages(site: str) -> list[str]:
    """``name version`` for every ``*.dist-info`` in the target directory."""
    found: list[str] = []
    try:
        entries = sorted(os.listdir(site))
    except OSError:
        return found
    for entry in entries:
        if not entry.endswith(".dist-info"):
            continue
        name = version = ""
        try:
            with open(
                os.path.join(site, entry, "METADATA"), encoding="utf-8", errors="replace"
            ) as fh:
                for line in fh:
                    if line.startswith("Name:"):
                        name = line[5:].strip()
                    elif line.startswith("Version:"):
                        version = line[8:].strip()
                    if name and version:
                        break
        except OSError:
            continue
        if name:
            found.append(f"{name} {version}".strip())
    return found


def main(argv: list[str], pip: PipRunner | None = None) -> int:
    if len(argv) < 1:
        sys.stdout.write(RESULT_MARKER + json.dumps({"ok": False, "error": "usage: <json>"}) + "\n")
        return 2
    try:
        config = json.loads(argv[0])
        os.makedirs(config["site"], exist_ok=True)
        result = Build(config, pip).run()
    except Exception as exc:  # the builder itself failed: report, never hang
        result = {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(RESULT_MARKER + json.dumps(result, default=str) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
