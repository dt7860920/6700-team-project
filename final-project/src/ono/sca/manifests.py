"""Parse a repository's dependency declarations into ``(ecosystem, name, version)`` triples.

Everything flows through one **parser registry** (:data:`REGISTRY`) keyed by OSV ecosystem
name. Each entry is a :class:`ManifestType` that says which files it recognises and how to
turn their text into ``(name, version)`` pairs; the walker attaches the ecosystem and the
manifest's path. **Adding an ecosystem is one small function plus one registry entry** - no
other code changes - which is the whole point of the design, so no individual package is
ever special-cased.

Only triples with a *concrete, pinned* version are emitted: lockfiles (which pin exact
versions) are the richest source, so a loose ``package.json`` / ``requirements.txt`` range is
skipped rather than guessed. Ecosystem names are OSV's exact spellings ("PyPI", "npm", "Go",
"RubyGems", "Maven", "crates.io", "NuGet", "Packagist"); see https://ossf.github.io/osv-schema.

The PyPI ``requirements*.txt`` parser reuses the battle-tested requirement-line handling in
``ono/executor/_builder.py`` (``requirement_lines`` / ``exact_pin``) rather than duplicating it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tomllib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

from ono.executor._builder import exact_pin

log = logging.getLogger(__name__)

_REQ_FILE = re.compile(r"^requirements[A-Za-z0-9._-]*\.txt$")

# One parsed dependency: an OSV triple plus the manifest it came from (workspace-relative).
Triple = tuple[str, str, str]


@dataclass(frozen=True)
class ParsedDep:
    ecosystem: str
    name: str
    version: str
    manifest: str

    @property
    def triple(self) -> Triple:
        return (self.ecosystem, self.name, self.version)


# A parser turns one manifest's TEXT into ``(name, version)`` pairs (ecosystem added later).
Parser = Callable[[str], list[tuple[str, str]]]

# Directories never walked: vendored installs and VCS/build output. Supersets _builder's set.
_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        "env",
        ".git",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "__pycache__",
        "build",
        "dist",
        "vendor",
        "site-packages",
        ".gradle",
        "target",
    }
)
_MAX_FILE_BYTES = 8_000_000  # a manifest larger than this is almost certainly not one


@dataclass(frozen=True)
class ManifestType:
    """One recognised manifest: how to spot its files and how to parse them."""

    ecosystem: str
    matches: Callable[[str], bool]
    parse: Parser


def _basenames(*names: str) -> Callable[[str], bool]:
    lowered = {n.lower() for n in names}
    return lambda name: name.lower() in lowered


def _strip_v(version: str) -> str:
    """Normalise a leading ``v`` (``v1.2.3`` -> ``1.2.3``) as OSV expects for Go/Packagist."""
    version = version.strip()
    if len(version) > 1 and version[0] in "vV" and version[1].isdigit():
        return version[1:]
    return version


_CONCRETE_VERSION = re.compile(r"^[0-9][0-9A-Za-z.+:~_-]*$")


def _is_concrete(version: str) -> bool:
    """A single resolved version - not a range/constraint/property/wildcard reference."""
    version = version.strip()
    if not version or any(c in version for c in "^~*<>=| ") or version.startswith("${"):
        return False
    return bool(_CONCRETE_VERSION.match(_strip_v(version)))


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------


def parse_requirements_txt(text: str) -> list[tuple[str, str]]:
    """Pinned ``name==version`` lines of a pip requirements file (ranges are skipped).

    Line splitting mirrors ``_builder.requirement_lines`` (comments / options), and each
    surviving line is handed to ``_builder.exact_pin`` so the exact-pin grammar is shared
    with the dependency installer rather than re-implemented.
    """
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].split("\t#", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        pin = exact_pin(line)
        if pin is not None:
            out.append(pin)
    return out


def parse_pipfile_lock(text: str) -> list[tuple[str, str]]:
    data = _json(text)
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    for section in ("default", "develop"):
        packages = data.get(section)
        if not isinstance(packages, dict):
            continue
        for name, spec in packages.items():
            version = spec.get("version") if isinstance(spec, dict) else None
            if isinstance(version, str) and version.startswith("=="):
                out.append((str(name), version[2:].strip()))
    return out


def parse_poetry_lock(text: str) -> list[tuple[str, str]]:
    return _toml_packages(text, name_key="name", version_key="version")


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


def parse_package_lock(text: str) -> list[tuple[str, str]]:
    """``package-lock.json`` v2/v3 (``packages`` map) and v1 (``dependencies`` tree)."""
    data = _json(text)
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2 / v3
        for path, spec in packages.items():
            if not path or not isinstance(spec, dict):
                continue  # "" is the root project itself
            name = path.rsplit("node_modules/", 1)[-1]
            version = spec.get("version")
            if name and isinstance(version, str) and _is_concrete(version):
                out.append((name, version))
    deps = data.get("dependencies")
    if not out and isinstance(deps, dict):  # lockfile v1
        _walk_npm_v1(deps, out)
    return out


def _walk_npm_v1(deps: dict[str, object], out: list[tuple[str, str]]) -> None:
    for name, spec in deps.items():
        if not isinstance(spec, dict):
            continue
        version = spec.get("version")
        if isinstance(version, str) and _is_concrete(version):
            out.append((name, version))
        nested = spec.get("dependencies")
        if isinstance(nested, dict):
            _walk_npm_v1(nested, out)


def parse_package_json(text: str) -> list[tuple[str, str]]:
    """``package.json`` - only used when NO lockfile is present; only exact pins survive."""
    data = _json(text)
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, version in block.items():
            if isinstance(version, str) and _is_concrete(version):
                out.append((str(name), version))
    return out


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

_GO_REQUIRE_LINE = re.compile(r"^\s*(?:require\s+)?([^\s()]+/[^\s()]+|[^\s().]+)\s+(v[^\s]+)")


def parse_go_mod(text: str) -> list[tuple[str, str]]:
    """``require`` directives of a ``go.mod`` (single-line and block form)."""
    out: list[tuple[str, str]] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require") and line.endswith("("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if "=>" in line:  # a replace directive, not a real dependency
            continue
        if in_block or line.startswith("require "):
            match = _GO_REQUIRE_LINE.match(line)
            if match and match.group(1) != "require":
                out.append((match.group(1), _strip_v(match.group(2))))
    return out


# ---------------------------------------------------------------------------
# RubyGems
# ---------------------------------------------------------------------------

# A gem SPEC line in Gemfile.lock is indented exactly four spaces: ``    rails (7.0.4)``.
# Its own dependencies are indented six and carry constraints (``>= 1.0``), so they are skipped.
_GEM_SPEC = re.compile(r"^ {4}([A-Za-z0-9._-]+) \(([0-9][^()]*)\)\s*$")


def parse_gemfile_lock(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    in_specs = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if raw and not raw[0].isspace():  # a new top-level section (GEM, PLATFORMS, ...)
            in_specs = False
        if not in_specs:
            continue
        match = _GEM_SPEC.match(raw)
        if match:
            out.append((match.group(1), match.group(2).strip()))
    return out


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------


def parse_pom_xml(text: str) -> list[tuple[str, str]]:
    """``<dependency>`` entries of a ``pom.xml``; OSV name is ``groupId:artifactId``."""
    root = _xml(text)
    if root is None:
        return []
    out: list[tuple[str, str]] = []
    for dep in root.iter():
        if _localname(dep.tag) != "dependency":
            continue
        fields = {_localname(child.tag): (child.text or "").strip() for child in dep}
        group = fields.get("groupId", "")
        artifact = fields.get("artifactId", "")
        version = fields.get("version", "")
        if group and artifact and version and _is_concrete(version):
            out.append((f"{group}:{artifact}", version))
    return out


# ---------------------------------------------------------------------------
# crates.io
# ---------------------------------------------------------------------------


def parse_cargo_lock(text: str) -> list[tuple[str, str]]:
    return _toml_packages(text, name_key="name", version_key="version")


# ---------------------------------------------------------------------------
# NuGet
# ---------------------------------------------------------------------------


def parse_csproj(text: str) -> list[tuple[str, str]]:
    """``<PackageReference Include="X" Version="Y" />`` (attribute or child-element form)."""
    root = _xml(text)
    if root is None:
        return []
    out: list[tuple[str, str]] = []
    for ref in root.iter():
        if _localname(ref.tag) != "PackageReference":
            continue
        name = ref.attrib.get("Include") or ref.attrib.get("Update")
        version = ref.attrib.get("Version")
        if version is None:
            child = next((c for c in ref if _localname(c.tag) == "Version"), None)
            version = (child.text or "").strip() if child is not None else None
        if name and version and _is_concrete(version):
            out.append((name, version))
    return out


def parse_packages_config(text: str) -> list[tuple[str, str]]:
    """``<package id="X" version="Y" />`` entries of a classic ``packages.config``."""
    root = _xml(text)
    if root is None:
        return []
    out: list[tuple[str, str]] = []
    for pkg in root.iter():
        if _localname(pkg.tag) != "package":
            continue
        name = pkg.attrib.get("id")
        version = pkg.attrib.get("version")
        if name and version and _is_concrete(version):
            out.append((name, version))
    return out


# ---------------------------------------------------------------------------
# Packagist (Composer)
# ---------------------------------------------------------------------------


def parse_composer_lock(text: str) -> list[tuple[str, str]]:
    data = _json(text)
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    for section in ("packages", "packages-dev"):
        packages = data.get(section)
        if not isinstance(packages, list):
            continue
        for spec in packages:
            if not isinstance(spec, dict):
                continue
            name = spec.get("name")
            version = spec.get("version")
            if isinstance(name, str) and isinstance(version, str) and _is_concrete(version):
                out.append((name, _strip_v(version)))
    return out


# ---------------------------------------------------------------------------
# The registry  (add an ecosystem => add one entry here)
# ---------------------------------------------------------------------------

REGISTRY: dict[str, list[ManifestType]] = {
    "PyPI": [
        ManifestType("PyPI", lambda n: bool(_REQ_FILE.match(n)), parse_requirements_txt),
        ManifestType("PyPI", _basenames("Pipfile.lock"), parse_pipfile_lock),
        ManifestType("PyPI", _basenames("poetry.lock"), parse_poetry_lock),
    ],
    "npm": [
        ManifestType(
            "npm", _basenames("package-lock.json", "npm-shrinkwrap.json"), parse_package_lock
        ),
        ManifestType("npm", _basenames("package.json"), parse_package_json),
    ],
    "Go": [ManifestType("Go", _basenames("go.mod"), parse_go_mod)],
    "RubyGems": [ManifestType("RubyGems", _basenames("Gemfile.lock"), parse_gemfile_lock)],
    "Maven": [ManifestType("Maven", _basenames("pom.xml"), parse_pom_xml)],
    "crates.io": [ManifestType("crates.io", _basenames("Cargo.lock"), parse_cargo_lock)],
    "NuGet": [
        ManifestType("NuGet", lambda n: n.lower().endswith(".csproj"), parse_csproj),
        ManifestType("NuGet", _basenames("packages.config"), parse_packages_config),
    ],
    "Packagist": [ManifestType("Packagist", _basenames("composer.lock"), parse_composer_lock)],
}

# npm's lockfile wins over a loose package.json in the same directory (it pins exact versions).
_LOCKFILE_SHADOWS = {"package.json": ("package-lock.json", "npm-shrinkwrap.json")}


def _manifest_for(name: str) -> ManifestType | None:
    for types in REGISTRY.values():
        for manifest_type in types:
            if manifest_type.matches(name):
                return manifest_type
    return None


def collect_dependencies(workspace: Path) -> list[ParsedDep]:
    """Walk ``workspace`` and parse every recognised manifest into concrete deps.

    Vendored/VCS/build directories are skipped. Within one directory a lockfile shadows the
    loose manifest it supersedes (``package.json`` is parsed only when no npm lockfile sits
    beside it). Duplicate triples from the same manifest are collapsed; the same triple from
    different manifests keeps the first path seen.
    """
    deps: list[ParsedDep] = []
    seen: set[tuple[str, str, str, str]] = set()
    workspace = Path(workspace)
    for directory, dir_names, file_names in _walk(workspace):
        present = set(file_names)
        for file_name in sorted(file_names):
            if _shadowed(file_name, present):
                continue
            manifest_type = _manifest_for(file_name)
            if manifest_type is None:
                continue
            path = directory / file_name
            rel = path.relative_to(workspace).as_posix()
            text = _read(path)
            if text is None:
                continue
            for name, version in manifest_type.parse(text):
                name = name.strip()
                version = (
                    _strip_v(version)
                    if manifest_type.ecosystem in ("Go", "Packagist")
                    else version.strip()
                )
                if not name or not version:
                    continue
                key = (manifest_type.ecosystem, name, version, rel)
                if key in seen:
                    continue
                seen.add(key)
                deps.append(ParsedDep(manifest_type.ecosystem, name, version, rel))
        dir_names[:] = [d for d in dir_names if d not in _SKIP_DIRS and not d.startswith(".")]
    return deps


def _shadowed(file_name: str, present: set[str]) -> bool:
    shadows = _LOCKFILE_SHADOWS.get(file_name.lower())
    return bool(shadows and any(lock in present for lock in shadows))


def _walk(workspace: Path) -> Iterator[tuple[Path, list[str], list[str]]]:
    """``os.walk`` over ``workspace`` yielding the directory as a ``Path`` (dir_names is
    mutated in place by the caller to prune vendored directories)."""
    for dirpath, dir_names, file_names in os.walk(workspace):
        yield Path(dirpath), dir_names, file_names


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Shared parsing helpers
# ---------------------------------------------------------------------------


def _json(text: str) -> object:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _toml_packages(text: str, *, name_key: str, version_key: str) -> list[tuple[str, str]]:
    """``[[package]]`` array-of-tables parse shared by Cargo.lock and poetry.lock."""
    try:
        data = tomllib.loads(text)
    except (ValueError, TypeError):
        return []
    packages = data.get("package") if isinstance(data, dict) else None
    if not isinstance(packages, list):
        return []
    out: list[tuple[str, str]] = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get(name_key)
        version = entry.get(version_key)
        if isinstance(name, str) and isinstance(version, str) and version:
            out.append((name, version))
    return out


def _xml(text: str) -> ElementTree.Element | None:
    try:
        return ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None


def _localname(tag: object) -> str:
    """An XML tag without its ``{namespace}`` prefix (pom.xml declares a default namespace)."""
    return str(tag).rsplit("}", 1)[-1]
