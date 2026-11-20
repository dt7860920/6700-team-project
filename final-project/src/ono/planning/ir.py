"""The tiny language-neutral IR the threat-mapping stage reasons over.

Both front-ends (:mod:`ono.planning.python_frontend` on the stdlib ``ast``,
:mod:`ono.planning.js_frontend` on tree-sitter) lower source files into the same three
shapes - :class:`Expr`, :class:`Assign`, :class:`Function` - so the taint engine
(:mod:`ono.planning.taint`) is written and tested once.

The IR is deliberately lossy. It keeps exactly what a lightweight source->sink argument
needs: identifier/attribute chains (``request.args.get``), calls with their arguments and
keyword arguments, string building (f-strings, template literals, ``+``, ``%``,
``.format``), subscripts, collections and literals. Control flow is flattened: the engine
is flow-insensitive within a function (see :mod:`ono.planning.taint` for the exact depth).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ExprKind = Literal[
    "name",  # identifier                          name=<identifier>
    "member",  # obj.attr                            name=<attr>, children=(obj,)
    "call",  # f(args, k=v)                        children=(callee, *args), kwargs
    "new",  # new F(args) (JS)                    children=(callee, *args)
    "literal",  # string / number / None / regex...  constant=True
    "format",  # f"..{x}.." / `..${x}..` / "%" fmt   children=(substitutions...)
    "binop",  # a + b, a % b, a || b ...            children=(left, right), name=<operator>
    "subscript",  # obj[index]                        children=(obj, index)
    "collection",  # list / tuple / dict / set / object children=(elements...)
    "function",  # an inline function (lambda, arrow) - opaque, see Function.parent
    "other",  # anything else                      children=(sub-expressions...)
]

Language = Literal["python", "javascript", "typescript"]


@dataclass(frozen=True, slots=True)
class Expr:
    """One expression. ``children`` are the sub-expressions taint can flow through."""

    kind: ExprKind
    name: str = ""
    children: tuple[Expr, ...] = ()
    kwargs: tuple[tuple[str, Expr], ...] = ()
    line: int = 0
    text: str = ""
    constant: bool = False

    @property
    def callee(self) -> Expr | None:
        if self.kind in ("call", "new") and self.children:
            return self.children[0]
        return None

    @property
    def args(self) -> tuple[Expr, ...]:
        if self.kind in ("call", "new"):
            return self.children[1:]
        return ()

    def kwarg(self, key: str) -> Expr | None:
        for name, value in self.kwargs:
            if name == key:
                return value
        return None


def chain(e: Expr) -> str:
    """The dotted access path of ``e`` when it is rooted at an identifier.

    ``request.args.get("id")`` -> ``"request.args.get"``; ``os.system`` -> ``"os.system"``;
    ``conn.cursor().execute(q)`` -> ``".execute"`` (a leading dot marks a computed
    receiver - the method name is still known, the object is not). Subscripts are
    transparent (``request.args["id"]`` -> ``"request.args"``). Anything else -> ``""``.
    """
    if e.kind == "name":
        return e.name
    if e.kind == "member":
        base = chain(e.children[0]) if e.children else ""
        return f"{base}.{e.name}" if base else f".{e.name}"
    if e.kind in ("call", "new"):
        return chain(e.children[0]) if e.children else ""
    if e.kind == "subscript":
        return chain(e.children[0]) if e.children else ""
    return ""


def last_segment(path: str) -> str:
    return path.rsplit(".", 1)[-1] if path else ""


def receiver(path: str) -> str:
    """``"cur.execute"`` -> ``"cur"``; ``"system"`` -> ``""``; ``".execute"`` -> ``""``."""
    if "." not in path:
        return ""
    head = path.rsplit(".", 1)[0]
    return head


def is_constant(e: Expr) -> bool:
    """True when ``e`` can only ever evaluate to a fixed value (literals, collections of them)."""
    if e.kind == "literal":
        return True
    if e.kind == "collection":
        return all(is_constant(c) for c in e.children)
    if e.kind == "binop" and e.name in ("+", "%"):
        return all(is_constant(c) for c in e.children)
    if e.kind == "format":
        return not e.children
    return False


def is_string_building(e: Expr) -> bool:
    """True when ``e`` builds a string from parts (f-string, template literal, ``+``, ``%``...)."""
    if e.kind == "format" and e.children:
        return True
    if e.kind == "binop" and e.name in ("+", "%", "+="):
        return True
    if e.kind == "call":
        return last_segment(chain(e)) in ("format", "join", "replace", "concat")
    return False


@dataclass(frozen=True, slots=True)
class Assign:
    """``targets = value``. Targets are plain names, or dotted names for attribute targets."""

    line: int
    targets: tuple[str, ...]
    value: Expr


@dataclass(frozen=True, slots=True)
class EntryPoint:
    """An attacker-reachable way into the code, bound to the function that handles it."""

    file: str
    line: int
    function: str
    kind: (
        str  # route / view / class-view / url-map / request-param / handler / lambda / cli / event
    )
    detail: str  # e.g. "GET /user", "path('users/<pk>', views.detail)"
    tainted_params: tuple[str, ...] = ()  # parameters that carry attacker data directly
    request_params: tuple[str, ...] = ()  # parameters that are *request objects* (req / request)
    request_props: tuple[str, ...] | None = None  # None = every member of the request object

    @property
    def label(self) -> str:
        return f"{self.detail} -> {self.file}:{self.line} {self.function}()"


@dataclass(slots=True)
class Function:
    """A function body flattened to what the taint engine needs. The module is one too."""

    name: str
    file: str
    language: Language
    start: int
    end: int
    params: tuple[str, ...] = ()
    decorators: tuple[Expr, ...] = ()
    assigns: list[Assign] = field(default_factory=list)
    calls: list[Expr] = field(default_factory=list)  # every call / new in the body, any depth
    parent: Function | None = None  # enclosing function (closures inherit its taint)
    owner: str = ""  # enclosing class name, if a method
    owner_bases: tuple[str, ...] = ()
    exported: bool = False  # JS: exported / assigned to module.exports
    is_module: bool = False
    entry: EntryPoint | None = None

    @property
    def label(self) -> str:
        return f"{self.file}:{self.start} {self.name}()"

    def contains(self, line: int) -> bool:
        return self.start <= line <= self.end

    def nearest_entry(self) -> EntryPoint | None:
        fn: Function | None = self
        while fn is not None:
            if fn.entry is not None:
                return fn.entry
            fn = fn.parent
        return None


@dataclass(frozen=True, slots=True)
class HandlerRef:
    """A handler referenced by name from a URL map / route registration (``views.detail``)."""

    name: str
    line: int
    detail: str
    kind: str = "url-map"


@dataclass(slots=True)
class Module:
    """One parsed source file."""

    file: str
    language: Language
    functions: list[Function] = field(default_factory=list)  # source order, module first
    imports: dict[str, str] = field(default_factory=dict)  # bound name -> module[.symbol]
    handler_refs: list[HandlerRef] = field(default_factory=list)
    parse_error: str = ""

    def function_at(self, line: int) -> Function | None:
        """The innermost non-module function containing ``line`` (None = module level)."""
        best: Function | None = None
        for fn in self.functions:
            if fn.is_module or not fn.contains(line):
                continue
            if best is None or (fn.end - fn.start) < (best.end - best.start):
                best = fn
        return best

    def resolve(self, path: str) -> str:
        """Rewrite the root of a dotted path through the import table.

        ``from os import system`` makes ``"system"`` -> ``"os.system"``; ``import subprocess
        as sp`` makes ``"sp.run"`` -> ``"subprocess.run"``. Unknown roots pass through.
        """
        if not path or path.startswith("."):
            return path
        root, _, rest = path.partition(".")
        target = self.imports.get(root)
        if target is None:
            return path
        return f"{target}.{rest}" if rest else target
