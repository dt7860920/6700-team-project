"""Python -> IR, on the standard library ``ast``.

Why ``ast`` and not tree-sitter for Python: the stdlib parser accepts exactly what the
interpreter accepts, gives exact line numbers for every node, needs no native wheel and
cannot drift from the language version the scanner runs on. tree-sitter is used for
JavaScript/TypeScript (:mod:`ono.planning.js_frontend`), where there is no stdlib parser.

What is lowered (everything else is walked for nested calls and otherwise ignored):

* every function / method (``def`` / ``async def``), nested ones with their parent, and a
  ``<module>`` pseudo-function for top-level code;
* assignments in all their forms (``=``, annotated, augmented, walrus, ``for`` targets,
  ``with ... as``), tuple targets flattened;
* every call expression, any depth, registered on the function it occurs in;
* imports, so ``from os import system`` resolves ``system(...)`` to ``os.system``;
* entry-point markers: route / view / CLI / event decorators, HTTP-verb methods on view
  classes, a ``request`` parameter, and URL-map references (``path("x", views.detail)``).
"""

from __future__ import annotations

import ast
from pathlib import Path

from ono.planning.catalog import (
    HTTP_VERBS,
    PY_CLI_DECORATORS,
    PY_EVENT_DECORATORS,
    PY_REQUEST_PARAM_NAMES,
    PY_ROUTE_DECORATORS,
    PY_URLMAP_CALLS,
    PY_VIEW_BASES,
    PY_VIEW_DECORATORS,
    REQUEST_PROPS,
)
from ono.planning.ir import (
    Assign,
    EntryPoint,
    Expr,
    Function,
    HandlerRef,
    Module,
    chain,
    last_segment,
    receiver,
)

__all__ = ["lower_python", "parse_python"]

_MAX_TEXT = 200

_BINOP_SYMBOLS: dict[type[ast.operator], str] = {
    ast.Add: "+",
    ast.Mod: "%",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.Div: "/",
    ast.BitOr: "|",
    ast.BitAnd: "&",
}


def parse_python(path: Path, rel: str) -> Module:
    """Parse ``path`` (reported as ``rel``) into a :class:`Module`; never raises."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return Module(file=rel, language="python", parse_error=str(exc))
    return lower_python(source, rel)


def lower_python(source: str, rel: str) -> Module:
    module = Module(file=rel, language="python")
    lines = source.splitlines()
    top = Function(
        name="<module>",
        file=rel,
        language="python",
        start=1,
        end=max(1, len(lines)),
        is_module=True,
    )
    module.functions.append(top)
    try:
        tree = ast.parse(source, filename=rel)
    except (SyntaxError, ValueError, RecursionError) as exc:
        module.parse_error = f"{type(exc).__name__}: {exc}"
        return module
    lowerer = _Lowerer(module, lines)
    lowerer.walk_body(tree.body, top, owner="", bases=())
    _mark_entry_points(module)
    return module


class _Lowerer:
    def __init__(self, module: Module, lines: list[str]) -> None:
        self.module = module
        self.lines = lines
        self.fn: Function = module.functions[0]

    # -- statements ---------------------------------------------------------------
    def walk_body(
        self, body: list[ast.stmt], fn: Function, *, owner: str, bases: tuple[str, ...]
    ) -> None:
        previous = self.fn
        self.fn = fn
        try:
            for stmt in body:
                self.stmt(stmt, owner=owner, bases=bases)
        finally:
            self.fn = previous

    def stmt(self, node: ast.stmt, *, owner: str, bases: tuple[str, ...]) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            self.function(node, owner=owner, bases=bases)
        elif isinstance(node, ast.ClassDef):
            class_bases = tuple(
                last_segment(chain(self.expr(b))) or b.__class__.__name__ for b in node.bases
            )
            for d in node.decorator_list:
                self.expr(d)
            self.walk_body(node.body, self.fn, owner=node.name, bases=class_bases)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    self.module.imports[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level + (node.module or "")
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                self.module.imports[bound] = f"{prefix}.{alias.name}" if prefix else alias.name
        elif isinstance(node, ast.Assign):
            value = self.expr(node.value)
            targets = tuple(n for t in node.targets for n in self.target_names(t))
            self.assign(node.lineno, targets, value)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.assign(node.lineno, self.target_names(node.target), self.expr(node.value))
        elif isinstance(node, ast.AugAssign):
            target = self.expr(node.target)
            value = self.expr(node.value)
            combined = Expr(
                "binop",
                name=_BINOP_SYMBOLS.get(type(node.op), "op"),
                children=(target, value),
                line=node.lineno,
                text=self.text(node),
            )
            self.assign(node.lineno, self.target_names(node.target), combined)
        elif isinstance(node, ast.For | ast.AsyncFor):
            self.assign(node.lineno, self.target_names(node.target), self.expr(node.iter))
            self.walk_body(node.body, self.fn, owner=owner, bases=bases)
            self.walk_body(node.orelse, self.fn, owner=owner, bases=bases)
        elif isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                ctx = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(node.lineno, self.target_names(item.optional_vars), ctx)
            self.walk_body(node.body, self.fn, owner=owner, bases=bases)
        elif isinstance(node, ast.If | ast.While):
            self.expr(node.test)
            self.walk_body(node.body, self.fn, owner=owner, bases=bases)
            self.walk_body(node.orelse, self.fn, owner=owner, bases=bases)
        elif isinstance(node, ast.Try | ast.TryStar):
            self.walk_body(node.body, self.fn, owner=owner, bases=bases)
            for handler in node.handlers:
                self.walk_body(handler.body, self.fn, owner=owner, bases=bases)
            self.walk_body(node.orelse, self.fn, owner=owner, bases=bases)
            self.walk_body(node.finalbody, self.fn, owner=owner, bases=bases)
        elif isinstance(node, ast.Match):
            self.expr(node.subject)
            for case in node.cases:
                self.walk_body(case.body, self.fn, owner=owner, bases=bases)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self.expr(node.value)
        elif isinstance(node, ast.Expr):
            self.expr(node.value)
        elif isinstance(node, ast.Raise):
            if node.exc is not None:
                self.expr(node.exc)
        elif isinstance(node, ast.Assert):
            self.expr(node.test)
        elif isinstance(node, ast.Delete):
            for t in node.targets:
                self.expr(t)
        # Global / Nonlocal / Pass / Break / Continue / TypeAlias: nothing to lower.

    def function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, owner: str, bases: tuple[str, ...]
    ) -> None:
        params = _param_names(node.args)
        decorators = tuple(self.expr(d, register=False) for d in node.decorator_list)
        fn = Function(
            name=node.name,
            file=self.module.file,
            language="python",
            start=node.lineno,
            end=node.end_lineno or node.lineno,
            params=params,
            decorators=decorators,
            parent=None if self.fn.is_module else self.fn,
            owner=owner,
            owner_bases=bases,
        )
        self.module.functions.append(fn)
        # defaults are evaluated in the enclosing scope
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.expr(default)
        self.walk_body(node.body, fn, owner="", bases=())

    def assign(self, line: int, targets: tuple[str, ...], value: Expr) -> None:
        if targets:
            self.fn.assigns.append(Assign(line=line, targets=targets, value=value))

    def target_names(self, node: ast.expr) -> tuple[str, ...]:
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, ast.Tuple | ast.List):
            return tuple(n for elt in node.elts for n in self.target_names(elt))
        if isinstance(node, ast.Starred):
            return self.target_names(node.value)
        if isinstance(node, ast.Attribute):
            path = chain(self.expr(node, register=False))
            return (path,) if path else ()
        if isinstance(node, ast.Subscript):
            # ``d["k"] = tainted`` taints the container
            self.expr(node.slice)
            return self.target_names(node.value)
        return ()

    # -- expressions ----------------------------------------------------------------
    def expr(self, node: ast.expr, *, register: bool = True) -> Expr:
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Name):
            return Expr("name", name=node.id, line=line, text=node.id)
        if isinstance(node, ast.Attribute):
            return Expr(
                "member",
                name=node.attr,
                children=(self.expr(node.value, register=register),),
                line=line,
                text=self.text(node),
            )
        if isinstance(node, ast.Call):
            callee = self.expr(node.func, register=register)
            args = tuple(self.expr(a, register=register) for a in node.args)
            kwargs = tuple(
                (kw.arg, self.expr(kw.value, register=register))
                for kw in node.keywords
                if kw.arg is not None
            )
            spread = tuple(
                self.expr(kw.value, register=register) for kw in node.keywords if kw.arg is None
            )
            call = Expr(
                "call",
                children=(callee, *args, *spread),
                kwargs=kwargs,
                line=line,
                text=self.text(node),
            )
            if register:
                self.fn.calls.append(call)
            return call
        if isinstance(node, ast.Constant):
            return Expr("literal", line=line, text=self.text(node), constant=True)
        if isinstance(node, ast.JoinedStr):
            parts = tuple(
                self.expr(v.value, register=register)
                for v in node.values
                if isinstance(v, ast.FormattedValue)
            )
            return Expr("format", children=parts, line=line, text=self.text(node))
        if isinstance(node, ast.BinOp):
            return Expr(
                "binop",
                name=_BINOP_SYMBOLS.get(type(node.op), "op"),
                children=(
                    self.expr(node.left, register=register),
                    self.expr(node.right, register=register),
                ),
                line=line,
                text=self.text(node),
            )
        if isinstance(node, ast.BoolOp):
            return Expr(
                "binop",
                name="or" if isinstance(node.op, ast.Or) else "and",
                children=tuple(self.expr(v, register=register) for v in node.values),
                line=line,
                text=self.text(node),
            )
        if isinstance(node, ast.Subscript):
            return Expr(
                "subscript",
                children=(
                    self.expr(node.value, register=register),
                    self.expr(node.slice, register=register),
                ),
                line=line,
                text=self.text(node),
            )
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return Expr(
                "collection",
                children=tuple(self.expr(e, register=register) for e in node.elts),
                line=line,
                text=self.text(node),
            )
        if isinstance(node, ast.Dict):
            values = tuple(self.expr(v, register=register) for v in node.values)
            kwargs = tuple(
                (str(k.value), v)
                for k, v in zip(node.keys, values, strict=True)
                if isinstance(k, ast.Constant)
            )
            return Expr(
                "collection", children=values, kwargs=kwargs, line=line, text=self.text(node)
            )
        if isinstance(node, ast.IfExp):
            return Expr(
                "other",
                children=(
                    self.expr(node.body, register=register),
                    self.expr(node.orelse, register=register),
                ),
                line=line,
                text=self.text(node),
            )
        if isinstance(node, ast.Await | ast.Starred | ast.Yield | ast.YieldFrom):
            inner = node.value
            if inner is None:
                return Expr("other", line=line)
            return Expr(
                "other",
                children=(self.expr(inner, register=register),),
                line=line,
                text=self.text(node),
            )
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value, register=register)
            self.assign(line, self.target_names(node.target), value)
            return value
        if isinstance(node, ast.Lambda):
            return Expr("function", name=f"<lambda@{line}>", line=line, text=self.text(node))
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
            pieces: list[Expr] = []
            if isinstance(node, ast.DictComp):
                pieces.append(self.expr(node.value, register=register))
            else:
                pieces.append(self.expr(node.elt, register=register))
            for gen in node.generators:
                pieces.append(self.expr(gen.iter, register=register))
                for cond in gen.ifs:
                    self.expr(cond, register=register)
            return Expr("other", children=tuple(pieces), line=line, text=self.text(node))
        if isinstance(node, ast.Compare):
            self.expr(node.left, register=register)
            for c in node.comparators:
                self.expr(c, register=register)
            return Expr("other", line=line, text=self.text(node))  # a boolean: not data
        if isinstance(node, ast.UnaryOp):
            inner_e = self.expr(node.operand, register=register)
            if isinstance(node.op, ast.Not):
                return Expr("other", line=line, text=self.text(node))
            return Expr("other", children=(inner_e,), line=line, text=self.text(node))
        if isinstance(node, ast.Slice):
            for part in (node.lower, node.upper, node.step):
                if part is not None:
                    self.expr(part, register=register)
            return Expr("other", line=line)
        # Anything else: walk sub-expressions for calls, keep an opaque node.
        children = tuple(
            self.expr(child, register=register)
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
        )
        return Expr("other", children=children, line=line, text=self.text(node))

    def text(self, node: ast.expr | ast.stmt) -> str:
        start, end = node.lineno, node.end_lineno
        if end is None or start < 1 or end > len(self.lines):
            return ""
        if start == end:
            segment = self.lines[start - 1][node.col_offset : node.end_col_offset]
        else:
            first = self.lines[start - 1][node.col_offset :]
            middle = self.lines[start : end - 1]
            last = self.lines[end - 1][: node.end_col_offset]
            segment = " ".join(s.strip() for s in (first, *middle, last))
        return segment[:_MAX_TEXT]


def _param_names(args: ast.arguments) -> tuple[str, ...]:
    names = [a.arg for a in (*args.posonlyargs, *args.args)]
    if args.vararg is not None:
        names.append(args.vararg.arg)
    names.extend(a.arg for a in args.kwonlyargs)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return tuple(names)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def _mark_entry_points(module: Module) -> None:
    _collect_handler_refs(module)
    for fn in module.functions:
        if fn.is_module:
            continue
        entry = _decorator_entry(module, fn) or _class_view_entry(fn) or _request_param_entry(fn)
        if entry is not None:
            fn.entry = entry


def _data_params(fn: Function) -> tuple[str, ...]:
    return tuple(
        p for p in fn.params if p not in ("self", "cls") and p not in PY_REQUEST_PARAM_NAMES
    )


def _request_params(fn: Function) -> tuple[str, ...]:
    return tuple(p for p in fn.params if p in PY_REQUEST_PARAM_NAMES)


def _entry(fn: Function, kind: str, detail: str, *, tainted_all: bool = True) -> EntryPoint:
    return EntryPoint(
        file=fn.file,
        line=fn.start,
        function=fn.name if not fn.owner else f"{fn.owner}.{fn.name}",
        kind=kind,
        detail=detail,
        tainted_params=_data_params(fn) if tainted_all else (),
        request_params=_request_params(fn),
        request_props=tuple(sorted(REQUEST_PROPS["python"])),
    )


def _decorator_entry(module: Module, fn: Function) -> EntryPoint | None:
    for dec in fn.decorators:
        path = module.resolve(chain(dec))
        last = last_segment(path)
        rcv = receiver(path)
        if last in PY_ROUTE_DECORATORS and rcv:
            method = last.upper() if last in HTTP_VERBS else _methods_kwarg(dec)
            route = _first_literal(dec) or "*"
            return _entry(fn, "route", f"{method} {route}")
        if last in PY_VIEW_DECORATORS:
            return _entry(fn, "view", f"@{last}")
        if (
            last in PY_CLI_DECORATORS
            and rcv
            and ("click" in path or "typer" in path or rcv.endswith(("app", "cli")))
        ):
            return _entry(fn, "cli", f"@{path}")
        if last in PY_EVENT_DECORATORS and rcv:
            return _entry(fn, "event", f"@{path}({_first_literal(dec) or ''})")
    return None


def _class_view_entry(fn: Function) -> EntryPoint | None:
    if not fn.owner or fn.name not in HTTP_VERBS | {"dispatch"}:
        return None
    looks_like_view = any(b.endswith(PY_VIEW_BASES) for b in fn.owner_bases) or bool(
        _request_params(fn)
    )
    if not looks_like_view:
        return None
    return _entry(fn, "class-view", f"{fn.name.upper()} {fn.owner}")


def _request_param_entry(fn: Function) -> EntryPoint | None:
    request = _request_params(fn)
    if not request:
        return None
    return _entry(fn, "request-param", f"parameter {request[0]!r}")


def _collect_handler_refs(module: Module) -> None:
    """``path("users/<pk>", views.detail)``, ``add_url_rule(view_func=f)``, ``Foo.as_view()``."""
    for fn in module.functions:
        for call in fn.calls:
            path = module.resolve(chain(call))
            if last_segment(path) not in PY_URLMAP_CALLS:
                continue
            route = _first_literal(call) or "*"
            candidates = [
                *call.args[1:],
                *(v for k, v in call.kwargs if k in ("view", "view_func", "handler")),
            ]
            for arg in candidates:
                target = chain(arg)
                if not target:
                    continue
                if arg.kind == "call" and last_segment(target) == "as_view":
                    owner = last_segment(receiver(target))
                    if owner:
                        module.handler_refs.append(
                            HandlerRef(
                                name=owner,
                                line=call.line,
                                detail=f"url-map {route}",
                                kind="class-view",
                            )
                        )
                elif arg.kind in ("name", "member"):
                    module.handler_refs.append(
                        HandlerRef(
                            name=last_segment(target), line=call.line, detail=f"url-map {route}"
                        )
                    )


def _first_literal(call: Expr) -> str:
    for arg in call.args:
        if arg.kind == "literal":
            return arg.text.strip().strip("\"'")
    return ""


def _methods_kwarg(call: Expr) -> str:
    methods = call.kwarg("methods")
    if methods is None:
        return "ANY"
    names = [c.text.strip().strip("\"'") for c in methods.children if c.kind == "literal"]
    return "/".join(names) if names else "ANY"
