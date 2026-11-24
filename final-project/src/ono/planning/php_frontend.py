"""PHP -> IR, on tree-sitter.

Why tree-sitter: there is no stdlib PHP parser, and tree-sitter's ``tree-sitter-php`` grammar
is error-tolerant (a file with one syntax error still yields a tree for the rest) and ships as
a prebuilt wheel with type stubs, so ``mypy --strict`` sees it. The ``language_php`` variant is
used (not ``language_php_only``) so templated ``.php`` / ``.phtml`` files with interleaved HTML
and ``<?php ?>`` islands parse.

The lowering mirrors :mod:`ono.planning.js_frontend`: functions (top-level ``function``,
class ``method``s, ``anonymous`` closures and ``fn`` arrows) with their parent for closures,
assignments, every call / ``new``, and the entry-point markers of the common frameworks
(Laravel ``Route::get`` / ``$router->post``, Slim/Lumen ``$app->get``, Symfony ``#[Route]``
attributes, and any handler taking a ``$request`` parameter). PHP's keyword forms - ``echo``,
``print``, ``include`` / ``require`` and the backtick operator - are lowered into *synthetic
calls* so the catalog can match them as ordinary data rows (no per-sink logic here).

Attacker input is modelled two ways, both through the existing catalog seams:

* the superglobals ``$_GET`` / ``$_POST`` / ``$_REQUEST`` / ``$_COOKIE`` / ``$_FILES`` /
  ``$_SERVER`` are :data:`~ono.planning.catalog.GLOBAL_SOURCES` (attacker-influenced wherever
  read, like ``process.env``); and
* a routed handler's ``$request`` object exposes the request accessors in
  :data:`~ono.planning.catalog.REQUEST_PROPS`.

If tree-sitter (or the PHP grammar wheel) is not importable the front-end degrades to "no PHP
coverage" with a parse_error note rather than failing the scan.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from ono.planning.catalog import (
    HTTP_VERBS,
    PHP_NONINPUT_PARAMS,
    PHP_REQUEST_PARAM_NAMES,
    PHP_ROUTE_METHODS,
    PHP_ROUTE_RECEIVERS,
    REQUEST_PROPS,
)
from ono.planning.ir import (
    Assign,
    EntryPoint,
    Expr,
    Function,
    HandlerRef,
    Language,
    Module,
    chain,
    last_segment,
    receiver,
)

if TYPE_CHECKING:
    from tree_sitter import Node

log = logging.getLogger(__name__)

__all__ = ["AVAILABLE", "EXTENSIONS", "lower_php", "parse_php"]

try:
    import tree_sitter_php
    from tree_sitter import Language as _TSLanguage
    from tree_sitter import Parser as _TSParser

    AVAILABLE = True
except ImportError as exc:  # pragma: no cover - exercised only without the wheel
    AVAILABLE = False
    _IMPORT_ERROR = str(exc)
    log.warning("planning: tree-sitter-php unavailable (%s); PHP is skipped", exc)

_MAX_TEXT = 200

EXTENSIONS: dict[str, tuple[Language, str]] = {
    ".php": ("php", "php"),
    ".phtml": ("php", "php"),
    ".php3": ("php", "php"),
    ".php4": ("php", "php"),
    ".php5": ("php", "php"),
    ".phps": ("php", "php"),
}

_FUNCTION_TYPES = frozenset({"anonymous_function", "arrow_function"})
_CLASS_TYPES = frozenset(
    {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"}
)
_LITERAL_TYPES = frozenset(
    {"string", "integer", "float", "boolean", "null", "heredoc", "nowdoc", "shell_command_string"}
)
# Expression node types: anything that carries or routes a value (so the generic statement
# walker knows to evaluate it rather than recurse into it as a statement).
_VALUE_TYPES = frozenset(
    {
        "variable_name",
        "name",
        "qualified_name",
        "member_access_expression",
        "nullsafe_member_access_expression",
        "scoped_property_access_expression",
        "class_constant_access_expression",
        "subscript_expression",
        "function_call_expression",
        "member_call_expression",
        "nullsafe_member_call_expression",
        "scoped_call_expression",
        "object_creation_expression",
        "binary_expression",
        "unary_op_expression",
        "update_expression",
        "cast_expression",
        "assignment_expression",
        "augmented_assignment_expression",
        "conditional_expression",
        "match_expression",
        "encapsed_string",
        "print_intrinsic",
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
        "shell_command_expression",
        "array_creation_expression",
        "parenthesized_expression",
        "throw_expression",
        "clone_expression",
        "error_suppression_expression",
        "reference_assignment_expression",
        "list_literal",
        *_FUNCTION_TYPES,
        *_LITERAL_TYPES,
    }
)
_INCLUDE_NAMES: dict[str, str] = {
    "include_expression": "include",
    "include_once_expression": "include_once",
    "require_expression": "require",
    "require_once_expression": "require_once",
}
_CAST_SANITIZERS: dict[str, str] = {
    "int": "intval",
    "integer": "intval",
    "float": "floatval",
    "double": "floatval",
    "bool": "ctype_digit",
    "boolean": "ctype_digit",
}

_parser: _TSParser | None = None


def _get_parser() -> _TSParser:
    global _parser
    if _parser is None:
        _parser = _TSParser(_TSLanguage(tree_sitter_php.language_php()))
    return _parser


def parse_php(path: Path, rel: str) -> Module:
    """Parse a ``.php`` / ``.phtml`` file into a :class:`Module`; never raises."""
    try:
        source = path.read_bytes()
    except OSError as exc:
        return Module(file=rel, language="php", parse_error=str(exc))
    return lower_php(source, rel)


def lower_php(source: bytes | str, rel: str, *, language: Language = "php") -> Module:
    module = Module(file=rel, language=language)
    if not AVAILABLE:  # pragma: no cover - only without the wheel
        module.parse_error = f"tree-sitter-php unavailable: {_IMPORT_ERROR}"
        return module
    data = source.encode("utf-8") if isinstance(source, str) else source
    try:
        tree = _get_parser().parse(data)
    except Exception as exc:  # tree-sitter is defensive, but never fail a scan on a parser
        module.parse_error = f"{type(exc).__name__}: {exc}"
        return module
    root = tree.root_node
    if root.has_error:
        module.parse_error = "syntax errors (partial tree used)"
    top = Function(
        name="<module>",
        file=rel,
        language=language,
        start=1,
        end=max(1, root.end_point.row + 1),
        is_module=True,
    )
    module.functions.append(top)
    lowerer = _Lowerer(module, language)
    lowerer.block(root, top)
    lowerer.finish()
    return module


def _text(node: Node) -> str:
    raw = node.text
    if raw is None:
        return ""
    return " ".join(raw.decode("utf-8", errors="replace").split())[:_MAX_TEXT]


def _line(node: Node) -> int:
    return node.start_point.row + 1


def _unquote(text: str) -> str:
    return text.strip().strip("\"'`")


class _Lowerer:
    def __init__(self, module: Module, language: Language) -> None:
        self.module = module
        self.language = language
        self.fn: Function = module.functions[0]
        self.inline: dict[str, Function] = {}  # Expr("function").name -> Function

    # -- statements -------------------------------------------------------------------
    def block(self, node: Node, fn: Function) -> None:
        previous = self.fn
        self.fn = fn
        try:
            for child in node.named_children:
                self.stmt(child)
        finally:
            self.fn = previous

    def walk(self, node: Node) -> None:
        if node.type in _VALUE_TYPES:
            self.expr(node)
        else:
            self.stmt(node)

    def stmt(self, node: Node) -> None:
        t = node.type
        if t in ("php_tag", "php_end_tag", "text", "comment", "namespace_use_declaration"):
            return
        if t == "function_definition":
            self.function(node)
            return
        if t == "method_declaration":
            self.function(node)
            return
        if t in _CLASS_TYPES:
            self.class_body(node)
            return
        if t == "expression_statement":
            for child in node.named_children:
                self.walk(child)
            return
        if t == "echo_statement":
            self._echo(node)
            return
        if t in ("return_statement", "throw_statement", "unset_statement"):
            for child in node.named_children:
                self.expr(child)
            return
        if t == "foreach_statement":
            self._foreach(node)
            return
        if t in ("compound_statement", "declaration_list", "program"):
            for child in node.named_children:
                self.walk(child)
            return
        if t in _VALUE_TYPES:
            self.expr(node)
            return
        # if / for / while / switch / try / namespace_definition / text_interpolation / ...:
        # walk children, routing values to the evaluator and everything else as statements.
        for child in node.named_children:
            self.walk(child)

    def _echo(self, node: Node) -> None:
        args = [self.expr(c) for c in node.named_children]
        self._synth_call("echo", args, _line(node), _text(node))

    def _foreach(self, node: Node) -> None:
        body = node.child_by_field_name("body")
        parts = [c for c in node.named_children if c is not body]
        if parts:
            iterable = self.expr(parts[0])
            for target in parts[1:]:
                if target.type == "pair":
                    members = target.named_children
                    if members:
                        self.assign(_line(node), self._targets(members[-1]), iterable)
                else:
                    self.assign(_line(node), self._targets(target), iterable)
        if body is not None:
            self.stmt(body)

    # -- functions / classes ----------------------------------------------------------
    def function(
        self, node: Node, *, hint: str = "", owner: str = "", decorators: tuple[Expr, ...] = ()
    ) -> Function:
        name_node = node.child_by_field_name("name")
        name = _text(name_node) if name_node is not None else hint
        if not name:
            name = f"<anonymous@{_line(node)}:{node.start_point.column}>"
        params = self._params(node)
        fn = Function(
            name=name,
            file=self.module.file,
            language=self.language,
            start=_line(node),
            end=node.end_point.row + 1,
            params=params,
            decorators=decorators,
            parent=None if self.fn.is_module else self.fn,
            owner=owner,
        )
        self.module.functions.append(fn)
        body = node.child_by_field_name("body")
        if body is None:  # arrow function: ``fn($x) => <expr>``
            inner = _last_value_child(node)
            if inner is not None:
                previous = self.fn
                self.fn = fn
                try:
                    self.expr(inner)
                finally:
                    self.fn = previous
        elif body.type == "compound_statement":
            self.block(body, fn)
        else:
            previous = self.fn
            self.fn = fn
            try:
                self.expr(body)
            finally:
                self.fn = previous
        return fn

    def _params(self, node: Node) -> tuple[str, ...]:
        fp = next((c for c in node.named_children if c.type == "formal_parameters"), None)
        if fp is None:
            return ()
        names: list[str] = []
        for child in fp.named_children:
            if child.type in (
                "simple_parameter",
                "variadic_parameter",
                "property_promotion_parameter",
            ):
                var = next((d for d in child.named_children if d.type == "variable_name"), None)
                if var is not None:
                    names.append(_text(var))
        return tuple(names)

    def class_body(self, node: Node) -> None:
        name_node = node.child_by_field_name("name")
        owner = _text(name_node) if name_node is not None else "<class>"
        bases = self._base_names(node)
        body = next((c for c in node.named_children if c.type == "declaration_list"), None)
        if body is None:
            return
        for member in body.named_children:
            if member.type == "method_declaration":
                decorators = self._attributes(member)
                fn = self.function(member, owner=owner, decorators=decorators)
                fn.owner_bases = bases
            else:
                # property / const defaults, enum cases: walk for nested calls.
                for child in member.named_children:
                    self.walk(child)

    def _base_names(self, node: Node) -> tuple[str, ...]:
        names: list[str] = []
        for clause in node.named_children:
            if clause.type in ("base_clause", "class_interface_clause"):
                names.extend(
                    last_segment(_text(c)) for c in clause.named_children if c.type == "name"
                )
        return tuple(names)

    def _attributes(self, node: Node) -> tuple[Expr, ...]:
        out: list[Expr] = []
        for group in node.named_children:
            if group.type != "attribute_list":
                continue
            for sub in group.named_children:
                if sub.type != "attribute_group":
                    continue
                for attr in sub.named_children:
                    if attr.type == "attribute":
                        out.append(self._attribute_expr(attr))
        return tuple(out)

    def _attribute_expr(self, node: Node) -> Expr:
        name_node = next(
            (c for c in node.named_children if c.type in ("name", "qualified_name")), None
        )
        name = last_segment(_text(name_node)) if name_node is not None else ""
        callee = Expr("name", name=name, line=_line(node), text=name)
        args_node = next((c for c in node.named_children if c.type == "arguments"), None)
        args, kwargs = self._args(args_node)
        return Expr(
            "call", children=(callee, *args), kwargs=kwargs, line=_line(node), text=_text(node)
        )

    # -- assignments ------------------------------------------------------------------
    def assign(self, line: int, targets: tuple[str, ...], value: Expr) -> None:
        if targets:
            self.fn.assigns.append(Assign(line=line, targets=targets, value=value))

    def _targets(self, node: Node) -> tuple[str, ...]:
        t = node.type
        if t == "variable_name":
            return (_text(node),)
        if t in (
            "subscript_expression",
            "member_access_expression",
            "nullsafe_member_access_expression",
            "scoped_property_access_expression",
        ):
            path = chain(self.expr(node, register=False))
            return (path,) if path else ()
        if t in ("list_literal", "array_creation_expression"):
            out: list[str] = []
            for child in node.named_children:
                inner = child
                if child.type == "array_element_initializer" and child.named_children:
                    inner = child.named_children[-1]
                if inner.type == "pair" and inner.named_children:
                    inner = inner.named_children[-1]
                out.extend(self._targets(inner))
            return tuple(out)
        return ()

    # -- expressions ------------------------------------------------------------------
    def expr(self, node: Node, *, register: bool = True, hint: str = "") -> Expr:
        t = node.type
        line = _line(node)
        if t == "variable_name":
            return Expr("name", name=_text(node), line=line, text=_text(node))
        if t in ("name", "qualified_name"):
            return Expr("name", name=_text(node).lstrip("\\"), line=line, text=_text(node))
        if t in ("parenthesized_expression", "error_suppression_expression"):
            inner = _last_value_child(node)
            return (
                self.expr(inner, register=register)
                if inner is not None
                else Expr("other", line=line)
            )
        if t == "cast_expression":
            return self._cast(node, register=register)
        if t == "member_access_expression" or t == "nullsafe_member_access_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("name")
            base = (
                self.expr(obj, register=register) if obj is not None else Expr("other", line=line)
            )
            return Expr(
                "member",
                name=_text(prop) if prop is not None else "",
                children=(base,),
                line=line,
                text=_text(node),
            )
        if t == "scoped_property_access_expression" or t == "class_constant_access_expression":
            scope = node.child_by_field_name("scope")
            name_node = node.child_by_field_name("name")
            base = (
                self.expr(scope, register=register)
                if scope is not None and scope.type in _VALUE_TYPES
                else Expr("name", name=_text(scope) if scope is not None else "", line=line)
            )
            return Expr(
                "member",
                name=_text(name_node) if name_node is not None else "",
                children=(base,),
                line=line,
                text=_text(node),
            )
        if t == "subscript_expression":
            named = node.named_children
            base = self.expr(named[0], register=register) if named else Expr("other", line=line)
            idx = (
                self.expr(named[1], register=register)
                if len(named) > 1
                else Expr("other", line=line)
            )
            return Expr("subscript", children=(base, idx), line=line, text=_text(node))
        if t in (
            "function_call_expression",
            "member_call_expression",
            "nullsafe_member_call_expression",
            "scoped_call_expression",
        ):
            return self._call(node, register=register)
        if t == "object_creation_expression":
            return self._new(node, register=register)
        if t == "print_intrinsic":
            inner = _last_value_child(node)
            arg = (
                self.expr(inner, register=register)
                if inner is not None
                else Expr("other", line=line)
            )
            return self._synth_call("print", [arg], line, _text(node))
        if t in _INCLUDE_NAMES:
            inner = _last_value_child(node)
            arg = (
                self.expr(inner, register=register)
                if inner is not None
                else Expr("other", line=line)
            )
            return self._synth_call(_INCLUDE_NAMES[t], [arg], line, _text(node))
        if t == "shell_command_expression":
            parts = tuple(
                self.expr(c, register=register)
                for c in node.named_children
                if c.type not in ("string_content", "escape_sequence")
            )
            fmt = Expr("format", children=parts, line=line, text=_text(node), constant=not parts)
            return self._synth_call("shell_exec", [fmt], line, _text(node))
        if t in _LITERAL_TYPES:
            return Expr("literal", line=line, text=_text(node), constant=True)
        if t == "encapsed_string":
            parts = tuple(
                self.expr(c, register=register)
                for c in node.named_children
                if c.type not in ("string_content", "escape_sequence")
            )
            if parts:
                return Expr("format", children=parts, line=line, text=_text(node))
            return Expr("literal", line=line, text=_text(node), constant=True)
        if t == "array_creation_expression":
            return self._array(node, register=register)
        if t == "binary_expression":
            return self._binop(node, register=register)
        if t == "augmented_assignment_expression":
            return self._augmented(node, register=register)
        if t == "assignment_expression" or t == "reference_assignment_expression":
            return self._assignment(node, register=register, hint=hint)
        if t == "conditional_expression":
            children = tuple(self.expr(c, register=register) for c in node.named_children)
            return Expr("other", children=children, line=line, text=_text(node))
        if t in _FUNCTION_TYPES:
            fn = self.function(node, hint=hint)
            key = f"{fn.name}@{line}:{node.start_point.column}"
            self.inline[key] = fn
            return Expr("function", name=key, line=line, text=_text(node)[:60])
        if t in (
            "unary_op_expression",
            "update_expression",
            "clone_expression",
            "throw_expression",
        ):
            for c in node.named_children:
                self.expr(c, register=register)
            return Expr("other", line=line, text=_text(node))
        children = tuple(
            self.expr(c, register=register) for c in node.named_children if c.type in _VALUE_TYPES
        )
        return Expr("other", children=children, line=line, text=_text(node))

    def _cast(self, node: Node, *, register: bool) -> Expr:
        line = _line(node)
        cast_node = next((c for c in node.named_children if c.type == "cast_type"), None)
        inner = _last_value_child(node)
        value = (
            self.expr(inner, register=register) if inner is not None else Expr("other", line=line)
        )
        sanitizer = (
            _CAST_SANITIZERS.get(_text(cast_node).lower()) if cast_node is not None else None
        )
        if sanitizer is not None:  # ``(int) $x`` neutralises an injection payload
            callee = Expr("name", name=sanitizer, line=line, text=sanitizer)
            return Expr("call", children=(callee, value), line=line, text=_text(node))
        return value  # ``(string) $x`` etc.: transparent, taint flows through

    def _call(self, node: Node, *, register: bool) -> Expr:
        line = _line(node)
        t = node.type
        if t == "function_call_expression":
            callee_node = node.child_by_field_name("function")
            callee = (
                self.expr(callee_node, register=register)
                if callee_node is not None
                else Expr("other", line=line)
            )
        else:  # member_call / nullsafe_member_call / scoped_call
            obj = node.child_by_field_name("object") or node.child_by_field_name("scope")
            name_node = node.child_by_field_name("name")
            base = (
                self.expr(obj, register=register)
                if obj is not None and obj.type in _VALUE_TYPES
                else Expr("name", name=_text(obj) if obj is not None else "", line=line)
            )
            callee = Expr(
                "member",
                name=_text(name_node) if name_node is not None else "",
                children=(base,),
                line=line,
                text=_text(node),
            )
        args, kwargs = self._args(node.child_by_field_name("arguments"))
        call = Expr("call", children=(callee, *args), kwargs=kwargs, line=line, text=_text(node))
        if register:
            self.fn.calls.append(call)
        return call

    def _new(self, node: Node, *, register: bool) -> Expr:
        line = _line(node)
        callee_node = next(
            (
                c
                for c in node.named_children
                if c.type in ("name", "qualified_name", "variable_name")
            ),
            None,
        )
        callee = (
            self.expr(callee_node, register=register)
            if callee_node is not None
            else Expr("other", line=line)
        )
        args, kwargs = self._args(
            next((c for c in node.named_children if c.type == "arguments"), None)
        )
        call = Expr("new", children=(callee, *args), kwargs=kwargs, line=line, text=_text(node))
        if register:
            self.fn.calls.append(call)
        return call

    def _args(self, node: Node | None) -> tuple[list[Expr], tuple[tuple[str, Expr], ...]]:
        if node is None:
            return [], ()
        args: list[Expr] = []
        kwargs: list[tuple[str, Expr]] = []
        for child in node.named_children:
            if child.type != "argument":
                if child.type in _VALUE_TYPES:
                    args.append(self.expr(child))
                continue
            named = child.named_children
            if len(named) == 2 and named[0].type == "name":  # ``methods: ['GET']`` named arg
                value = self.expr(named[1])
                args.append(value)
                kwargs.append((_text(named[0]), value))
            elif named:
                args.append(self.expr(named[-1]))
        return args, tuple(kwargs)

    def _array(self, node: Node, *, register: bool) -> Expr:
        line = _line(node)
        values: list[Expr] = []
        for element in node.named_children:
            inner = element
            if element.type == "array_element_initializer" and element.named_children:
                inner = element.named_children[-1]  # value of ``key => value``
            if inner.type in _VALUE_TYPES:
                values.append(self.expr(inner, register=register))
        return Expr("collection", children=tuple(values), line=line, text=_text(node))

    def _binop(self, node: Node, *, register: bool) -> Expr:
        op_node = node.child_by_field_name("operator")
        op = _text(op_node) if op_node is not None else "op"
        op = {".": "+", ".=": "+="}.get(op, op)  # PHP string concat -> treated as +
        children = tuple(
            self.expr(c, register=register) for c in node.named_children if c.type in _VALUE_TYPES
        )
        return Expr("binop", name=op, children=children, line=_line(node), text=_text(node))

    def _augmented(self, node: Node, *, register: bool) -> Expr:
        op_node = node.child_by_field_name("operator")
        op = _text(op_node) if op_node is not None else "op"
        op = {".": "+", ".=": "+="}.get(op, op)
        named = [c for c in node.named_children if c.type in _VALUE_TYPES]
        children = tuple(self.expr(c, register=register) for c in named)
        result = Expr("binop", name=op, children=children, line=_line(node), text=_text(node))
        if named:
            self.assign(_line(node), self._targets(named[0]), result)
        return result

    def _assignment(self, node: Node, *, register: bool, hint: str) -> Expr:
        named = node.named_children
        if len(named) < 2:
            return Expr("other", line=_line(node))
        left, right = named[0], named[-1]
        target_hint = _text(left) if left.type == "variable_name" else ""
        value = self.expr(right, register=register, hint=target_hint or hint)
        self.assign(_line(node), self._targets(left), value)
        return value

    def _synth_call(self, name: str, args: list[Expr], line: int, text: str) -> Expr:
        """Lower a PHP keyword construct (echo / print / include / backticks) to a call row."""
        callee = Expr("name", name=name, line=line, text=name)
        call = Expr("call", children=(callee, *args), line=line, text=text[:_MAX_TEXT])
        self.fn.calls.append(call)
        return call

    # -- entry points -----------------------------------------------------------------
    def finish(self) -> None:
        self.mark_registrations()
        for fn in self.module.functions:
            if fn.is_module or fn.entry is not None:
                continue
            fn.entry = self._attribute_entry(fn) or self._request_param_entry(fn)

    def mark_registrations(self) -> None:
        for fn in list(self.module.functions):
            for call in fn.calls:
                self._registration(call)

    def _registration(self, call: Expr) -> None:
        if call.kind != "call" or not call.args:
            return
        path = chain(call)
        last = last_segment(path)
        rcv = last_segment(receiver(path))
        if last not in PHP_ROUTE_METHODS or rcv not in PHP_ROUTE_RECEIVERS:
            return
        first = call.args[0]
        route = _unquote(first.text) if first.kind in ("literal", "format") else "*"
        method = last.upper() if last in HTTP_VERBS else "ANY"
        detail = f"{method} {route}"
        for arg in call.args[1:]:
            if arg.kind == "function":
                fn = self.inline.get(arg.name)
                if fn is not None and fn.entry is None:
                    fn.entry = _request_entry(fn, "route", detail, taint_data=False)
            else:
                name = _handler_ref_name(arg)
                if name:
                    self.module.handler_refs.append(
                        HandlerRef(name=name, line=call.line, detail=detail, kind="route")
                    )

    def _attribute_entry(self, fn: Function) -> EntryPoint | None:
        for dec in fn.decorators:
            last = last_segment(chain(dec)).lower()
            if last in HTTP_VERBS or last in ("route", "all"):
                route = ""
                if dec.args and dec.args[0].kind == "literal":
                    route = _unquote(dec.args[0].text)
                method = last.upper() if last in HTTP_VERBS else _methods_kwarg(dec)
                return _request_entry(fn, "route", f"{method} {route or '*'}", taint_data=True)
        return None

    def _request_param_entry(self, fn: Function) -> EntryPoint | None:
        if not any(p in PHP_REQUEST_PARAM_NAMES for p in fn.params):
            return None
        request = next(p for p in fn.params if p in PHP_REQUEST_PARAM_NAMES)
        return _request_entry(fn, "request-param", f"parameter {request!r}", taint_data=True)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _last_value_child(node: Node) -> Node | None:
    for child in reversed(node.named_children):
        if child.type in _VALUE_TYPES:
            return child
    return None


def _handler_ref_name(arg: Expr) -> str:
    """Name of a routed controller method: ``'Ctrl@show'`` or ``[Ctrl::class, 'show']``."""
    if arg.kind == "literal":
        text = _unquote(arg.text)
        if "@" in text:  # ``'HomeController@show'``
            return text.rsplit("@", 1)[-1]
        return ""
    if arg.kind == "collection":  # ``[Ctrl::class, 'save']``
        for child in reversed(arg.children):
            if child.kind == "literal":
                return _unquote(child.text)
    return ""


def _methods_kwarg(dec: Expr) -> str:
    methods = dec.kwarg("methods")
    if methods is None:
        return "ANY"
    names = [_unquote(c.text) for c in methods.children if c.kind == "literal"]
    return "/".join(names) if names else "ANY"


def _request_entry(fn: Function, kind: str, detail: str, *, taint_data: bool) -> EntryPoint:
    request = tuple(p for p in fn.params if p in PHP_REQUEST_PARAM_NAMES)
    data = (
        tuple(
            p
            for p in fn.params
            if p not in PHP_REQUEST_PARAM_NAMES and p not in PHP_NONINPUT_PARAMS
        )
        if taint_data
        else ()
    )
    return EntryPoint(
        file=fn.file,
        line=fn.start,
        function=fn.name if not fn.owner else f"{fn.owner}.{fn.name}",
        kind=kind,
        detail=detail,
        tainted_params=data,
        request_params=request,
        request_props=tuple(sorted(REQUEST_PROPS["php"])),
    )
