"""JavaScript / TypeScript -> IR, on tree-sitter.

Why tree-sitter: there is no stdlib parser for JS/TS, and tree-sitter's grammars
(``tree-sitter-javascript``, ``tree-sitter-typescript``) are error-tolerant - a file with
one syntax error still yields a tree for the rest, which matters on real repositories.
The grammars ship as prebuilt wheels with type stubs, so ``mypy --strict`` sees them.

The lowering mirrors :mod:`ono.planning.python_frontend`: functions (declarations,
expressions, arrows, class methods) with their parent for closures, assignments
(including destructuring - ``const { id } = req.query`` taints ``id``), every call and
``new`` expression, ``require`` / ``import`` bindings, and the entry-point markers of
Express / Koa / Fastify / hapi / Next.js / AWS Lambda / Node ``http`` / NestJS decorators.

If tree-sitter is not importable the front-end degrades to "no JS/TS coverage" with a
parse_error note rather than failing the scan.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from ono.planning.catalog import (
    HTTP_VERBS,
    JS_EVENT_RECEIVERS,
    JS_EXPORTED_HANDLER_NAMES,
    JS_REQUEST_PARAM_NAMES,
    JS_ROUTE_METHODS,
    JS_SERVER_FACTORIES,
    REQUEST_PROPS,
)
from ono.planning.ir import (
    Assign,
    EntryPoint,
    Expr,
    ExprKind,
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

__all__ = ["AVAILABLE", "lower_js", "parse_js"]

try:
    import tree_sitter_javascript
    import tree_sitter_typescript
    from tree_sitter import Language as _TSLanguage
    from tree_sitter import Parser as _TSParser

    AVAILABLE = True
except ImportError as exc:  # pragma: no cover - exercised only without the wheels
    AVAILABLE = False
    _IMPORT_ERROR = str(exc)
    log.warning("planning: tree-sitter unavailable (%s); JavaScript/TypeScript are skipped", exc)

_MAX_TEXT = 200

EXTENSIONS: dict[str, tuple[Language, str]] = {
    ".js": ("javascript", "javascript"),
    ".mjs": ("javascript", "javascript"),
    ".cjs": ("javascript", "javascript"),
    ".jsx": ("javascript", "javascript"),
    ".ts": ("typescript", "typescript"),
    ".mts": ("typescript", "typescript"),
    ".cts": ("typescript", "typescript"),
    ".tsx": ("typescript", "tsx"),
}

_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function_expression",
        "function",
        "generator_function",
        "function_declaration",
        "generator_function_declaration",
    }
)
_TRANSPARENT = frozenset(
    {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "type_assertion",
        "await_expression",
        "spread_element",
        "instantiation_expression",
    }
)
_LITERAL_TYPES = frozenset({"string", "number", "true", "false", "null", "undefined", "regex"})
_EXPR_TYPES = frozenset(
    {
        "identifier",
        "this",
        "super",
        "member_expression",
        "subscript_expression",
        "call_expression",
        "new_expression",
        "template_string",
        "array",
        "object",
        "binary_expression",
        "unary_expression",
        "update_expression",
        "assignment_expression",
        "augmented_assignment_expression",
        "ternary_expression",
        "sequence_expression",
        "yield_expression",
        "class",
        *_FUNCTION_TYPES,
        *_TRANSPARENT,
        *_LITERAL_TYPES,
    }
)
_CLASS_TYPES = frozenset({"class_declaration", "abstract_class_declaration", "class"})
_SKIP_TYPES = frozenset(
    {
        "comment",
        "import_statement",
        "interface_declaration",
        "type_alias_declaration",
        "enum_declaration",
        "ambient_declaration",
        "function_signature",
        "method_signature",
        "abstract_method_signature",
        "index_signature",
        "type_annotation",
        "type_arguments",
        "type_parameters",
        "decorator",
        "accessibility_modifier",
        "property_identifier",
        "private_property_identifier",
        "hash_bang_line",
    }
)

_parsers: dict[str, _TSParser] = {}


def _parser(grammar: str) -> _TSParser:
    parser = _parsers.get(grammar)
    if parser is None:
        if grammar == "typescript":
            lang = _TSLanguage(tree_sitter_typescript.language_typescript())
        elif grammar == "tsx":
            lang = _TSLanguage(tree_sitter_typescript.language_tsx())
        else:
            lang = _TSLanguage(tree_sitter_javascript.language())
        parser = _TSParser(lang)
        _parsers[grammar] = parser
    return parser


def parse_js(path: Path, rel: str) -> Module:
    """Parse a ``.js/.mjs/.cjs/.jsx/.ts/.tsx`` file into a :class:`Module`; never raises."""
    language, grammar = EXTENSIONS.get(path.suffix.lower(), ("javascript", "javascript"))
    try:
        source = path.read_bytes()
    except OSError as exc:
        return Module(file=rel, language=language, parse_error=str(exc))
    return lower_js(source, rel, language=language, grammar=grammar)


def lower_js(
    source: bytes | str, rel: str, *, language: Language = "javascript", grammar: str = ""
) -> Module:
    module = Module(file=rel, language=language)
    if not AVAILABLE:  # pragma: no cover
        module.parse_error = f"tree-sitter unavailable: {_IMPORT_ERROR}"
        return module
    data = source.encode("utf-8") if isinstance(source, str) else source
    grammar = grammar or ("typescript" if language == "typescript" else "javascript")
    try:
        tree = _parser(grammar).parse(data)
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
        self.exported_names: set[str] = set()
        self.default_export: str = ""
        self.pending_decorators: list[Expr] = []

    # -- statements -------------------------------------------------------------------
    def block(self, node: Node, fn: Function) -> None:
        previous = self.fn
        self.fn = fn
        try:
            for child in node.named_children:
                self.stmt(child)
        finally:
            self.fn = previous

    def stmt(self, node: Node, *, exported: bool = False, default: bool = False) -> None:
        t = node.type
        if t in _SKIP_TYPES:
            if t == "import_statement":
                self.import_statement(node)
            elif t == "decorator":
                self.pending_decorators.append(self.expr(_decorator_expr(node), register=False))
            return
        if t in ("lexical_declaration", "variable_declaration"):
            for decl in node.named_children:
                if decl.type == "variable_declarator":
                    self.declarator(decl, exported=exported)
            return
        if t in ("function_declaration", "generator_function_declaration"):
            self.function(node, exported=exported, default=default)
            return
        if t in _CLASS_TYPES:
            self.class_body(node, exported=exported)
            return
        if t == "export_statement":
            self.export_statement(node)
            return
        if t == "expression_statement":
            for child in node.named_children:
                self.expr(child)
            return
        if t in ("return_statement", "throw_statement"):
            for child in node.named_children:
                self.expr(child)
            return
        if t == "if_statement":
            self.field_expr(node, "condition")
            self.field_stmt(node, "consequence")
            self.field_stmt(node, "alternative")
            return
        if t == "for_in_statement":
            right = self.field_expr(node, "right")
            left = node.child_by_field_name("left")
            if left is not None and right is not None:
                self.destructure(left, right, _line(node))
            self.field_stmt(node, "body")
            return
        if t in ("for_statement", "while_statement", "do_statement"):
            for part in ("initializer", "condition", "increment"):
                piece = node.child_by_field_name(part)
                if piece is not None:
                    if piece.type in _EXPR_TYPES:
                        self.expr(piece)
                    else:
                        self.stmt(piece)
            self.field_stmt(node, "body")
            return
        if t == "switch_statement":
            self.field_expr(node, "value")
            self.field_stmt(node, "body")
            return
        if t == "catch_clause":
            self.field_stmt(node, "body")
            return
        # statement_block, try_statement, switch_body, switch_case, labeled_statement, else_clause,
        # finally_clause, program-level odds and ends: walk children.
        for child in node.named_children:
            if child.type in _EXPR_TYPES:
                self.expr(child)
            else:
                self.stmt(child)

    def field_stmt(self, node: Node, field: str) -> None:
        child = node.child_by_field_name(field)
        if child is not None:
            self.stmt(child)

    def field_expr(self, node: Node, field: str) -> Expr | None:
        child = node.child_by_field_name(field)
        return self.expr(child) if child is not None else None

    def import_statement(self, node: Node) -> None:
        source = node.child_by_field_name("source")
        if source is None:
            return
        module_name = _module_name(_unquote(_text(source)))
        for clause in node.named_children:
            if clause.type != "import_clause":
                continue
            for part in clause.named_children:
                if part.type == "identifier":
                    self.module.imports[_text(part)] = module_name
                elif part.type == "namespace_import":
                    for ident in part.named_children:
                        if ident.type == "identifier":
                            self.module.imports[_text(ident)] = module_name
                elif part.type == "named_imports":
                    for spec in part.named_children:
                        if spec.type != "import_specifier":
                            continue
                        name = spec.child_by_field_name("name")
                        alias = spec.child_by_field_name("alias")
                        if name is None:
                            continue
                        bound = _text(alias) if alias is not None else _text(name)
                        self.module.imports[bound] = f"{module_name}.{_text(name)}"

    def export_statement(self, node: Node) -> None:
        default = any(c.type == "default" for c in node.children)
        declaration = node.child_by_field_name("declaration")
        value = node.child_by_field_name("value")
        if declaration is not None:
            self.stmt(declaration, exported=True, default=default)
            return
        if value is not None:
            if value.type in _FUNCTION_TYPES or value.type in _CLASS_TYPES:
                hint = "default" if default else ""
                self.expr(value, hint=hint, exported=True)
            elif value.type == "identifier":
                name = _text(value)
                self.exported_names.add(name)
                if default:
                    self.default_export = name
            else:
                self.expr(value)
            return
        for child in node.named_children:  # export { a, b as c }
            if child.type == "export_clause":
                for spec in child.named_children:
                    spec_name = spec.child_by_field_name("name")
                    if spec_name is not None:
                        self.exported_names.add(_text(spec_name))

    def declarator(self, node: Node, *, exported: bool) -> None:
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None:
            return
        if value_node is None:
            return
        hint = _text(name_node) if name_node.type == "identifier" else ""
        value = self.expr(value_node, hint=hint, exported=exported)
        # ``const x = require("m")`` / ``const { a, b: c } = require("m")``
        if value.kind == "name" and _is_require(value_node):
            self.bind_require(name_node, value.name)
        elif value.kind == "member" and value.children and _is_require_member(value_node):
            self.bind_require(name_node, chain(value))
        self.destructure(name_node, value, _line(node))

    def bind_require(self, pattern: Node, module_name: str) -> None:
        if pattern.type == "identifier":
            self.module.imports[_text(pattern)] = module_name
        elif pattern.type == "object_pattern":
            for child in pattern.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    self.module.imports[_text(child)] = f"{module_name}.{_text(child)}"
                elif child.type == "pair_pattern":
                    key = child.child_by_field_name("key")
                    val = child.child_by_field_name("value")
                    if key is not None and val is not None and val.type == "identifier":
                        self.module.imports[_text(val)] = f"{module_name}.{_text(key)}"

    def class_body(self, node: Node, *, exported: bool) -> None:
        name_node = node.child_by_field_name("name")
        owner = _text(name_node) if name_node is not None else "<class>"
        body = node.child_by_field_name("body")
        self.pending_decorators = []
        if body is None:
            return
        for member in body.named_children:
            if member.type == "decorator":
                self.pending_decorators.append(self.expr(_decorator_expr(member), register=False))
                continue
            if member.type == "method_definition":
                decorators = tuple(self.pending_decorators)
                self.pending_decorators = []
                self.function(member, owner=owner, decorators=decorators, exported=exported)
            elif member.type in ("field_definition", "public_field_definition"):
                self.pending_decorators = []
                prop = member.child_by_field_name("property") or member.child_by_field_name("name")
                value = member.child_by_field_name("value")
                if value is not None:
                    hint = _text(prop) if prop is not None else ""
                    v = self.expr(value, hint=hint)
                    if prop is not None:
                        self.assign(_line(member), (f"this.{_text(prop)}",), v)
            else:
                self.pending_decorators = []
                self.stmt(member)

    # -- functions --------------------------------------------------------------------
    def function(
        self,
        node: Node,
        *,
        hint: str = "",
        owner: str = "",
        decorators: tuple[Expr, ...] = (),
        exported: bool = False,
        default: bool = False,
    ) -> Function:
        name_node = node.child_by_field_name("name")
        name = _text(name_node) if name_node is not None else hint
        if not name:
            name = f"<anonymous@{_line(node)}:{node.start_point.column}>"
        params, param_assigns = self.params(node)
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
            exported=exported,
        )
        fn.assigns.extend(param_assigns)
        if default:
            self.default_export = name
        self.module.functions.append(fn)
        body = node.child_by_field_name("body")
        if body is not None:
            if body.type == "statement_block":
                self.block(body, fn)
            else:  # expression-bodied arrow function
                previous = self.fn
                self.fn = fn
                try:
                    self.expr(body)
                finally:
                    self.fn = previous
        return fn

    def params(self, node: Node) -> tuple[tuple[str, ...], list[Assign]]:
        names: list[str] = []
        assigns: list[Assign] = []
        single = node.child_by_field_name("parameter")
        if single is not None:  # ``x => ...``
            return (_text(single),), []
        params = node.child_by_field_name("parameters")
        if params is None:
            return (), []
        for index, child in enumerate(params.named_children):
            pattern: Node | None = child
            if child.type in ("required_parameter", "optional_parameter"):
                pattern = child.child_by_field_name("pattern")
            if pattern is not None and pattern.type == "assignment_pattern":
                pattern = pattern.child_by_field_name("left")
            if pattern is None:
                continue
            if pattern.type == "rest_pattern":
                inner_names = [c for c in pattern.named_children if c.type == "identifier"]
                if inner_names:
                    names.append(_text(inner_names[0]))
                continue
            if pattern.type == "identifier":
                names.append(_text(pattern))
            elif pattern.type == "this":
                continue
            elif pattern.type in ("object_pattern", "array_pattern"):
                synthetic = f"__param{index}"
                names.append(synthetic)
                assigns.extend(
                    self.destructure_list(
                        pattern, Expr("name", name=synthetic, line=_line(pattern)), _line(pattern)
                    )
                )
        return tuple(names), assigns

    # -- assignments ------------------------------------------------------------------
    def assign(self, line: int, targets: tuple[str, ...], value: Expr) -> None:
        if targets:
            self.fn.assigns.append(Assign(line=line, targets=targets, value=value))

    def destructure(self, pattern: Node, value: Expr, line: int) -> None:
        for a in self.destructure_list(pattern, value, line):
            self.fn.assigns.append(a)

    def destructure_list(self, pattern: Node, value: Expr, line: int) -> list[Assign]:
        t = pattern.type
        if t in ("identifier", "shorthand_property_identifier_pattern"):
            return [Assign(line=line, targets=(_text(pattern),), value=value)]
        if t == "object_pattern":
            out: list[Assign] = []
            for child in pattern.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    key = _text(child)
                    out.append(
                        Assign(
                            line=line,
                            targets=(key,),
                            value=Expr("member", name=key, children=(value,), line=line),
                        )
                    )
                elif child.type == "pair_pattern":
                    key_node = child.child_by_field_name("key")
                    val = child.child_by_field_name("value")
                    if key_node is None or val is None:
                        continue
                    member = Expr(
                        "member", name=_unquote(_text(key_node)), children=(value,), line=line
                    )
                    out.extend(self.destructure_list(val, member, line))
                elif child.type == "object_assignment_pattern":
                    left = child.child_by_field_name("left")
                    if left is not None:
                        key = _text(left)
                        member = Expr("member", name=key, children=(value,), line=line)
                        out.extend(self.destructure_list(left, member, line))
                elif child.type == "rest_pattern":
                    for inner in child.named_children:
                        out.extend(self.destructure_list(inner, value, line))
            return out
        if t == "array_pattern":
            out = []
            for index, child in enumerate(pattern.named_children):
                element = Expr(
                    "subscript",
                    children=(value, Expr("literal", text=str(index), constant=True)),
                    line=line,
                )
                out.extend(self.destructure_list(child, element, line))
            return out
        if t == "assignment_pattern":
            left = pattern.child_by_field_name("left")
            return self.destructure_list(left, value, line) if left is not None else []
        if t == "rest_pattern":
            return [
                a for c in pattern.named_children for a in self.destructure_list(c, value, line)
            ]
        if t in (
            "member_expression",
            "subscript_expression",
            "parenthesized_expression",
            "non_null_expression",
        ):
            target = self.expr(pattern, register=False)
            path = chain(target)
            return [Assign(line=line, targets=(path,), value=value)] if path else []
        return []

    # -- expressions ------------------------------------------------------------------
    def expr(
        self, node: Node, *, register: bool = True, hint: str = "", exported: bool = False
    ) -> Expr:
        t = node.type
        line = _line(node)
        if t in ("identifier", "this", "super", "shorthand_property_identifier"):
            return Expr("name", name=_text(node), line=line, text=_text(node))
        if t in _TRANSPARENT:
            inner = _first_expr_child(node)
            return (
                self.expr(inner, register=register)
                if inner is not None
                else Expr("other", line=line)
            )
        if t == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
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
        if t == "subscript_expression":
            obj = node.child_by_field_name("object")
            index = node.child_by_field_name("index")
            base = (
                self.expr(obj, register=register) if obj is not None else Expr("other", line=line)
            )
            idx = (
                self.expr(index, register=register)
                if index is not None
                else Expr("other", line=line)
            )
            return Expr("subscript", children=(base, idx), line=line, text=_text(node))
        if t in ("call_expression", "new_expression"):
            return self.call(node, register=register)
        if t in _LITERAL_TYPES:
            return Expr("literal", line=line, text=_text(node), constant=True)
        if t == "template_string":
            parts = tuple(
                self.expr(sub, register=register)
                for s in node.named_children
                if s.type == "template_substitution"
                for sub in s.named_children
            )
            return Expr("format", children=parts, line=line, text=_text(node), constant=not parts)
        if t == "array":
            return Expr(
                "collection",
                children=tuple(self.expr(c, register=register) for c in node.named_children),
                line=line,
                text=_text(node),
            )
        if t == "object":
            return self.object(node, register=register)
        if t in ("binary_expression", "augmented_assignment_expression"):
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op = node.child_by_field_name("operator")
            children = tuple(
                self.expr(c, register=register) for c in (left, right) if c is not None
            )
            result = Expr(
                "binop",
                name=_text(op) if op is not None else "op",
                children=children,
                line=line,
                text=_text(node),
            )
            if t == "augmented_assignment_expression" and left is not None:
                self.destructure(left, result, line)
            return result
        if t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if right is None:
                return Expr("other", line=line)
            target_hint = _text(left) if left is not None and left.type == "identifier" else ""
            value = self.expr(right, register=register, hint=target_hint or hint)
            if left is not None:
                self.destructure(left, value, line)
                self.note_export_assignment(left, value)
            return value
        if t == "ternary_expression":
            cons = node.child_by_field_name("consequence")
            alt = node.child_by_field_name("alternative")
            self.field_expr(node, "condition")
            children = tuple(self.expr(c, register=register) for c in (cons, alt) if c is not None)
            return Expr("other", children=children, line=line, text=_text(node))
        if t in _FUNCTION_TYPES:
            fn = self.function(node, hint=hint, exported=exported)
            key = f"{fn.name}@{line}:{node.start_point.column}"
            self.inline[key] = fn
            return Expr("function", name=key, line=line, text=_text(node)[:60])
        if t in _CLASS_TYPES:
            self.class_body(node, exported=exported)
            return Expr("other", line=line)
        if t in ("unary_expression", "update_expression"):
            for c in node.named_children:
                self.expr(c, register=register)
            return Expr("other", line=line, text=_text(node))
        if t == "sequence_expression":
            return Expr(
                "other",
                children=tuple(self.expr(c, register=register) for c in node.named_children),
                line=line,
            )
        children = tuple(
            self.expr(c, register=register) for c in node.named_children if c.type in _EXPR_TYPES
        )
        return Expr("other", children=children, line=line, text=_text(node))

    def call(self, node: Node, *, register: bool) -> Expr:
        line = _line(node)
        callee_node = node.child_by_field_name("function") or node.child_by_field_name(
            "constructor"
        )
        args_node = node.child_by_field_name("arguments")
        callee = (
            self.expr(callee_node, register=register)
            if callee_node is not None
            else Expr("other", line=line)
        )
        args: list[Expr] = []
        if args_node is not None:
            if args_node.type == "template_string":  # tagged template: sql`...${x}`
                args.append(self.expr(args_node, register=register))
            else:
                args.extend(
                    self.expr(a, register=register)
                    for a in args_node.named_children
                    if a.type not in _SKIP_TYPES
                )
        # ``require("m")`` becomes the module name itself so ``require("fs").readFile``
        # resolves to the ``fs.readFile`` sink and ``const fs = require("fs")`` binds ``fs``.
        if (
            node.type == "call_expression"
            and callee.kind == "name"
            and callee.name == "require"
            and args
            and args[0].kind == "literal"
        ):
            return Expr(
                "name", name=_module_name(_unquote(args[0].text)), line=line, text=_text(node)
            )
        kind: ExprKind = "new" if node.type == "new_expression" else "call"
        call = Expr(kind, children=(callee, *args), line=line, text=_text(node))
        if register:
            self.fn.calls.append(call)
        return call

    def object(self, node: Node, *, register: bool) -> Expr:
        line = _line(node)
        values: list[Expr] = []
        kwargs: list[tuple[str, Expr]] = []
        for child in node.named_children:
            if child.type == "pair":
                key_node = child.child_by_field_name("key")
                value = child.child_by_field_name("value")
                if value is None:
                    continue
                key_text = _unquote(_text(key_node)) if key_node is not None else ""
                v = self.expr(value, register=register, hint=key_text)
                values.append(v)
                if key_text:
                    kwargs.append((key_text, v))
            elif child.type == "shorthand_property_identifier":
                v = Expr("name", name=_text(child), line=_line(child), text=_text(child))
                values.append(v)
                kwargs.append((_text(child), v))
            elif child.type == "method_definition":
                fn = self.function(child, owner="")
                inline_key = f"{fn.name}@{_line(child)}:{child.start_point.column}"
                self.inline[inline_key] = fn
                v = Expr("function", name=inline_key, line=_line(child))
                values.append(v)
                kwargs.append((fn.name, v))
            elif child.type == "spread_element":
                inner = _first_expr_child(child)
                if inner is not None:
                    values.append(self.expr(inner, register=register))
        return Expr(
            "collection", children=tuple(values), kwargs=tuple(kwargs), line=line, text=_text(node)
        )

    def note_export_assignment(self, left: Node, value: Expr) -> None:
        """``exports.handler = fn`` / ``module.exports = fn`` / ``module.exports = { handler }``."""
        target = _text(left)
        if not (target.startswith("exports.") or target.startswith("module.exports")):
            return
        exported_as = target.rsplit(".", 1)[-1] if "." in target else "default"
        if target == "module.exports":
            exported_as = "default"
        if value.kind == "function":
            fn = self.inline.get(value.name)
            if fn is not None:
                fn.exported = True
                if exported_as == "default":
                    self.default_export = fn.name
                elif fn.name.startswith("<anonymous"):
                    fn.name = exported_as
        elif value.kind == "name":
            self.exported_names.add(value.name)
            if exported_as == "default":
                self.default_export = value.name
        elif value.kind == "collection":
            for key, v in value.kwargs:
                if v.kind == "name":
                    self.exported_names.add(v.name)
                elif v.kind == "function" and (fn := self.inline.get(v.name)) is not None:
                    fn.exported = True
                    if fn.name.startswith("<anonymous"):
                        fn.name = key

    # -- entry points -----------------------------------------------------------------
    def finish(self) -> None:
        for fn in self.module.functions:
            if fn.name in self.exported_names or fn.name == self.default_export:
                fn.exported = True
        self.mark_registrations()
        for fn in self.module.functions:
            if fn.is_module or fn.entry is not None:
                continue
            fn.entry = _decorator_entry(self.module, fn) or _exported_entry(fn, self.default_export)
        for fn in self.module.functions:
            if fn.is_module or fn.entry is not None:
                continue
            if fn.params and fn.params[0] in JS_REQUEST_PARAM_NAMES:
                fn.entry = _request_entry(fn, "request-param", f"parameter {fn.params[0]!r}")

    def mark_registrations(self) -> None:
        """Route / middleware / server / event registrations anywhere in the module."""
        for fn in list(self.module.functions):
            for call in fn.calls:
                self.registration(call)

    def registration(self, call: Expr) -> None:
        if call.kind != "call":
            return
        path = self.module.resolve(chain(call))
        last = last_segment(path)
        rcv = receiver(path)
        callee = call.callee
        chained_route = (
            callee is not None
            and callee.kind == "member"
            and callee.children
            and callee.children[0].kind == "call"
            and last_segment(chain(callee.children[0])) == "route"
        )
        functions = [a for a in call.args if a.kind == "function"]
        refs = [
            a
            for a in call.args[1:]
            if a.kind in ("name", "member") and chain(a) not in ("", "this")
        ]
        if last in JS_ROUTE_METHODS and (rcv or chained_route) and (functions or refs):
            if last == "route" and call.args and call.args[0].kind == "collection":
                self.hapi_route(call)
                return
            first = call.args[0] if call.args else None
            if chained_route and callee is not None:  # router.route("/b").post(fn)
                inner = callee.children[0]
                first = inner.args[0] if inner.args else None
            route = (
                _unquote(first.text)
                if first is not None and first.kind in ("literal", "format")
                else "*"
            )
            method = "USE" if last == "use" else last.upper()
            kind = "middleware" if last == "use" else "route"
            detail = f"{method} {route}"
            for arg in functions:
                fn = self.inline.get(arg.name)
                if fn is not None and (fn.entry is None or fn.entry.kind == "request-param"):
                    fn.entry = _request_entry(fn, kind, detail)
            for ref in refs:
                self.module.handler_refs.append(
                    HandlerRef(
                        name=last_segment(chain(ref)), line=call.line, detail=detail, kind="route"
                    )
                )
            return
        if path in JS_SERVER_FACTORIES:
            for arg in functions:
                fn = self.inline.get(arg.name)
                if fn is not None:
                    fn.entry = _request_entry(fn, "handler", "http.createServer request handler")
            return
        if last in ("on", "once", "addListener") and call.args and call.args[0].kind == "literal":
            root = rcv.split(".")[0] if rcv else ""
            if root not in JS_EVENT_RECEIVERS:
                return
            event = _unquote(call.args[0].text)
            for arg in functions:
                fn = self.inline.get(arg.name)
                if fn is None:
                    continue
                if event in ("request", "connection", "upgrade"):
                    fn.entry = _request_entry(fn, "handler", f"{root}.on({event!r})")
                else:
                    fn.entry = _data_entry(fn, "event", f"{root}.on({event!r})")

    def hapi_route(self, call: Expr) -> None:
        config = call.args[0]
        handler = config.kwarg("handler")
        method = config.kwarg("method")
        route = config.kwarg("path")
        detail = (
            f"{_unquote(method.text) if method else 'ANY'} {_unquote(route.text) if route else '*'}"
        )
        if handler is not None and handler.kind == "function":
            fn = self.inline.get(handler.name)
            if fn is not None:
                fn.entry = _request_entry(fn, "route", detail)
        elif handler is not None and chain(handler):
            self.module.handler_refs.append(
                HandlerRef(
                    name=last_segment(chain(handler)), line=call.line, detail=detail, kind="route"
                )
            )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _module_name(name: str) -> str:
    return name[5:] if name.startswith("node:") else name


def _is_require(node: Node) -> bool:
    if node.type in _TRANSPARENT:
        inner = _first_expr_child(node)
        return inner is not None and _is_require(inner)
    if node.type != "call_expression":
        return False
    fn = node.child_by_field_name("function")
    return fn is not None and _text(fn) == "require"


def _is_require_member(node: Node) -> bool:
    if node.type != "member_expression":
        return False
    obj = node.child_by_field_name("object")
    return obj is not None and _is_require(obj)


def _first_expr_child(node: Node) -> Node | None:
    for child in node.named_children:
        if child.type in _EXPR_TYPES:
            return child
    return None


def _decorator_expr(node: Node) -> Node:
    for child in node.named_children:
        if child.type in _EXPR_TYPES:
            return child
    return node


def _request_entry(fn: Function, kind: str, detail: str, *, any_prop: bool = False) -> EntryPoint:
    return EntryPoint(
        file=fn.file,
        line=fn.start,
        function=fn.name if not fn.owner else f"{fn.owner}.{fn.name}",
        kind=kind,
        detail=detail,
        tainted_params=(),
        request_params=fn.params[:1],
        request_props=None if any_prop else tuple(sorted(REQUEST_PROPS["javascript"])),
    )


def _data_entry(fn: Function, kind: str, detail: str) -> EntryPoint:
    return EntryPoint(
        file=fn.file,
        line=fn.start,
        function=fn.name if not fn.owner else f"{fn.owner}.{fn.name}",
        kind=kind,
        detail=detail,
        tainted_params=fn.params,
        request_params=(),
        request_props=None,
    )


def _decorator_entry(module: Module, fn: Function) -> EntryPoint | None:
    """NestJS-style ``@Get(':id') findOne(@Param('id') id)``: every parameter is input."""
    for dec in fn.decorators:
        path = module.resolve(chain(dec))
        last = last_segment(path).lower()
        if last in HTTP_VERBS or last in ("all", "route"):
            route = ""
            if dec.kind == "call" and dec.args and dec.args[0].kind == "literal":
                route = _unquote(dec.args[0].text)
            return _data_entry(fn, "route", f"{last.upper()} {route or '*'}")
    return None


def _exported_entry(fn: Function, default_export: str) -> EntryPoint | None:
    if not fn.exported or not fn.params:
        return None
    first = fn.params[0]
    is_default = fn.name == default_export
    named_handler = fn.name in JS_EXPORTED_HANDLER_NAMES
    if not (is_default or named_handler):
        return None
    if first in ("event", "evt"):
        return _request_entry(fn, "lambda", f"exported {fn.name}(event)", any_prop=True)
    if first in JS_REQUEST_PARAM_NAMES:
        return _request_entry(fn, "exported-handler", f"exported {fn.name}({first})")
    return None
