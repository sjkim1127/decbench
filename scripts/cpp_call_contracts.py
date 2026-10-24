"""Caller-owned declaration evidence for the unregistered recompilation profile."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from tree_sitter import Node

from decbench.metrics.variable_features import (
    _declarator_identifier,
    _parse_source,
    _walk,
)

_DIRECT_NAME = re.compile(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*")


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode()


def _function_declarator(node: Node | None) -> Node | None:
    while node is not None and node.type in {"pointer_declarator", "attributed_declarator"}:
        node = node.child_by_field_name("declarator")
    if node is None or node.type != "function_declarator":
        return None
    name = node.child_by_field_name("declarator")
    return (
        node if name is not None and name.type in {"identifier", "qualified_identifier"} else None
    )


def _arity(declarator: Node | None, source: bytes, definition: bool = False) -> dict:
    if declarator is None or declarator.has_error:
        return {"kind": "unknown"}
    parameters = declarator.child_by_field_name("parameters")
    if parameters is None:
        return {"kind": "unknown"}
    children = [n for n in parameters.named_children if n.type != "comment"]
    if not children:
        return {"kind": "fixed", "count": 0} if definition else {"kind": "unspecified"}
    if len(children) == 1 and _text(children[0], source).strip() == "void":
        return {"kind": "fixed", "count": 0}
    if any(n.type not in {"parameter_declaration", "variadic_parameter"} for n in children):
        return {"kind": "unknown"}
    variadic = any(n.type == "variadic_parameter" for n in children)
    return {
        "kind": "variadic" if variadic else "fixed",
        "count": sum(n.type == "parameter_declaration" for n in children),
    }


def _accepts(arity: dict, count: int) -> bool | None:
    if arity["kind"] == "fixed":
        return count == int(arity["count"])
    if arity["kind"] == "variadic":
        return count >= int(arity["count"])
    return None


def _prototype_arity(prototype: str | None) -> dict:
    if prototype is None:
        return {"kind": "unavailable"}
    source = prototype.encode()
    tree = _parse_source(source)
    declarators = [n for n in _walk(tree.root_node) if _function_declarator(n) == n]
    return _arity(declarators[0], source) if len(declarators) == 1 else {"kind": "unknown"}


@dataclass(frozen=True)
class _Binding:
    name: str
    kind: str
    visible: int
    scope_start: int
    scope_end: int
    depth: int
    declaration: str
    arity: dict


def _scope(node: Node) -> tuple[int, int, int]:
    parent = node.parent
    while parent is not None and parent.type not in {
        "compound_statement",
        "for_statement",
        "translation_unit",
        "namespace_definition",
    }:
        parent = parent.parent
    if parent is None:
        raise ValueError("caller declaration has no lexical scope")
    depth, ancestor = 0, parent
    while ancestor.parent is not None:
        depth += 1
        ancestor = ancestor.parent
    return parent.start_byte, parent.end_byte, depth


def analyze_calls(code: str, prototypes: dict[str, str]) -> dict[str, Any]:
    """External context never overrides a producer declaration, object or macro.

    File-scope injection is withheld for every caller-bound spelling, including
    out-of-scope declarations. This conservative bound avoids introducing a new
    conflict elsewhere; it does not pretend an unrelated binding resolves a call.
    """
    source = code.encode()
    tree = _parse_source(source)
    bindings: list[_Binding] = []
    macros = set()
    for node in _walk(tree.root_node):
        if node.type in {"preproc_def", "preproc_function_def"}:
            macro_name = node.child_by_field_name("name")
            if macro_name is not None:
                macros.add(_text(macro_name, source))
        if node.type not in {"declaration", "function_definition", "parameter_declaration"}:
            continue
        if node.has_error:
            continue
        if node.type == "parameter_declaration":
            ancestor = node.parent
            while ancestor is not None and ancestor.type not in {
                "declaration",
                "function_definition",
                "parameter_declaration",
            }:
                ancestor = ancestor.parent
            if ancestor is None or ancestor.type != "function_definition":
                continue
            body = ancestor.child_by_field_name("body")
            if body is None:
                continue
            scope_start, scope_end, depth = _scope(node)
            scope_start, scope_end, depth = body.start_byte, body.end_byte, depth + 1
        else:
            scope_start, scope_end, depth = _scope(node)
        for index, declarator in enumerate(node.children):
            if node.field_name_for_child(index) != "declarator":
                continue
            identifier = _declarator_identifier(declarator)
            if identifier is None:
                continue
            name = _text(identifier, source)
            if not _DIRECT_NAME.fullmatch(name):
                continue
            function = _function_declarator(declarator)
            end = node.child_by_field_name("body") if node.type == "function_definition" else None
            declaration = source[
                node.start_byte : end.start_byte if end else node.end_byte
            ].decode()
            bindings.append(
                _Binding(
                    name,
                    "function" if function is not None else "object_or_function_pointer",
                    identifier.end_byte,
                    scope_start,
                    scope_end,
                    depth,
                    declaration,
                    _arity(function, source, node.type == "function_definition"),
                )
            )
    bound_names = {b.name for b in bindings} | macros
    calls = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        callee, arguments = node.child_by_field_name("function"), node.child_by_field_name(
            "arguments"
        )
        if callee is None or arguments is None:
            continue
        name = _text(callee, source)
        direct = callee.type in {"identifier", "qualified_identifier"} and bool(
            _DIRECT_NAME.fullmatch(name)
        )
        argument_count = len([n for n in arguments.named_children if n.type != "comment"])
        row: dict[str, Any] = {
            "start_byte": node.start_byte,
            "end_byte": node.end_byte,
            "line": source.count(b"\n", 0, node.start_byte) + 1,
            "callee": name,
            "argument_count": argument_count,
            "direct": direct,
        }
        if not direct:
            row["resolution"] = "indirect_or_unsupported_expression"
            calls.append(row)
            continue
        visible = [
            b
            for b in bindings
            if b.name == name
            and b.visible <= node.start_byte
            and b.scope_start <= node.start_byte < b.scope_end
        ]
        if name in macros:
            row["resolution"] = "producer_macro_unexpanded"
        elif visible:
            nearest = max(b.depth for b in visible)
            selected = [b for b in visible if b.depth == nearest]
            row["caller_bindings"] = [
                {
                    "kind": b.kind,
                    "declaration": b.declaration,
                    "arity": b.arity,
                    "scope": [b.scope_start, b.scope_end],
                    "visible_from": b.visible,
                }
                for b in selected
            ]
            if any(b.kind != "function" for b in selected):
                row["resolution"] = "caller_object_or_function_pointer"
            elif len(selected) != 1:
                row["resolution"] = "multiple_caller_declarations"
            else:
                row["resolution"] = "caller_function_declaration"
                row["caller_arity_accepts"] = _accepts(selected[0].arity, argument_count)
        elif name.startswith("__builtin_"):
            row["resolution"] = "compiler_builtin"
        elif name in bound_names:
            row["resolution"] = "caller_binding_outside_visible_scope"
        elif tree.root_node.has_error:
            row["resolution"] = "unresolved_parser_context"
        else:
            row["resolution"] = "external_context" if name in prototypes else "missing_context"
        if name in prototypes:
            arity = _prototype_arity(prototypes[name])
            row["external_prototype"] = prototypes[name]
            row["external_arity"] = arity
            row["external_arity_accepts"] = _accepts(arity, argument_count)
        row["external_injection_allowed"] = (
            name not in bound_names
            and not name.startswith("__builtin_")
            and not tree.root_node.has_error
        )
        calls.append(row)
    if tree.root_node.has_error:
        bound_names.update(row["callee"] for row in calls if row["direct"])
    return {
        "schema": "caller-lexical-contract-v1",
        "calls": calls,
        "blocked_injection_names": sorted(bound_names),
        "scope_or_syntax_incomplete": tree.root_node.has_error,
        "type_compatibility_proven": False,
    }
