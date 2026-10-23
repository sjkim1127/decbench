"""Native debug formal roles and bounded declared-return recovery.

Debug formal order is not a certified physical calling convention. Aggregate
returns and uncertain declarators abstain rather than inventing hidden slots.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from decbench.metrics.cpp_recovered_types import RecoveredTypeContext
from decbench.metrics.cpp_type_graph import TypeGraph, dwarf_graph, pdb_graph, primitive_graph
from decbench.metrics.cpp_types import UnsupportedType, parse_type
from decbench.metrics.variable_features import _parse_source, _text, _walk
from decbench.utils import binfmt
from decbench.utils.native_code import entry_address_candidates
from decbench.utils.pdb_info import _unpack


@dataclass(frozen=True)
class DebugVariableRole:
    identity: str
    role: str
    debug_formal_index: int | None = None
    artificial: bool | None = None


@dataclass(frozen=True)
class SignatureEvidence:
    address: int
    debug_format: str
    roles: tuple[DebugVariableRole, ...]
    declared_return: TypeGraph | None
    return_exclusion: str | None
    abi_slots_verified: bool = False


def native_signature(context: Any, address: int, data_model: str) -> SignatureEvidence:
    """Read the function at the requested native entry, never by display name."""
    context.validate(context.path)
    roles = []
    return_graph = None
    exclusion = None
    if context.dwarf is not None:
        candidates = {
            die.offset: die
            for entry in entry_address_candidates(
                address, context.info.arch if context.info else ""
            )
            for die in context.index.get(entry, [])
        }
        if len(candidates) != 1:
            raise UnsupportedType("DWARF function missing or entry identity ambiguous")
        function = next(iter(candidates.values()))
        ordinal = 0

        def walk(parent: Any) -> None:
            nonlocal ordinal
            for child in parent.iter_children():
                if child.tag == "DW_TAG_lexical_block":
                    walk(child)
                elif child.tag in {"DW_TAG_formal_parameter", "DW_TAG_variable"}:
                    formal = parent is function and child.tag == "DW_TAG_formal_parameter"
                    artificial = binfmt.die_attr(
                        child, "DW_AT_artificial", follow_abstract_origin=True
                    )
                    roles.append(
                        DebugVariableRole(
                            f"dwarf:0x{child.offset:x}",
                            "formal_parameter" if formal else "local",
                            ordinal if formal else None,
                            bool(artificial.value) if artificial else False,
                        )
                    )
                    if formal:
                        ordinal += 1

        walk(function)
        try:
            return_graph = dwarf_graph(function, data_model)
        except UnsupportedType as exc:
            exclusion = str(exc)
        debug_format = "dwarf"
    elif context.pdb is not None:
        function = context.pdb.at_address(address)
        if function is None:
            raise UnsupportedType("PDB function missing or entry identity ambiguous")
        for variable in function.variables:
            role = (
                "formal_parameter"
                if variable.is_parameter is True
                else "local" if variable.is_parameter is False else "unknown"
            )
            roles.append(DebugVariableRole(variable.identity, role))
        signature = (
            context.pdb.types.records.get(function.signature_type_index)
            if context.pdb.types
            else None
        )
        if signature is None or signature[0] not in {0x1008, 0x1009}:
            exclusion = "PDB declared return signature unavailable"
        else:
            try:
                return_graph = pdb_graph(
                    context.pdb.types, _unpack("<I", signature[1])[0], data_model
                )
            except UnsupportedType as exc:
                exclusion = str(exc)
        debug_format = "pdb"
    else:
        raise UnsupportedType("no readable native signature oracle")
    if return_graph and return_graph.nodes[return_graph.root].kind in {"record", "union", "array"}:
        return_graph = None
        exclusion = "aggregate return requires explicit ABI lowering evidence"
    context.validate(context.path)
    return SignatureEvidence(address, debug_format, tuple(roles), return_graph, exclusion)


def recovered_return(code: str, data_model: str) -> TypeGraph:
    """Parse a single isolated definition; preserve pointer/reference declarators."""
    source = code.encode()
    tree = _parse_source(source)
    definitions = [node for node in _walk(tree.root_node) if node.type == "function_definition"]
    if len(definitions) != 1 or definitions[0].has_error:
        raise UnsupportedType("one error-free recovered definition required")
    function = definitions[0]
    body = function.child_by_field_name("body")
    header = source[function.start_byte : body.start_byte] if body is not None else source
    if re.search(rb"\b(?:__attribute__|__declspec|alignas|__ptr32|__ptr64|__based)\b|\[\[", header):
        raise UnsupportedType("attributed return requires explicit target evidence")
    ty = function.child_by_field_name("type")
    declarator = function.child_by_field_name("declarator")
    if ty is None or ty.type not in {
        "primitive_type",
        "sized_type_specifier",
        "type_identifier",
        "qualified_identifier",
        "struct_specifier",
        "union_specifier",
    }:
        raise UnsupportedType("unsupported recovered return type syntax")
    suffix = []
    while declarator is not None and declarator.type in {
        "pointer_declarator",
        "reference_declarator",
    }:
        if any(c.type == "type_qualifier" for c in declarator.named_children):
            raise UnsupportedType("qualified return indirection needs explicit evidence")
        suffix.append(
            "*"
            if declarator.type == "pointer_declarator"
            else "&&" if _text(declarator, source).lstrip().startswith("&&") else "&"
        )
        child = declarator.child_by_field_name("declarator")
        if child is None:
            named = declarator.named_children
            child = named[0] if len(named) == 1 else None
        declarator = child
    if declarator is None or declarator.type != "function_declarator":
        raise UnsupportedType("unsupported recovered function declarator")
    name = declarator.child_by_field_name("declarator")
    if name is None or name.type not in {"identifier", "qualified_identifier", "operator_name"}:
        raise UnsupportedType("function/member pointer return unsupported")
    if any(
        c.type in {"trailing_return_type", "attribute_specifier"} for c in declarator.named_children
    ):
        raise UnsupportedType("trailing or attributed return requires explicit evidence")
    qualifiers = " ".join(
        _text(c, source) for c in function.named_children if c.type == "type_qualifier"
    )
    spelling = " ".join(v for v in (qualifiers, _text(ty, source)) if v) + "".join(suffix)
    try:
        graph = primitive_graph(parse_type(spelling, data_model))
    except UnsupportedType:
        graph = RecoveredTypeContext(code, data_model).graph(spelling)
    if graph.nodes[graph.root].kind in {"record", "union", "array"}:
        raise UnsupportedType("aggregate return requires explicit ABI lowering evidence")
    return graph
