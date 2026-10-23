"""Experimental field-layout projection, independent of the registered metrics.

Fixed-offset record members and ordinary bases become typed leaves at absolute
bit offsets. Arrays retain extent/stride; pointers retain recursive pointees.
This compares field storage, not alignment, calling ABI or C++ execution.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from decbench.metrics.cpp_type_graph import MAX_NODES, TypeEdge, TypeGraph, TypeNode
from decbench.metrics.cpp_types import UnsupportedType

PROFILE = "cpp-field-layout-v1-experimental"
MAX_LEAVES = 4096


@dataclass(frozen=True)
class FieldOrigin:
    record: str
    path: tuple[int, ...]
    offset_bits: int
    target: str


@dataclass(frozen=True)
class FieldLayout:
    graph: TypeGraph
    origins: tuple[FieldOrigin, ...]
    profile: str = PROFILE


def normalize_field_layout(graph: TypeGraph, data_model: str) -> FieldLayout:
    """Project one graph without access to its counterpart or correspondence.

    Original source graphs remain untouched. Unsupported oracle layouts must be
    reported separately; unsupported recovery must not remove an eligible row.
    """
    if data_model not in {"LP64", "LLP64", "ILP32"}:
        raise ValueError("explicit data model required")
    if not 0 < len(graph.nodes) <= MAX_NODES:
        raise UnsupportedType("field layout node bound exceeded")
    graph.validate()
    nodes: dict[str, TypeNode] = {}
    origins: list[FieldOrigin] = []
    leaves = 0

    def flatten(
        key: str, offset: int, path: tuple[int, ...]
    ) -> list[tuple[int, str, tuple[int, ...]]]:
        nonlocal leaves
        node = graph.nodes[key]
        if node.kind != "record":
            leaves += 1
            if leaves > MAX_LEAVES:
                raise UnsupportedType("field layout expansion bound exceeded")
            return [(offset, key, path)]
        if not node.edges:
            raise UnsupportedType("empty or opaque record storage")
        spans = []
        result = []
        for index, edge in enumerate(node.edges):
            if edge.virtual or edge.locator or edge.locator_type is not None:
                raise UnsupportedType("virtual or computed member storage")
            if edge.role not in {"field", "base"} or edge.bit_width is not None:
                raise UnsupportedType("special member storage")
            if type(edge.offset_bits) is not int:
                raise UnsupportedType("unknown member offset")
            child = graph.nodes[edge.target]
            if edge.role == "base" and child.kind != "record":
                raise UnsupportedType("ordinary base must be a complete record")
            if child.size <= 0:
                raise UnsupportedType("zero-size member storage")
            spans.append((edge.offset_bits, edge.offset_bits + child.size * 8))
            result.extend(flatten(edge.target, offset + edge.offset_bits, (*path, index)))
        spans.sort()
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:], strict=False)):
            raise UnsupportedType("overlapping member or base storage")
        return result

    def visit(key: str) -> str:
        if key in nodes:
            return key
        node = graph.nodes[key]
        if node.kind in {"union", "pending"}:
            raise UnsupportedType("unsupported union or incomplete layout")
        if node.kind in {"pointer", "lref", "rref"}:
            if node.size != (4 if data_model == "ILP32" else 8):
                raise UnsupportedType("pointer width disagrees with data model")
        elif node.kind not in {
            "record",
            "array",
            "enum",
            "void",
            "signed",
            "unsigned",
            "char",
            "bool",
            "float",
            "char8_t",
            "char16_t",
            "char32_t",
        }:
            raise UnsupportedType("unsupported field type")
        nodes[key] = replace(node, name="", qualifiers=(), rank="", enumerators=())
        if node.kind == "record":
            fields = []
            for offset, target, path in flatten(key, 0, ()):
                fields.append(TypeEdge("field", visit(target), offset_bits=offset))
                origins.append(FieldOrigin(key, path, offset, target))
            nodes[key] = replace(nodes[key], edges=tuple(fields))
        elif node.kind in {"pointer", "lref", "rref", "array", "enum"}:
            if any(
                e.virtual
                or e.locator
                or e.locator_type is not None
                or e.offset_bits is not None
                or e.bit_width is not None
                for e in node.edges
            ):
                raise UnsupportedType("unexpected indirection or array metadata")
            target = visit(node.edges[0].target)
            if node.kind == "enum":
                if node.size != nodes[target].size:
                    raise UnsupportedType("enum extent disagrees with underlying storage")
                nodes[key] = nodes[target]
            else:
                nodes[key] = replace(
                    nodes[key],
                    kind="pointer" if node.kind in {"lref", "rref"} else node.kind,
                    edges=(TypeEdge("element", target),),
                )
        elif node.kind != "void" and node.size <= 0:
            raise UnsupportedType("unknown scalar extent")
        return key

    root = visit(graph.root)
    normalized = TypeGraph(root, nodes, view="abi")
    normalized.validate()
    return FieldLayout(normalized, tuple(origins))
