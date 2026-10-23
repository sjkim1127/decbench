"""Experimental declared-type facts and failure diagnosis, outside default scores.

Facts describe saved debug/recovery type graphs. They do not prove that a field
was accessed, a return ABI was recovered, or a program executes correctly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from decbench.metrics.cpp_type_graph import MAX_NODES, TypeGraph
from decbench.metrics.cpp_types import UnsupportedType

PROFILE = "cpp-declared-type-facts-v1-diagnostic"
MAX_FACTS = 4096
MAX_POINTER_HOPS = 2


@dataclass(frozen=True)
class TypeFact:
    path: tuple[str, ...]
    attribute: str
    value: int | str

    @property
    def key(self) -> tuple[str, ...]:
        return (*self.path, self.attribute)


@dataclass(frozen=True)
class FactGap:
    path: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class TypeFacts:
    facts: tuple[TypeFact, ...]
    gaps: tuple[FactGap, ...]


def extract_type_facts(graph: TypeGraph) -> TypeFacts:
    """Extract one side independently; field correspondence uses fixed offsets.

    Missing or unsupported members do not erase known enclosing facts. Neither
    type names nor node IDs are matching evidence. Arrays keep their boundaries.
    """
    if not 0 < len(graph.nodes) <= MAX_NODES:
        raise UnsupportedType("fact graph node bound exceeded")
    graph.validate()
    facts: dict[tuple[str, ...], TypeFact] = {}
    gaps: list[FactGap] = []
    work = 0

    def emit(path: tuple[str, ...], attribute: str, value: int | str) -> None:
        fact = TypeFact(path, attribute, value)
        if fact.key in facts:
            raise ValueError("ambiguous declared-type fact slot")
        if len(facts) >= MAX_FACTS:
            raise UnsupportedType("type fact expansion bound exceeded")
        facts[fact.key] = fact

    def members(key: str, offset: int, path: tuple[str, ...]) -> list[tuple[int, str]]:
        nonlocal work
        work += 1
        if work > MAX_FACTS:
            raise UnsupportedType("member expansion bound exceeded")
        node = graph.nodes[key]
        if not node.edges:
            gaps.append(FactGap(path, "empty_or_opaque_member_population"))
            return []
        spans = []
        leaves = []
        for edge in node.edges:
            if (
                edge.role not in {"field", "base"}
                or edge.virtual
                or edge.locator
                or edge.locator_type is not None
                or type(edge.offset_bits) is not int
                or edge.bit_width is not None
            ):
                gaps.append(FactGap(path, "special_or_unlocated_member"))
                continue
            target = graph.nodes[edge.target]
            start = offset + edge.offset_bits
            spans.append((start, start + target.size * 8))
            if target.size <= 0:
                gaps.append(FactGap(path, "zero_size_member"))
            elif target.kind == "record":
                leaves.extend(members(edge.target, start, path))
            else:
                leaves.append((start, edge.target))
        spans.sort()
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:], strict=False)):
            gaps.append(FactGap(path, "overlapping_member_population"))
            return []
        return leaves

    def visit(key: str, path: tuple[str, ...], pointer_hops: int) -> None:
        node = graph.nodes[key]
        if node.kind == "enum":
            visit(node.edges[0].target, path, pointer_hops)
            return
        kind = "pointer" if node.kind in {"lref", "rref"} else node.kind
        emit(path, "type_kind", kind)
        if node.size > 0:
            emit(path, "size_bytes", node.size)
        elif node.kind != "void":
            gaps.append(FactGap(path, "unknown_type_extent"))
        if kind == "pointer":
            if pointer_hops < MAX_POINTER_HOPS:
                visit(node.edges[0].target, (*path, "pointee"), pointer_hops + 1)
            else:
                gaps.append(FactGap((*path, "pointee"), "pointee_depth_bound"))
        elif kind == "array":
            target = node.edges[0].target
            emit(path, "array_count", node.count)
            emit(path, "array_stride_bytes", graph.nodes[target].size)
            visit(target, (*path, "element"), pointer_hops)
        elif kind == "record":
            for offset, target in members(key, 0, path):
                member_path = (*path, f"field@{offset}")
                emit(member_path, "field_offset_bits", offset)
                visit(target, member_path, pointer_hops)
        elif kind == "union":
            gaps.append(FactGap(path, "union_alternative_policy_unavailable"))
        elif kind not in {
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
            raise UnsupportedType("unsupported fact type kind")

    visit(graph.root, ("root",), 0)
    return TypeFacts(tuple(facts[key] for key in sorted(facts)), tuple(gaps))


def assess_recovery(
    expected: TypeFacts, actual: TypeFacts | None, previous_verdict: str
) -> dict[str, Any]:
    """Keep missing/invalid recovery in the fixed oracle fact denominator."""
    if not expected.facts:
        raise ValueError("no supported oracle facts")
    blocked = {
        "unmatched": ("correspondence_failure", "no_proven_value_correspondence"),
        "unsupported_recovered_type": (
            "recovery_information_gap",
            "recovery_or_evaluator_support_unresolved",
        ),
        "invalid_producer_output": ("recovery_information_gap", "confirmed_invalid_output"),
        "inconsistent_recovered_storage_width": (
            "type_mismatch",
            "reported_storage_width_inconsistent",
        ),
    }
    if previous_verdict not in {*blocked, "correct", "type_mismatch"}:
        raise ValueError("unknown saved type verdict")
    if previous_verdict in {"correct", "type_mismatch"} and actual is None:
        raise ValueError("saved typed decision has no recovered graph")
    available = {fact.key: fact for fact in actual.facts} if actual else {}
    decisions = []
    for fact in expected.facts:
        recovered = available.get(fact.key) if previous_verdict not in blocked else None
        status = (
            "missing"
            if recovered is None
            else "correct" if recovered.value == fact.value else "mismatch"
        )
        decisions.append(
            {
                **asdict(fact),
                "actual": recovered.value if recovered else None,
                "status": status,
            }
        )
    correct = sum(row["status"] == "correct" for row in decisions)
    mismatched = sum(row["status"] == "mismatch" for row in decisions)
    missing = len(decisions) - correct - mismatched
    if previous_verdict in blocked:
        category, reason = blocked[previous_verdict]
    elif mismatched:
        category, reason = "type_mismatch", "observed_type_facts_differ"
    elif missing:
        category, reason = "recovery_information_gap", "recovered_type_facts_unavailable"
    elif previous_verdict == "type_mismatch":
        category, reason = "representation_difference", "outside_assessed_fact_contract"
    else:
        category, reason = "correct", "original_type_and_assessed_facts_agree"
    if previous_verdict == "correct" and (mismatched or missing):
        raise ValueError("fact projection disagrees with an existing exact type match")
    return {
        "category": category,
        "reason": reason,
        "correct_facts": correct,
        "total_facts": len(decisions),
        "mismatched_facts": mismatched,
        "missing_facts": missing,
        "facts": decisions,
        "oracle_fact_gaps": [asdict(gap) for gap in expected.gaps],
        "recovered_fact_gaps": [asdict(gap) for gap in actual.gaps] if actual else [],
        "unscored_recovered_fact_slots": sorted(
            set(available) - {fact.key for fact in expected.facts}
        ),
    }
