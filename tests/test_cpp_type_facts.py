"""Fact denominators, identity independence and bounded failure diagnosis."""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from decbench.metrics.cpp_recovered_types import RecoveredTypeContext
from decbench.metrics.cpp_type_facts import TypeFacts, assess_recovery, extract_type_facts
from decbench.metrics.cpp_type_graph import TypeEdge, TypeGraph, TypeNode
from decbench.metrics.cpp_types import UnsupportedType
from scripts.report_cpp_type_diagnostics import markdown, report, saved_graph


def scalar(kind: str = "signed", size: int = 4) -> TypeGraph:
    return TypeGraph("root", {"root": TypeNode(kind, size)})


def pointer() -> TypeGraph:
    graph = scalar()
    graph.nodes["pointer"] = TypeNode("pointer", 8, edges=(TypeEdge("element", "root"),))
    return replace(graph, root="pointer")


def test_atomic_width_credit_never_establishes_pointer_correctness() -> None:
    expected = extract_type_facts(pointer())
    actual = extract_type_facts(scalar("unsigned", 8))
    result = assess_recovery(expected, actual, "type_mismatch")
    assert result["category"] == "type_mismatch"
    assert result["correct_facts"] == 1
    assert result["mismatched_facts"] == 1 and result["missing_facts"] == 2


@pytest.mark.parametrize("kind", ["lref", "rref"])
def test_reference_projection_preserves_original_graph(kind: str) -> None:
    graph = pointer()
    graph.nodes["pointer"] = replace(graph.nodes["pointer"], kind=kind)
    original = copy.deepcopy(graph)
    assert extract_type_facts(graph) == extract_type_facts(pointer())
    assert graph == original


@pytest.mark.parametrize(
    "verdict,category",
    [
        ("unmatched", "correspondence_failure"),
        ("unsupported_recovered_type", "recovery_information_gap"),
        ("invalid_producer_output", "recovery_information_gap"),
        ("inconsistent_recovered_storage_width", "type_mismatch"),
    ],
)
def test_failure_categories_keep_all_oracle_facts(verdict: str, category: str) -> None:
    facts = extract_type_facts(pointer())
    result = assess_recovery(facts, facts, verdict)
    assert result["category"] == category
    assert result["correct_facts"] == 0 and result["total_facts"] == 4


def test_plain_c_fields_and_inheritance_have_the_same_atomic_contract() -> None:
    derived = TypeGraph(
        "object",
        {
            "object": TypeNode(
                "record",
                8,
                edges=(
                    TypeEdge("base", "base", offset_bits=0),
                    TypeEdge("field", "int", offset_bits=32),
                ),
            ),
            "base": TypeNode("record", 4, edges=(TypeEdge("field", "int", offset_bits=0),)),
            "int": TypeNode("signed", 4),
        },
    )
    flat = RecoveredTypeContext("struct X { int x; int y; };", "LP64").graph("X")
    assert derived.project("abi") != flat.project("abi")
    result = assess_recovery(extract_type_facts(derived), extract_type_facts(flat), "type_mismatch")
    assert result["correct_facts"] == result["total_facts"]
    assert result["category"] == "representation_difference"


def test_missing_field_is_information_gap_and_wrong_field_is_mismatch() -> None:
    graph = RecoveredTypeContext("struct X { int x; int y; };", "LP64").graph("X")
    incomplete = copy.deepcopy(graph)
    incomplete.nodes[graph.root] = replace(
        graph.nodes[graph.root], edges=graph.nodes[graph.root].edges[:1]
    )
    result = assess_recovery(
        extract_type_facts(graph), extract_type_facts(incomplete), "type_mismatch"
    )
    assert result["category"] == "recovery_information_gap"
    assert result["missing_facts"] == 3
    wrong = RecoveredTypeContext("struct X { int x; unsigned int y; };", "LP64").graph("X")
    result = assess_recovery(extract_type_facts(graph), extract_type_facts(wrong), "type_mismatch")
    assert result["category"] == "type_mismatch" and result["mismatched_facts"] == 1


def test_empty_or_special_object_preserves_known_facts_and_records_gaps() -> None:
    empty = TypeGraph("object", {"object": TypeNode("record", 8)})
    facts = extract_type_facts(empty)
    assert len(facts.facts) == 2 and facts.gaps
    special = copy.deepcopy(empty)
    special.nodes["int"] = TypeNode("signed", 4)
    special.nodes["object"] = replace(
        special.nodes["object"],
        edges=(TypeEdge("base", "int", virtual=True, locator="native:opaque"),),
    )
    facts = extract_type_facts(special)
    assert len(facts.facts) == 2 and facts.gaps


def test_arrays_keep_extent_and_member_offsets_are_type_blind() -> None:
    a = RecoveredTypeContext("struct X { int a[2]; };", "LP64").graph("X")
    b = RecoveredTypeContext("struct X { int x; int y; };", "LP64").graph("X")
    result = assess_recovery(extract_type_facts(a), extract_type_facts(b), "type_mismatch")
    assert result["category"] == "type_mismatch"
    assert any(
        f["attribute"] == "array_count" and f["status"] == "missing" for f in result["facts"]
    )
    shifted = copy.deepcopy(b)
    shifted.nodes[b.root] = replace(
        b.nodes[b.root],
        size=12,
        edges=(
            b.nodes[b.root].edges[0],
            replace(b.nodes[b.root].edges[1], offset_bits=64),
        ),
    )
    result = assess_recovery(extract_type_facts(b), extract_type_facts(shifted), "type_mismatch")
    assert any(
        f["attribute"] == "field_offset_bits" and f["status"] == "missing" for f in result["facts"]
    )


def recursive_graph(two_records: bool) -> TypeGraph:
    nodes = {
        "a": TypeNode("record", 8, edges=(TypeEdge("field", "pa", offset_bits=0),)),
        "pa": TypeNode("pointer", 8, edges=(TypeEdge("element", "a"),)),
    }
    if two_records:
        nodes["b"] = replace(nodes["a"], edges=(TypeEdge("field", "pb", offset_bits=0),))
        nodes["pb"] = nodes["pa"]
        nodes["pa"] = replace(nodes["pa"], edges=(TypeEdge("element", "b"),))
    return TypeGraph("a", nodes)


def test_type_node_sharing_and_ids_are_not_comparison_evidence() -> None:
    a, b = recursive_graph(False), recursive_graph(True)
    assert a.project("abi") == b.project("abi")
    assert extract_type_facts(a).facts == extract_type_facts(b).facts
    assert any(gap.reason == "pointee_depth_bound" for gap in extract_type_facts(a).gaps)
    assert (
        assess_recovery(extract_type_facts(a), extract_type_facts(b), "correct")["category"]
        == "correct"
    )


def test_bounds_and_internal_inconsistency_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError):
        assess_recovery(TypeFacts((), ()), None, "unmatched")
    facts = extract_type_facts(pointer())
    with pytest.raises(ValueError):
        assess_recovery(facts, None, "type_mismatch")
    with pytest.raises(ValueError):
        assess_recovery(facts, facts, "unknown")
    with pytest.raises(ValueError):
        assess_recovery(facts, extract_type_facts(scalar()), "correct")
    with pytest.raises(ValueError):
        saved_graph({"root": "missing", "nodes": {"i": {**asdict(TypeNode("signed", 4))}}})
    monkeypatch.setattr("decbench.metrics.cpp_type_facts.MAX_FACTS", 1)
    with pytest.raises(UnsupportedType):
        extract_type_facts(pointer())


def cell_report() -> dict:
    decision = {
        "identity": "oracle:0",
        "matched_identity": "producer:0",
        "verdict": "correct",
        "expected": asdict(pointer()),
        "actual": asdict(pointer()),
    }
    value = {
        "value": 1,
        "metadata": {
            "decisions": [decision],
            "ground_truth_count": 1,
            "matched_count": 1,
            "correct_count": 1,
            "data_model": "LP64",
        },
    }
    profile = {
        "perfect_count": 1,
        "function_results": {"f": value},
        "errors": ["excluded: unavailable"],
    }
    return {
        "cell": "cell",
        "requested": 2,
        "tools": {
            tool: {
                "function_addresses": {"f": 4096, "excluded": 8192},
                "profiles": {view: copy.deepcopy(profile) for view in ("source", "abi")},
            }
            for tool in ("fission", "kuna", "ghidra", "angr")
        },
    }


def test_three_numbers_have_fixed_denominators_and_no_invented_capabilities(tmp_path: Path) -> None:
    path = tmp_path / "cell.json"
    path.write_text(json.dumps(cell_report()))
    result = report([path])
    for summary in result["summary"].values():
        assert summary["oracle_coverage"] == 0.5
        assert summary["fact_recall"] == 1
        assert summary["strict_abi_perfect_rate"] == 1
    assert result["capabilities"]["return_type_facts"] == "not measured"
    assert result["capabilities"]["actual_accessed_field_facts"] == "not measured"
    assert "1/2" in markdown(result)
    assert len(result["rows"]) == 8


@pytest.mark.parametrize(
    "mutation",
    [
        "requested",
        "duplicate_cell",
        "duplicate_address",
        "missing_exclusion",
        "bad_aggregate",
        "bad_score",
        "different_oracle",
        "different_correspondence",
        "duplicate_variable",
    ],
)
def test_corrupt_or_producer_dependent_evidence_fails(tmp_path: Path, mutation: str) -> None:
    cell = cell_report()
    tool = cell["tools"]["angr"]
    abi = tool["profiles"]["abi"]
    meta = abi["function_results"]["f"]["metadata"]
    if mutation == "requested":
        tool["function_addresses"]["excluded"] = 12288
    elif mutation == "duplicate_address":
        tool["function_addresses"]["excluded"] = 4096
    elif mutation == "missing_exclusion":
        abi["errors"] = []
    elif mutation == "bad_aggregate":
        abi["perfect_count"] = 0
    elif mutation == "bad_score":
        meta["correct_count"] = 0
    elif mutation == "different_oracle":
        meta["decisions"][0]["expected"]["nodes"]["root"]["kind"] = "unsigned"
        meta["decisions"][0]["actual"]["nodes"]["root"]["kind"] = "unsigned"
    elif mutation == "different_correspondence":
        meta["decisions"][0]["matched_identity"] = "other"
    elif mutation == "duplicate_variable":
        meta["decisions"] *= 2
        meta["ground_truth_count"] = 2
    path = tmp_path / "cell.json"
    path.write_text(json.dumps(cell))
    paths = [path, path] if mutation == "duplicate_cell" else [path]
    with pytest.raises(ValueError):
        report(paths)


def test_empty_eligible_population_is_unmeasurable_not_zero(tmp_path: Path) -> None:
    cell = cell_report()
    for producer in cell["tools"].values():
        for profile in producer["profiles"].values():
            profile.update(
                perfect_count=0,
                function_results={},
                errors=["f: unavailable", "excluded: unavailable"],
            )
    path = tmp_path / "cell.json"
    path.write_text(json.dumps(cell))
    result = report([path])
    assert all(s["fact_recall"] is None for s in result["summary"].values())
