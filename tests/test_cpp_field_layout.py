"""Bounded storage equivalence and fail-closed layout controls."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from decbench.metrics.cpp_field_layout import normalize_field_layout
from decbench.metrics.cpp_recovered_types import RecoveredTypeContext
from decbench.metrics.cpp_type_graph import TypeEdge, TypeGraph, TypeNode, dwarf_graph
from decbench.metrics.cpp_types import UnsupportedType
from decbench.utils import binfmt
from scripts.audit_cpp_field_layout import TOOLS, audit, compare_decisions


def inherited() -> TypeGraph:
    return TypeGraph(
        "derived",
        {
            "derived": TypeNode(
                "record",
                8,
                "Derived",
                edges=(
                    TypeEdge("base", "base", offset_bits=0),
                    TypeEdge("field", "int", "y", 32),
                ),
            ),
            "base": TypeNode("record", 4, "Base", edges=(TypeEdge("field", "int", "x", 0),)),
            "int": TypeNode("signed", 4, rank="int"),
        },
    )


def flat() -> TypeGraph:
    return RecoveredTypeContext("struct Flat { int x; int y; };", "LP64").graph("Flat")


def test_inheritance_and_flat_fields_have_one_storage_view_without_mutation() -> None:
    a, b = inherited(), flat()
    before = copy.deepcopy(a)
    assert a.project("abi") != b.project("abi")
    left = normalize_field_layout(a, "LP64")
    assert left.graph == normalize_field_layout(b, "LP64").graph
    assert a == before
    assert [(o.path, o.offset_bits) for o in left.origins] == [((0, 0), 0), ((1,), 32)]
    assert normalize_field_layout(left.graph, "LP64").graph == left.graph


@pytest.mark.parametrize("mutation", ["type", "offset", "size", "missing", "depth"])
def test_flattening_does_not_erase_storage_errors(mutation: str) -> None:
    a, b = inherited(), flat()
    root = b.nodes[b.root]
    if mutation == "type":
        b.nodes[root.edges[0].target] = TypeNode("unsigned", 4)
    elif mutation == "offset":
        b.nodes[b.root] = replace(
            root,
            size=12,
            edges=(
                root.edges[0],
                replace(root.edges[1], offset_bits=64),
            ),
        )
    elif mutation == "size":
        b.nodes[b.root] = replace(root, size=12)
    elif mutation == "missing":
        b.nodes[b.root] = replace(root, edges=root.edges[:1])
    else:
        b.nodes["ptr"] = TypeNode("pointer", 8, edges=(TypeEdge("element", b.root),))
        b = replace(b, root="ptr")
    assert normalize_field_layout(a, "LP64").graph != normalize_field_layout(b, "LP64").graph


@pytest.mark.parametrize("mutation", ["virtual", "overlap", "bitfield", "vptr", "empty", "union"])
def test_unproven_layouts_are_explicitly_unsupported(mutation: str) -> None:
    graph = inherited()
    root = graph.nodes[graph.root]
    if mutation == "virtual":
        edge = replace(root.edges[0], virtual=True, offset_bits=None, locator="dwarf:expr")
        graph.nodes[graph.root] = replace(root, edges=(edge, root.edges[1]))
    elif mutation == "overlap":
        graph.nodes[graph.root] = replace(
            root,
            edges=(
                root.edges[0],
                replace(root.edges[1], offset_bits=0),
            ),
        )
    elif mutation == "bitfield":
        graph.nodes[graph.root] = replace(
            root,
            edges=(
                root.edges[0],
                replace(root.edges[1], bit_width=2),
            ),
        )
    elif mutation == "vptr":
        graph.nodes[graph.root] = replace(
            root,
            edges=(
                replace(root.edges[0], role="vptr"),
                root.edges[1],
            ),
        )
    elif mutation == "empty":
        graph.nodes["base"] = replace(graph.nodes["base"], edges=())
    else:
        graph.nodes[graph.root] = replace(root, kind="union")
    with pytest.raises(UnsupportedType):
        normalize_field_layout(graph, "LP64")


def test_arrays_keep_extent_and_element_stride() -> None:
    array = RecoveredTypeContext("struct X { int x[2]; };", "LP64").graph("X")
    assert (
        normalize_field_layout(array, "LP64").graph != normalize_field_layout(flat(), "LP64").graph
    )


def test_recursive_pointers_are_preserved_and_wrong_pointee_is_rejected() -> None:
    code = "struct Node { int x; Node *next; };"
    a = RecoveredTypeContext(code, "LP64").graph("Node")
    b = RecoveredTypeContext(code.replace("int x", "unsigned int x"), "LP64").graph("Node")
    assert normalize_field_layout(a, "LP64").graph != normalize_field_layout(b, "LP64").graph
    with pytest.raises(UnsupportedType, match="pointer width"):
        normalize_field_layout(a, "ILP32")


def test_nested_records_flatten_but_nested_padding_does_not_become_a_field() -> None:
    a = RecoveredTypeContext(
        "struct A { char x; int y; }; struct B { A a; int z; };", "LP64"
    ).graph("B")
    b = RecoveredTypeContext("struct B { char x; int y; int z; };", "LP64").graph("B")
    assert a.project("abi") != b.project("abi")
    assert normalize_field_layout(a, "LP64").graph == normalize_field_layout(b, "LP64").graph
    c = RecoveredTypeContext("struct B { char x; char pad[3]; int y; int z; };", "LP64").graph("B")
    assert normalize_field_layout(a, "LP64").graph != normalize_field_layout(c, "LP64").graph


@pytest.mark.parametrize("target", ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"])
@pytest.mark.parametrize("flags", [("-O0",), ("-O2",), ("-O2", "-fno-inline")])
def test_compiler_generated_dwarf_and_plain_c_definition(
    tmp_path: Path, target: str, flags: tuple[str, ...]
) -> None:
    clang = shutil.which("clang++")
    if not clang:
        pytest.skip("Clang required for real debug layout fixture")
    source = tmp_path / "layout.cpp"
    obj = tmp_path / "layout.o"
    source.write_text(
        "struct Base { int x; }; struct Derived : Base { int y; };\n"
        "struct Flat { int x; int y; };\n"
        "Derived cpp_value; Flat c_value;\n"
    )
    subprocess.run(
        [
            clang,
            "--target=" + target,
            "-g",
            "-gdwarf-4",
            *flags,
            "-c",
            str(source),
            "-o",
            str(obj),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    with obj.open("rb") as stream:
        dwarf = ELFFile(stream).get_dwarf_info()
        variables = {
            binfmt.die_str_attr(die, "DW_AT_name"): die
            for cu in dwarf.iter_CUs()
            for die in cu.iter_DIEs()
            if die.tag == "DW_TAG_variable"
        }
        a = dwarf_graph(variables["cpp_value"], "LP64")
        b = dwarf_graph(variables["c_value"], "LP64")
        assert a.project("abi") != b.project("abi")
        assert normalize_field_layout(a, "LP64").graph == normalize_field_layout(b, "LP64").graph


def decision_metadata(verdict: str = "type_mismatch") -> dict:
    return {
        "ground_truth_count": 1,
        "data_model": "LP64",
        "decisions": [
            {
                "identity": "oracle:0",
                "matched_identity": "producer:0",
                "expected": asdict(inherited()),
                "actual": asdict(flat()),
                "verdict": verdict,
            }
        ],
    }


def test_saved_replay_changes_only_type_equivalence() -> None:
    metadata = decision_metadata()
    before = copy.deepcopy(metadata)
    result = compare_decisions(metadata)
    assert result["eligible"] and result["value"] == 1
    assert result["decisions"][0]["matched_identity"] == "producer:0"
    assert metadata == before


@pytest.mark.parametrize(
    "verdict",
    [
        "unmatched",
        "invalid_producer_output",
        "unsupported_recovered_type",
        "inconsistent_recovered_storage_width",
    ],
)
def test_saved_replay_does_not_repair_invalid_or_unmatched_recovery(verdict: str) -> None:
    metadata = decision_metadata(verdict)
    metadata["decisions"][0]["actual"] = None
    result = compare_decisions(metadata)
    assert result["eligible"] and result["value"] == 0
    assert result["decisions"][0]["verdict"] == verdict


def test_recovered_layout_failure_is_zero_and_oracle_failure_is_explicit() -> None:
    metadata = decision_metadata()
    actual = metadata["decisions"][0]["actual"]
    actual["nodes"][actual["root"]]["kind"] = "union"
    result = compare_decisions(metadata)
    assert result["eligible"] and result["value"] == 0
    assert result["decisions"][0]["verdict"] == "unsupported_recovered_layout"
    metadata["decisions"][0]["expected"] = actual
    result = compare_decisions(metadata)
    assert not result["eligible"] and result["oracle_exclusions"]


@pytest.mark.parametrize(
    "mutation", ["duplicate", "count", "verdict", "missing_actual", "invalid_oracle_graph"]
)
def test_bad_saved_evidence_fails_evaluation(mutation: str) -> None:
    metadata = decision_metadata()
    if mutation == "duplicate":
        metadata["decisions"] *= 2
        metadata["ground_truth_count"] = 2
    elif mutation == "count":
        metadata["ground_truth_count"] = 2
    elif mutation == "verdict":
        metadata["decisions"][0]["verdict"] = "unknown"
    elif mutation == "missing_actual":
        metadata["decisions"][0]["actual"] = None
    else:
        metadata["decisions"][0]["expected"]["root"] = "missing"
    with pytest.raises(ValueError):
        compare_decisions(metadata)


def test_expansion_has_a_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("decbench.metrics.cpp_field_layout.MAX_LEAVES", 1)
    with pytest.raises(UnsupportedType, match="expansion bound"):
        normalize_field_layout(inherited(), "LP64")


@pytest.mark.parametrize("model,width", [("LP64", 8), ("LLP64", 8), ("ILP32", 4)])
@pytest.mark.parametrize("kind", ["lref", "rref"])
def test_reference_storage_projection_is_explicit(model: str, width: int, kind: str) -> None:
    graph = TypeGraph(
        "ref",
        {
            "ref": TypeNode(kind, width, edges=(TypeEdge("element", "int"),)),
            "int": TypeNode("signed", 4, rank="int"),
        },
    )
    pointer = copy.deepcopy(graph)
    pointer.nodes["ref"] = replace(pointer.nodes["ref"], kind="pointer")
    assert (
        normalize_field_layout(graph, model).graph == normalize_field_layout(pointer, model).graph
    )


@pytest.mark.parametrize("mutation", ["none", "requested", "oracle", "duplicate_cell"])
def test_report_populations_are_shared_and_unique(tmp_path: Path, mutation: str) -> None:
    profile = {
        "perfect_count": 0,
        "function_results": {
            "f": {"value": 0, "metadata": decision_metadata()},
        },
    }
    cell = {
        "cell": "cell",
        "requested": 2,
        "tools": {
            tool: {
                "profiles": {"source": copy.deepcopy(profile), "abi": copy.deepcopy(profile)},
                "function_addresses": {"f": 4096, "excluded": 8192},
            }
            for tool in TOOLS
        },
    }
    if mutation == "requested":
        cell["tools"]["angr"]["function_addresses"]["excluded"] = 12288
    elif mutation == "oracle":
        expected = cell["tools"]["angr"]["profiles"]["abi"]["function_results"]["f"]["metadata"][
            "decisions"
        ][0]["expected"]
        expected["nodes"][expected["root"]]["size"] = 12
    path = tmp_path / "cell.json"
    path.write_text(json.dumps(cell))
    paths = [path, path] if mutation == "duplicate_cell" else [path]
    if mutation != "none":
        with pytest.raises(ValueError):
            audit(paths)
    else:
        report = audit(paths)
        assert all(row["layout_perfect"] == 1 for row in report["summary"].values())
