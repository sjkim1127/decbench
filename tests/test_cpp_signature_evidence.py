"""Native identity, role scopes and isolated declared-return extraction."""

from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from decbench.metrics.cpp_signature_evidence import native_signature, recovered_return
from decbench.metrics.cpp_type_graph import primitive_graph
from decbench.metrics.cpp_types import UnsupportedType, parse_type
from decbench.utils.pdb_info import PdbFunction


@pytest.mark.parametrize(
    "spelling", ["void", "int", "unsigned int", "int*", "int&", "int&&", "int*&", "const char*"]
)
def test_recovered_declarator_preserves_return_type(spelling: str) -> None:
    graph = recovered_return(spelling + " f() { return {}; }", "LP64")
    assert graph == primitive_graph(parse_type(spelling, "LP64"))


@pytest.mark.parametrize(
    "code",
    [
        "int f();",
        "int f(){return 1;} int g(){return 2;}",
        "auto f() -> int {return 1;}",
        "int (*f())(int) {return 0;}",
        "int *const f() {return 0;}",
        "struct X { int n; }; X f() {return {};}",
        "int f( {",
        "unknown_type f() {return {};}",
    ],
)
def test_uncertain_or_aggregate_returns_abstain(code: str) -> None:
    with pytest.raises(UnsupportedType):
        recovered_return(code, "LP64")


def pdb_context(signature: int | None = 4096):
    fn = PdbFunction(
        "unrelated_display_name", 4096, 4100, "m", (), 4096, 4100, signature_type_index=signature
    )
    fn.variables = [
        SimpleNamespace(identity="v0", is_parameter=True),
        SimpleNamespace(identity="v1", is_parameter=False),
        SimpleNamespace(identity="v2", is_parameter=None),
    ]
    return SimpleNamespace(
        path="image",
        dwarf=None,
        pdb=SimpleNamespace(
            at_address=lambda addr: fn if addr == 4096 else None,
            types=SimpleNamespace(records={4096: (0x1008, struct.pack("<I", 0x74))}),
        ),
        validate=lambda path: None,
    )


def test_pdb_roles_and_return_use_exact_address_not_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "decbench.metrics.cpp_signature_evidence.pdb_graph",
        lambda types, index, model: primitive_graph(parse_type("int", model)),
    )
    result = native_signature(pdb_context(), 4096, "LLP64")
    assert [r.role for r in result.roles] == ["formal_parameter", "local", "unknown"]
    assert result.declared_return and not result.abi_slots_verified
    with pytest.raises(UnsupportedType):
        native_signature(pdb_context(), 8192, "LLP64")
    result = native_signature(pdb_context(None), 4096, "LLP64")
    assert result.return_exclusion and result.declared_return is None


def test_old_pdb_constructor_remains_compatible() -> None:
    fn = PdbFunction("f", 1, 2, "m", (), 1, 2)
    assert fn.signature_type_index is None


@pytest.mark.parametrize(
    "code",
    [
        "int __attribute__((vector_size(16))) f() { return {}; }",
        "[[nodiscard]] int f() {return 1;}",
        "int * __ptr32 f() {return 0;}",
    ],
)
def test_target_specific_return_attributes_are_not_erased(code: str) -> None:
    with pytest.raises(UnsupportedType):
        recovered_return(code, "LP64")


def test_dwarf_role_ids_are_preserved_and_ambiguous_entry_abstains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Die:
        def __init__(self, tag, offset, children=()):
            self.tag, self.offset, self.children = tag, offset, children

        def iter_children(self):
            return iter(self.children)

    parameter = Die("DW_TAG_formal_parameter", 10)
    local = Die("DW_TAG_variable", 20)
    function = Die("DW_TAG_subprogram", 1, [parameter, Die("DW_TAG_lexical_block", 30, [local])])
    context = SimpleNamespace(
        path="image",
        dwarf=True,
        info=SimpleNamespace(arch="x86_64"),
        index={4096: [function]},
        validate=lambda path: None,
    )
    monkeypatch.setattr(
        "decbench.metrics.cpp_signature_evidence.binfmt.die_attr", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "decbench.metrics.cpp_signature_evidence.dwarf_graph",
        lambda *a: primitive_graph(parse_type("void", "LP64")),
    )
    result = native_signature(context, 4096, "LP64")
    assert [(r.identity, r.role) for r in result.roles] == [
        ("dwarf:0xa", "formal_parameter"),
        ("dwarf:0x14", "local"),
    ]
    assert result.roles[0].debug_formal_index == 0
    context.index[4096].append(Die("DW_TAG_subprogram", 2))
    with pytest.raises(UnsupportedType):
        native_signature(context, 4096, "LP64")
