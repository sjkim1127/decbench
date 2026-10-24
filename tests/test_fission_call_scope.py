"""Call provenance must never grant variable PCs or complete object-type credit."""

from __future__ import annotations

import pytest

from decbench.decompilers.raw.fission_raw import RawFissionDecompiler
from decbench.models.decompilation import NativeCallSite


def test_call_only_scope_does_not_inherit_definition_variable_pcs() -> None:
    shape = {"kind": "pointer", "complete": False}
    result = RawFissionDecompiler._build_function(
        {
            "code_nir": "int f() { int x = 1; sink(); return x; }",
            "variables": [{"name": "x", "type": "int", "type_shape": shape}],
            "line_mappings_nir": [
                {"line_number": 2, "addresses": [4098], "defined_variables": ["x"]},
                {
                    "line_number": 3,
                    "addresses": [4100],
                    "defined_variables": [],
                    "call_site": {"instruction_address": 4100, "pcode_sequence": 0},
                },
            ],
        },
        "f",
        4096,
    )
    assert result is not None
    assert result.variables[0].line_numbers == [2]
    assert result.variables[0].type == "int"
    assert [m.line_number for m in result.line_mappings] == [2]
    assert "call_site" not in result.line_mappings[0].model_dump()
    assert result.metadata["call_mappings"][0]["addresses"] == [4100]
    assert result.metadata["recovered_type_shapes"] == [
        {"variable_index": 0, "name": "x", "shape": shape}
    ]
    assert "cpp_type_graphs" not in result.metadata


@pytest.mark.parametrize("scope,addresses", [(None, [4100]), (["x"], [4100]), ([], [4098, 4100])])
def test_mixed_call_variable_or_address_scope_is_rejected(scope, addresses) -> None:
    with pytest.raises(ValueError, match="exclusive call-only scope"):
        RawFissionDecompiler._build_function(
            {
                "code_nir": "void f() { sink(); }",
                "line_mappings_nir": [
                    {
                        "line_number": 1,
                        "addresses": addresses,
                        "defined_variables": scope,
                        "call_site": {"instruction_address": 4100, "pcode_sequence": 0},
                    },
                ],
            },
            "f",
            4096,
        )


@pytest.mark.parametrize("address,sequence", [(-1, 0), (4096, -1), (True, 0), (4096, True)])
def test_native_call_transport_requires_nonnegative_integer_identity(address, sequence) -> None:
    with pytest.raises(ValueError):
        NativeCallSite(instruction_address=address, pcode_sequence=sequence)
