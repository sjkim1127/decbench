"""Validate linker-ICF sentinel handling without rejecting real address-zero code."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from decbench.utils import binfmt
from decbench.utils.function_identity import dwarf_function_identities

pytestmark = pytest.mark.skipif(shutil.which("g++") is None, reason="g++ required")

ICF_SRC = r"""
extern "C" __attribute__((noinline)) int foo(int x) { return x + 1; }
extern "C" __attribute__((noinline)) int bar(int x) { return x + 1; }
int (*volatile fp_foo)(int) = &foo;
int (*volatile fp_bar)(int) = &bar;
volatile int seed = 1;
int main() { int x = seed; return fp_foo(x) + fp_bar(x); }
"""

ZERO_SRC = r"""
__attribute__((noinline)) int zero(int x) { return x + 1; }
"""


def _build_icf(directory: Path) -> Path:
    source = directory / "icf.cpp"
    binary = directory / "icf"
    source.write_text(ICF_SRC)
    subprocess.run(
        [
            "g++",
            "-std=c++17",
            "-O2",
            "-g",
            "-fno-ipa-icf",
            "-ffunction-sections",
            "-fuse-ld=lld",
            "-Wl,--icf=all",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return binary


def _symbol_addresses(binary: Path, names: set[str]) -> dict[str, int]:
    with binary.open("rb") as stream:
        symtab = ELFFile(stream).get_section_by_name(".symtab")
        assert symtab is not None
        return {
            symbol.name: int(symbol["st_value"])
            for symbol in symtab.iter_symbols()
            if symbol.name in names
        }


def test_linker_icf_sentinel_zero_is_not_a_concrete_binary_target(tmp_path: Path) -> None:
    selections: list[str] = []
    for index in range(2):
        directory = tmp_path / str(index)
        directory.mkdir()
        binary = _build_icf(directory)

        symbols = _symbol_addresses(binary, {"foo", "bar"})
        assert set(symbols) == {"foo", "bar"}
        assert symbols["foo"] == symbols["bar"]
        shared = symbols["foo"]
        assert shared != 0
        assert binfmt.executable_address_status(binary, 0) is False
        assert binfmt.executable_address_status(binary, shared) is True

        identities = [
            row for row in dwarf_function_identities(binary) if row.name in {"foo", "bar"}
        ]
        assert len(identities) == 1
        assert identities[0].address == shared
        assert identities[0].name in {"foo", "bar"}

        owners = binfmt.source_function_owners(
            binary,
            {"icf"},
            follow_abstract_origin=True,
        )
        alias_targets = {
            address: name
            for address, (name, _stem) in owners.items()
            if name in {"foo", "bar"}
        }
        assert alias_targets == {shared: identities[0].name}
        selections.append(identities[0].name)

    assert selections[0] == selections[1]


def test_real_executable_address_zero_is_preserved(tmp_path: Path) -> None:
    source = tmp_path / "zero.c"
    obj = tmp_path / "zero.o"
    script = tmp_path / "zero.ld"
    binary = tmp_path / "zero.elf"
    source.write_text(ZERO_SRC)
    script.write_text(
        "SECTIONS {\n"
        "  . = 0;\n"
        "  .text : { *(.text .text.*) }\n"
        "  .data : { *(.data .data.*) }\n"
        "  .bss : { *(.bss .bss.*) }\n"
        "}\n"
    )
    subprocess.run(
        [
            "gcc",
            "-O0",
            "-g",
            "-ffreestanding",
            "-ffunction-sections",
            "-fno-asynchronous-unwind-tables",
            "-fno-unwind-tables",
            "-c",
            str(source),
            "-o",
            str(obj),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["ld.lld", "-e", "zero", "-T", str(script), str(obj), "-o", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )

    symbols = _symbol_addresses(binary, {"zero"})
    assert symbols == {"zero": 0}
    assert binfmt.executable_address_status(binary, 0) is True

    identities = [row for row in dwarf_function_identities(binary) if row.name == "zero"]
    assert len(identities) == 1
    assert identities[0].address == 0

    owners = binfmt.source_function_owners(binary, {"zero"})
    assert owners[0][0] == "zero"
