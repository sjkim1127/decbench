"""Probe the one-address/one-target policy with a real linker ICF binary."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from decbench.utils import binfmt
from decbench.utils.function_identity import dwarf_function_identities

pytestmark = pytest.mark.skipif(shutil.which("g++") is None, reason="g++ required")

SRC = r"""
extern "C" __attribute__((noinline)) int foo(int x) { return x + 1; }
extern "C" __attribute__((noinline)) int bar(int x) { return x + 1; }
int (*volatile fp_foo)(int) = &foo;
int (*volatile fp_bar)(int) = &bar;
volatile int seed = 1;
int main() { int x = seed; return fp_foo(x) + fp_bar(x); }
"""


def _build(directory: Path) -> Path:
    source = directory / "icf.cpp"
    binary = directory / "icf"
    source.write_text(SRC)
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


def _symbol_addresses(binary: Path) -> dict[str, int]:
    with binary.open("rb") as stream:
        symtab = ELFFile(stream).get_section_by_name(".symtab")
        assert symtab is not None
        return {
            symbol.name: int(symbol["st_value"])
            for symbol in symtab.iter_symbols()
            if symbol.name in {"foo", "bar"}
        }


def test_linker_icf_aliases_are_one_binary_target(tmp_path: Path) -> None:
    selections = []
    for index in range(2):
        directory = tmp_path / str(index)
        directory.mkdir()
        binary = _build(directory)

        symbols = _symbol_addresses(binary)
        assert set(symbols) == {"foo", "bar"}
        assert symbols["foo"] == symbols["bar"]
        shared = symbols["foo"]

        identities = [
            row for row in dwarf_function_identities(binary) if row.name in {"foo", "bar"}
        ]
        assert {row.name for row in identities} == {"foo", "bar"}
        assert {row.address for row in identities} == {shared}

        owners = binfmt.source_function_owners(
            binary,
            {"icf"},
            follow_abstract_origin=True,
        )
        assert shared in owners
        assert owners[shared][0] in {"foo", "bar"}
        assert len({addr for addr, (name, _stem) in owners.items() if name in {"foo", "bar"}}) == 1
        selections.append(owners[shared][0])

    # The exact alias spelling is secondary; it must at least be stable for the
    # exact same toolchain/source so an ICF-folded binary has a reproducible target.
    assert selections[0] == selections[1]
