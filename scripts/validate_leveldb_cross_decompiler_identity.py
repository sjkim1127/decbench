#!/usr/bin/env python3
"""Require angr and Ghidra to produce identical canonical keys for a real LevelDB collision."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from decbench.decompilers.raw.angr_raw import RawAngrDecompiler
from decbench.decompilers.raw.ghidra_raw import RawGhidraDecompiler
from decbench.utils.function_identity import dwarf_function_identities, identities_by_name


def _driver():
    path = Path(__file__).resolve().parent / "run_benchmark.py"
    spec = importlib.util.spec_from_file_location("cross_identity_driver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _select_pair(binary: Path):
    grouped = identities_by_name(dwarf_function_identities(binary))
    preferred = ["Next", "Seek", "Prev", "Valid", "key", "value"]
    names = preferred + sorted(name for name in grouped if name not in preferred)
    for name in names:
        rows = sorted(grouped.get(name, []), key=lambda row: row.address)
        unique = []
        seen = set()
        for row in rows:
            if row.address in seen or not row.linkage_name:
                continue
            seen.add(row.address)
            unique.append(row)
        if len(unique) >= 2:
            return name, unique[:2]
    raise RuntimeError("no usable same-name LevelDB collision pair found")


def _strip(binary: Path, out: Path) -> None:
    shutil.copy2(binary, out)
    subprocess.run(["strip", "--strip-all", str(out)], check=True)


def _run_backend(backend, stripped: Path, unstripped: Path, addr2name: dict[int, str]):
    requested = [(f"sub_{address:x}", address) for address in sorted(addr2name)]
    result = backend.decompile_binary(stripped, functions=requested, output_dir=None)
    before = sorted((fd.name, fd.address) for fd in result.functions.values())
    _driver()._relabel_to_dwarf(result, addr2name, unstripped)
    return result, before


def main() -> int:
    binary = Path(sys.argv[1]).resolve()
    name, pair = _select_pair(binary)
    addr2name = {row.address: row.name for row in pair}
    expected = {f"{name}@0x{address:x}" for address in addr2name}

    with tempfile.TemporaryDirectory(prefix="decbench-cross-id-") as td:
        stripped = Path(td) / binary.name
        _strip(binary, stripped)
        angr, angr_before = _run_backend(RawAngrDecompiler(), stripped, binary, addr2name)
        ghidra, ghidra_before = _run_backend(RawGhidraDecompiler(), stripped, binary, addr2name)

    angr_keys = set(angr.functions)
    ghidra_keys = set(ghidra.functions)
    if angr_keys != expected:
        raise AssertionError(f"angr canonical keys: {sorted(angr_keys)} != {sorted(expected)}")
    if ghidra_keys != expected:
        raise AssertionError(f"Ghidra canonical keys: {sorted(ghidra_keys)} != {sorted(expected)}")
    if angr_keys != ghidra_keys:
        raise AssertionError("cross-decompiler canonical identity mismatch")
    if {fd.address for fd in angr.functions.values()} != set(addr2name):
        raise AssertionError("angr canonical addresses mismatch")
    if {fd.address for fd in ghidra.functions.values()} != set(addr2name):
        raise AssertionError("Ghidra canonical addresses mismatch")

    report = {
        "collision_name": name,
        "targets": [
            {"address": f"0x{row.address:x}", "linkage_name": row.linkage_name}
            for row in pair
        ],
        "expected_keys": sorted(expected),
        "angr_before_relabel": angr_before,
        "ghidra_before_relabel": ghidra_before,
        "angr_keys": sorted(angr_keys),
        "ghidra_keys": sorted(ghidra_keys),
        "angr_failed": angr.decompiler.failed_functions,
        "ghidra_failed": ghidra.decompiler.failed_functions,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    Path("/tmp/leveldb-cross-identity.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
