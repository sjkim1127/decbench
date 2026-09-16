#!/usr/bin/env python3
"""Real-target smoke test for DecBench C++ canonical function identity.

Build LevelDB separately, then point this script at its DWARF-bearing shared
library.  The smoke test deliberately uses real C++ same-name methods from the
binary rather than a synthetic collision fixture:

1. discover concrete DWARF subprograms and same-name collision groups;
2. prove `_relabel_to_dwarf()` preserves every selected address with stable
   `<name>@0x<low_pc>` storage keys derived from the complete target set;
3. strip a copy of the library, decompile a small collision-heavy slice with
   angr, and run the exact benchmark relabel step on the backend result;
4. require at least one real same-name pair to survive end-to-end.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from decbench.decompilers.raw.angr_raw import RawAngrDecompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.function_identity import dwarf_function_identities, identities_by_name


PREFERRED_NAMES = (
    "Next",
    "Prev",
    "Seek",
    "SeekToFirst",
    "SeekToLast",
    "Valid",
    "key",
    "value",
    "status",
    "Name",
)


def _load_driver():
    root = Path(__file__).resolve().parents[1]
    path = root / "scripts" / "run_benchmark.py"
    spec = importlib.util.spec_from_file_location("decbench_real_target_identity_smoke", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import benchmark driver from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _select_collision_slice(binary: Path):
    identities = dwarf_function_identities(binary)
    grouped = identities_by_name(identities)
    collisions = {
        name: rows
        for name, rows in grouped.items()
        if len({row.address for row in rows}) >= 2
    }
    if not collisions:
        raise RuntimeError("LevelDB binary contained no concrete same-name DWARF functions")

    ordered_names: list[str] = []
    for preferred in PREFERRED_NAMES:
        if preferred in collisions:
            ordered_names.append(preferred)
    ordered_names.extend(
        name
        for name, rows in sorted(
            collisions.items(), key=lambda item: (-len(item[1]), item[0])
        )
        if name not in ordered_names
    )

    selected = []
    selected_names = []
    # Give angr several independent collision pairs while keeping the smoke test
    # bounded.  Real LevelDB methods are preferred; generic template collisions
    # are only fallback candidates.
    for name in ordered_names:
        rows = sorted(collisions[name], key=lambda row: row.address)
        with_linkage = [row for row in rows if row.linkage_name]
        candidates = with_linkage if len(with_linkage) >= 2 else rows
        pair = candidates[:2]
        if len(pair) < 2:
            continue
        selected.extend(pair)
        selected_names.append(name)
        if len(selected_names) >= 5:
            break

    if len(selected) < 2:
        raise RuntimeError("could not select a LevelDB collision pair")

    return identities, collisions, selected, selected_names


def _expected_keys(addr2name: dict[int, str]) -> set[str]:
    counts = Counter(addr2name.values())
    return {
        f"{name}@0x{address:x}" if counts[name] > 1 else name
        for address, name in addr2name.items()
    }


def _synthetic_real_address_check(driver, binary: Path, addr2name: dict[int, str]) -> dict:
    funcs = {
        f"raw-{index}": FunctionDecompilation(
            name=f"FUN_{address:x}",
            address=address,
            decompiled_code=f"int FUN_{address:x}(void) {{ return {index}; }}",
        )
        for index, address in enumerate(sorted(addr2name))
    }
    result = DecompilationResult(
        binary_path=binary,
        binary_name=binary.stem,
        decompiler=DecompilerMetadata(decompiler_name="identity-smoke"),
        functions=funcs,
    )
    driver._relabel_to_dwarf(result, addr2name, binary)
    expected = _expected_keys(addr2name)
    actual = set(result.functions)
    if actual != expected:
        raise AssertionError(
            f"canonical relabel lost real DWARF identities: expected={sorted(expected)} "
            f"actual={sorted(actual)}"
        )
    if {fd.address for fd in result.functions.values()} != set(addr2name):
        raise AssertionError("canonical relabel did not preserve every selected DWARF low_pc")
    return {
        "targets": len(addr2name),
        "keys": sorted(actual),
    }


def _stripped_copy(binary: Path, directory: Path) -> Path:
    out = directory / binary.name
    shutil.copy2(binary, out)
    subprocess.run(["strip", "--strip-all", str(out)], check=True)
    return out


def _angr_check(driver, binary: Path, addr2name: dict[int, str]) -> dict:
    with tempfile.TemporaryDirectory(prefix="decbench-leveldb-identity-") as td:
        td_path = Path(td)
        stripped = _stripped_copy(binary, td_path)
        functions = [
            (f"sub_{address:x}", address)
            for address in sorted(addr2name)
        ]
        result = RawAngrDecompiler().decompile_binary(
            stripped,
            functions=functions,
            output_dir=None,
        )
        backend_count = len(result.functions)
        driver._relabel_to_dwarf(result, addr2name, binary)

        keys = set(result.functions)
        recovered_by_name: dict[str, list[str]] = {}
        for key, fd in result.functions.items():
            recovered_by_name.setdefault(fd.name, []).append(key)

        surviving_pairs = {
            name: sorted(keys_for_name)
            for name, keys_for_name in recovered_by_name.items()
            if len(keys_for_name) >= 2
        }
        if not surviving_pairs:
            raise AssertionError(
                "angr did not recover two members of any selected real LevelDB "
                f"same-name group (backend_count={backend_count}, keys={sorted(keys)})"
            )
        for name, pair_keys in surviving_pairs.items():
            if any("@0x" not in key for key in pair_keys):
                raise AssertionError(
                    f"ambiguous LevelDB name {name!r} survived with a non-canonical key: "
                    f"{pair_keys}"
                )

        return {
            "backend_before_relabel": backend_count,
            "after_relabel": len(result.functions),
            "failed_functions": result.decompiler.failed_functions,
            "surviving_collision_groups": surviving_pairs,
            "keys": sorted(keys),
            "identity_metadata": result.decompiler.extra,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")

    identities, collisions, selected, selected_names = _select_collision_slice(binary)
    addr2name = {row.address: row.name for row in selected}
    driver = _load_driver()

    report = {
        "binary": str(binary),
        "dwarf_concrete_functions": len(identities),
        "same_name_collision_groups": len(collisions),
        "selected_collision_names": selected_names,
        "selected_targets": [
            {
                "name": row.name,
                "address": f"0x{row.address:x}",
                "linkage_name": row.linkage_name,
            }
            for row in selected
        ],
        "canonical_relabel": _synthetic_real_address_check(driver, binary, addr2name),
        "angr": _angr_check(driver, binary, addr2name),
    }

    payload = json.dumps(report, indent=2, sort_keys=True)
    print(payload)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(payload + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
