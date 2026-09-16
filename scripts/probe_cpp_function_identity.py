#!/usr/bin/env python3
"""Probe DecBench's current C++ function identity behavior with real DWARF.

This is diagnostic, not a production identity implementation.  It compiles a
small C++ program containing overloads and same-named functions in different
scopes, then compares address/linkage-based concrete DWARF identity with the
name-keyed maps currently used by DecBench.

Exit status 0 means the expected collision/collapse was reproduced.  The JSON
report is suitable for a GitHub Actions artifact and can later become a
regression fixture for function-identity v2.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from decbench.metrics.type_match import extract_ground_truth_types
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils import binfmt
from decbench.utils.source_extract import _dwarf_decl

SOURCE = r"""
namespace alpha {
__attribute__((noinline)) int collide(int x) { return x + 1; }
}

namespace beta {
__attribute__((noinline)) int collide(int x) { return x + 2; }
}

__attribute__((noinline)) int collide(int x) { return x + 3; }
__attribute__((noinline)) int collide(double x) { return static_cast<int>(x) + 4; }

struct A {
    __attribute__((noinline)) int Next(int x) const;
};
struct B {
    __attribute__((noinline)) int Next(int x) const;
};

int A::Next(int x) const { return x + 5; }
int B::Next(int x) const { return x + 6; }

int main() {
    A a;
    B b;
    return alpha::collide(1) + beta::collide(1) + collide(1) + collide(1.0)
        + a.Next(1) + b.Next(1);
}
"""


def _compile(root: Path) -> tuple[Path, Path]:
    compiler = shutil.which("g++")
    if compiler is None:
        raise RuntimeError("g++ is required")
    source = root / "identity_collision.cpp"
    binary = root / "identity_collision"
    source.write_text(SOURCE)
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-O0",
            "-g",
            "-fno-inline",
            "-fno-builtin",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return source, binary


def _concrete_functions(binary: Path) -> list[dict[str, Any]]:
    dwarf = binfmt.dwarf_info(binary)
    if dwarf is None:
        raise RuntimeError("compiled probe binary has no DWARF")

    rows: list[dict[str, Any]] = []
    for cu in dwarf.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                continue
            name = binfmt.die_str_attr(die, "DW_AT_name")
            if not name:
                continue
            linkage = binfmt.die_str_attr(die, "DW_AT_linkage_name")
            if linkage is None:
                linkage = binfmt.die_str_attr(die, "DW_AT_MIPS_linkage_name")
            rows.append(
                {
                    "address": int(die.attributes["DW_AT_low_pc"].value),
                    "name": name,
                    "linkage_name": linkage,
                }
            )

    # A concrete address is the binary-local identity primitive.  Some producers
    # can emit duplicate DIE descriptions for one code range, so deduplicate here.
    by_address: dict[int, dict[str, Any]] = {}
    for row in rows:
        old = by_address.get(row["address"])
        if old is None or (not old.get("linkage_name") and row.get("linkage_name")):
            by_address[row["address"]] = row
    return sorted(by_address.values(), key=lambda row: row["address"])


def _simulate_decompilation_result(rows: list[dict[str, Any]], binary: Path) -> DecompilationResult:
    # This mirrors the public model contract: results are keyed by function name.
    functions = {
        row["name"]: FunctionDecompilation(
            name=row["name"],
            address=row["address"],
            decompiled_code=f"int {row['name']}(void) {{ return 0; }}",
        )
        for row in rows
    }
    return DecompilationResult(
        binary_path=binary,
        binary_name=binary.name,
        decompiler=DecompilerMetadata(decompiler_name="identity-probe"),
        functions=functions,
    )


def run_probe() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="decbench-cpp-identity-") as td:
        root = Path(td)
        source, binary = _compile(root)
        concrete = _concrete_functions(binary)

        interesting = [row for row in concrete if row["name"] in {"collide", "Next", "main"}]
        counts = Counter(row["name"] for row in interesting)
        linkage = [row["linkage_name"] for row in interesting if row.get("linkage_name")]

        dwarf_decl = _dwarf_decl(binary)
        type_ground_truth = extract_ground_truth_types(binary)
        modeled = _simulate_decompilation_result(interesting, binary)

        report = {
            "source": source.name,
            "binary": binary.name,
            "concrete_interesting_functions": len(interesting),
            "concrete_name_counts": dict(sorted(counts.items())),
            "concrete_unique_addresses": len({row["address"] for row in interesting}),
            "concrete_linkage_names": len(linkage),
            "concrete_unique_linkage_names": len(set(linkage)),
            "dwarf_decl_name_keys": sorted(k for k in dwarf_decl if k in {"collide", "Next", "main"}),
            "dwarf_decl_entries_for_collision_names": sum(
                1 for k in dwarf_decl if k in {"collide", "Next"}
            ),
            "type_match_name_keys": sorted(k for k in type_ground_truth if k in {"collide", "Next", "main"}),
            "type_match_entries_for_collision_names": sum(
                1 for k in type_ground_truth if k in {"collide", "Next"}
            ),
            "decompilation_result_function_count": modeled.function_count,
            "decompilation_result_keys": sorted(modeled.functions),
            "functions": interesting,
        }

        # Expected current behavior: four distinct collide() bodies and two Next()
        # methods exist, but each name-keyed map has at most one slot per spelling.
        assert counts["collide"] >= 4, report
        assert counts["Next"] >= 2, report
        assert report["concrete_unique_addresses"] == len(interesting), report
        assert len(set(linkage)) == len(linkage), report
        assert report["dwarf_decl_entries_for_collision_names"] <= 2, report
        assert report["type_match_entries_for_collision_names"] <= 2, report
        assert modeled.function_count < len(interesting), report

        report["collapse_reproduced"] = True
        report["address_count_minus_name_keyed_model"] = len(interesting) - modeled.function_count
        return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    report = run_probe()
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
