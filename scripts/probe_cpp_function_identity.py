#!/usr/bin/env python3
"""Probe C++ function identity with real DWARF and DecBench storage semantics."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from decbench.metrics.type_match import extract_ground_truth_types
from decbench.models.decompilation import FunctionDecompilation
from decbench.utils.function_identity import (
    dwarf_function_identities,
    identities_by_name,
    insert_function,
)
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
struct A { __attribute__((noinline)) int Next(int x) const; };
struct B { __attribute__((noinline)) int Next(int x) const; };
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


def _decomp(identity) -> FunctionDecompilation:
    return FunctionDecompilation(
        name=identity.name,
        address=identity.address,
        decompiled_code=f"int {identity.name}(void) {{ return 0; }}",
    )


def run_probe() -> dict:
    with tempfile.TemporaryDirectory(prefix="decbench-cpp-identity-") as td:
        source, binary = _compile(Path(td))
        identities = dwarf_function_identities(binary)
        interesting = [
            identity for identity in identities if identity.name in {"collide", "Next", "main"}
        ]
        grouped = identities_by_name(interesting)
        counts = Counter(identity.name for identity in interesting)
        linkage = [identity.linkage_name for identity in interesting if identity.linkage_name]

        legacy = {identity.name: _decomp(identity) for identity in interesting}
        collision_safe: dict[str, FunctionDecompilation] = {}
        for identity in interesting:
            insert_function(collision_safe, _decomp(identity))

        dwarf_decl = _dwarf_decl(binary)
        type_ground_truth = extract_ground_truth_types(binary)

        report = {
            "source": source.name,
            "binary": binary.name,
            "concrete_interesting_functions": len(interesting),
            "concrete_name_counts": dict(sorted(counts.items())),
            "concrete_unique_addresses": len({identity.address for identity in interesting}),
            "concrete_linkage_names": len(linkage),
            "concrete_unique_linkage_names": len(set(linkage)),
            "legacy_name_keyed_count": len(legacy),
            "legacy_name_keyed_keys": sorted(legacy),
            "collision_safe_count": len(collision_safe),
            "collision_safe_keys": sorted(collision_safe),
            "dwarf_decl_name_keys": sorted(
                key for key in dwarf_decl if key in {"collide", "Next", "main"}
            ),
            "type_match_name_keys": sorted(
                key for key in type_ground_truth if key in {"collide", "Next", "main"}
            ),
            "functions": [
                {
                    "address": identity.address,
                    "name": identity.name,
                    "linkage_name": identity.linkage_name,
                }
                for identity in interesting
            ],
        }

        assert len(grouped["collide"]) == 4, report
        assert len(grouped["Next"]) == 2, report
        assert len(grouped["main"]) == 1, report
        assert report["concrete_unique_addresses"] == 7, report
        assert len(linkage) == 6 and len(set(linkage)) == 6, report
        assert report["legacy_name_keyed_count"] == 3, report
        assert report["collision_safe_count"] == 7, report

        report["legacy_collapse_reproduced"] = True
        report["collision_safe_storage_preserves_all"] = True
        report["functions_recovered_by_collision_safe_storage"] = (
            report["collision_safe_count"] - report["legacy_name_keyed_count"]
        )
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
