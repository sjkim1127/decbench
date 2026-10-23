#!/usr/bin/env python3
"""Read native signatures and compare declared returns in frozen producer output.

One immutable image per process; no binaries, decompilers or recovered programs
are executed. This is separate evidence, never a default metric or ABI certificate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from decbench.decompilers.raw.fission_raw import RawFissionDecompiler
from decbench.decompilers.raw.kuna_raw import RawKunaDecompiler
from decbench.metrics.cpp_signature_evidence import native_signature, recovered_return
from decbench.metrics.cpp_type_facts import assess_recovery, extract_type_facts
from decbench.metrics.cpp_type_match import CppOracleContext
from decbench.metrics.cpp_types import UnsupportedType
from decbench.models.decompilation import DecompilationResult, FunctionDecompilation
from decbench.utils import binfmt
from decbench.utils.pdb_info import PdbFormatError
from decbench.utils.producer_validation import inspect_producer

TOOLS = ("fission", "kuna", "ghidra", "angr")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--producers", type=Path, required=True)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cell = next(c for c in json.loads(args.sample.read_text())["cells"] if c["id"] == args.cell)
    binary = args.dataset / cell["binary"]
    if hashlib.sha256(binary.read_bytes()).hexdigest() != cell["binary_sha256"]:
        raise ValueError("native image differs from frozen plan")
    if len({row["address"] for row in cell["rows"]}) != len(cell["rows"]):
        raise ValueError("duplicate requested function identity")
    model = "LLP64" if cell["platform"] == "windows" else "LP64"
    context = CppOracleContext(binary)
    companions = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in binfmt.native_debug_paths(binary)
        if path.is_file()
    }
    produced = {}
    producer_hashes = {}
    for tool in ("ghidra", "angr"):
        path = args.producers / tool / cell["id"] / "result.json"
        values = (
            DecompilationResult.model_validate_json(path.read_text()) if path.exists() else None
        )
        functions = list(values.functions.values()) if values else []
        if len({f.address for f in functions}) != len(functions):
            raise ValueError("ambiguous producer function identity")
        produced[tool] = {f.address: f for f in functions}
        if path.exists():
            producer_hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    results = []
    summary = {
        tool: Counter(
            requested=0, native_returns=0, perfect_returns=0, correct_facts=0, total_facts=0
        )
        for tool in TOOLS
    }
    for row in cell["rows"]:
        try:
            native = native_signature(context, row["address"], model)
            native_payload = asdict(native)
            expected = (
                extract_type_facts(native.declared_return) if native.declared_return else None
            )
        except (UnsupportedType, PdbFormatError) as exc:
            native = None
            native_payload = {"address": row["address"], "exclusion": str(exc)}
            expected = None
        outputs: dict[str, dict[str, Any]] = {}
        for tool in TOOLS:
            summary[tool]["requested"] += 1
            if tool in {"fission", "kuna"}:
                path = args.raw / tool / cell["id"] / (row["id"] + ".json")
                producer_hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
                raw = json.loads(path.read_text())
                fn = (
                    RawFissionDecompiler._build_function(raw, row["name"], row["address"])
                    if tool == "fission"
                    else RawKunaDecompiler()._build_function(raw, row["name"], row["address"])
                )
            else:
                fn = produced[tool].get(row["address"])
            fn = fn or FunctionDecompilation(
                name=row["name"], address=row["address"], decompiled_code=""
            )
            if expected is None:
                outputs[tool] = {"status": "oracle_return_unavailable"}
                continue
            assert native is not None and native.declared_return is not None
            summary[tool]["native_returns"] += 1
            inspection = inspect_producer(fn.decompiled_code, fn.metadata)
            actual_graph = None
            recovery_exclusion = None
            verdict = (
                "invalid_producer_output" if inspection.invalid else "unsupported_recovered_type"
            )
            if not inspection.invalid:
                try:
                    actual_graph = recovered_return(fn.decompiled_code, model)
                    verdict = (
                        "correct"
                        if actual_graph.project("abi") == native.declared_return.project("abi")
                        else "type_mismatch"
                    )
                except UnsupportedType as exc:
                    recovery_exclusion = str(exc)
            assessed = assess_recovery(
                expected, extract_type_facts(actual_graph) if actual_graph else None, verdict
            )
            summary[tool]["perfect_returns"] += verdict == "correct"
            summary[tool]["correct_facts"] += assessed["correct_facts"]
            summary[tool]["total_facts"] += assessed["total_facts"]
            outputs[tool] = {
                "status": verdict,
                "recovery_exclusion": recovery_exclusion,
                "actual_return": asdict(actual_graph) if actual_graph else None,
                "producer_validation": inspection.evidence(),
                "assessment": assessed,
            }
        results.append({"address": row["address"], "native": native_payload, "tools": outputs})
    context.validate(binary)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != cell["binary_sha256"]:
        raise ValueError("native image changed during capture")
    for path, digest in {**companions, **producer_hashes}.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise ValueError("debug or producer evidence changed during capture")
    result = {
        "profile": "cpp-debug-signature-v1-diagnostic",
        "official_score": False,
        "cell": cell["id"],
        "binary_sha256": cell["binary_sha256"],
        "data_model": model,
        "debug_sha256": companions,
        "producer_sha256": producer_hashes,
        "abi_slots_verified": False,
        "execution": "not measured",
        "scope": "native formal roles and declared scalar/pointer/reference return types",
        "summary": summary,
        "functions": results,
    }
    protected = {binary.resolve(), args.sample.resolve()} | {
        Path(path).resolve() for path in {**companions, **producer_hashes}
    }
    if args.output.resolve() in protected:
        raise ValueError("output must not overwrite original evidence")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"cell": cell["id"], "summary": summary}), flush=True)


if __name__ == "__main__":
    main()
