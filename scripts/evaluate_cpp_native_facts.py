#!/usr/bin/env python3
"""One immutable image per process: address-backed calls and declared type facts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import capstone
from cpp_call_contracts import _accepts, _prototype_arity, analyze_calls
from cpp_native_call_facts import (
    bind_calls,
    compare_signature,
    declared_signature,
    decode_function,
    native_calls,
    serial_signature,
)
from cpp_recompile_support import signatures

from decbench.metrics.cpp_type_match import CppOracleContext
from decbench.metrics.cpp_types import UnsupportedType
from decbench.models.decompilation import DecompilationResult, FunctionDecompilation
from decbench.utils import binfmt
from decbench.utils.pdb_info import PdbFormatError

TOOLS = ("fission", "kuna", "ghidra", "angr")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> Any:
    return json.loads(path.read_text())


def _load(
    path: Path, expected: str | None, evidence: dict[str, str]
) -> dict[int, FunctionDecompilation]:
    path = path.resolve()
    actual = digest(path)
    completion_path = path.parent / "completion.json"
    if completion_path.exists():
        completion = read(completion_path)
        if actual != completion["result_sha256"]:
            raise ValueError("producer differs from original completion")
        contract_path = path.parent / "contract.json"
        if digest(contract_path) != completion["contract_sha256"]:
            raise ValueError("producer capture contract changed")
        contract = read(contract_path)
        captured_plan = path.parents[2] / "plan.json"
        if digest(captured_plan) != contract["plan_sha256"]:
            raise ValueError("producer capture plan changed")
        evidence[str(contract_path)] = digest(contract_path)
        evidence[str(captured_plan)] = digest(captured_plan)
    elif expected is None:
        raise ValueError("producer requires original completion or frozen expected hash")
    if expected is not None and actual != expected:
        raise ValueError("frozen producer hash differs")
    result = DecompilationResult.model_validate_json(path.read_text())
    functions = list(result.functions.values())
    if len({f.address for f in functions}) != len(functions):
        raise ValueError("duplicate producer address")
    evidence[str(path)] = actual
    return {f.address: f for f in functions}


def evaluate(plan_path: Path, output: Path) -> dict:
    script_paths = [
        Path(__file__),
        Path(__file__).with_name("cpp_native_call_facts.py"),
        Path(__file__).with_name("cpp_call_contracts.py"),
        Path(__file__).with_name("cpp_recompile_support.py"),
    ]
    source_snapshot = {str(p): digest(p) for p in script_paths}
    plan = read(plan_path)
    original, stripped = Path(plan["original"]), Path(plan["input"])
    for path, key in [(original, "binary_sha256"), (stripped, "stripped_sha256")]:
        if digest(path) != plan["cell"][key]:
            raise ValueError("frozen image hash changed")
    if binfmt.executable_regions(original) != binfmt.executable_regions(stripped):
        raise ValueError("oracle and stripped code bytes differ")
    requested = plan["functions"]
    addresses = {r["address"] for r in requested}
    if len(addresses) != len(requested):
        raise ValueError("duplicate requested address")
    context = CppOracleContext(original)
    resolver = context.native.resolver()
    entries: dict[int, list[Any]] = defaultdict(list)
    if context.dwarf is not None:
        for address, dies in context.index.items():
            entries[address] = list({die.offset: die for die in dies}.values())
    elif context.pdb is not None:
        for function in context.pdb.functions:
            entries[function.address].append(function)
    model = "LLP64" if plan["cell"]["platform"] == "windows" else "LP64"
    hashes = {
        str(plan_path): digest(plan_path),
        str(original): digest(original),
        str(stripped): digest(stripped),
    }
    hashes.update(source_snapshot)
    hashes.update(
        {str(p): digest(p) for p in sorted(Path(binfmt.__file__).parents[1].rglob("*.py"))}
    )
    for path, expected in plan.get("input_evidence_sha256", {}).items():
        if digest(Path(path)) != expected:
            raise ValueError("original capture evidence changed")
        hashes[path] = expected
    hashes.update({str(p): digest(p) for p in binfmt.native_debug_paths(original) if p.is_file()})
    produced, callees = {}, {}
    for tool in TOOLS:
        path = plan_path.parent / "producers" / tool / "result.json"
        produced[tool] = _load(path, plan.get("producer_sha256", {}).get(tool), hashes)
        if not set(produced[tool]) <= addresses:
            raise ValueError("foreign requested producer address")
        callees[tool] = dict(produced[tool])
        if plan.get("context_root"):
            extra_path = Path(plan["context_root"]) / tool / "result.json"
            extras = _load(extra_path, None, hashes)
            primary_metadata, extra_metadata = (
                read(path)["decompiler"],
                read(extra_path)["decompiler"],
            )
            if any(
                primary_metadata[k] != extra_metadata[k]
                for k in ["decompiler_name", "decompiler_version"]
            ):
                raise ValueError("callee output belongs to another producer/version")
            primary_contract, extra_contract = read(path.parent / "contract.json"), read(
                extra_path.parent / "contract.json"
            )
            if {k: v for k, v in primary_contract.items() if k != "plan_sha256"} != {
                k: v for k, v in extra_contract.items() if k != "plan_sha256"
            }:
                raise ValueError("callee capture configuration differs")
            context_plan = read(Path(plan["context_root"]).parent / "plan.json")
            if context_plan["cell"]["stripped_sha256"] != plan["cell"]["stripped_sha256"]:
                raise ValueError("callee output belongs to another image")
            if digest(Path(context_plan["input"])) != plan["cell"]["stripped_sha256"]:
                raise ValueError("callee capture input changed")
            if not set(extras) <= {r["address"] for r in context_plan["functions"]}:
                raise ValueError("foreign callee-context address")
            # Keep the caller capture primary; only exact target addresses supply extra headers.
            callees[tool] = {**extras, **produced[tool]}
    signature_cache: dict[int, dict] = {}

    def signature_at(address: int) -> dict:
        if address not in signature_cache:
            try:
                signature_cache[address] = {"native": declared_signature(context, address, model)}
            except (UnsupportedType, PdbFormatError) as error:
                signature_cache[address] = {"exclusion": str(error)}
        return signature_cache[address]

    rows = []
    for requested_function in requested:
        address = requested_function["address"]
        instructions, native = [], []
        extent_exclusion = None
        try:
            if len(entries.get(address, [])) != 1:
                raise UnsupportedType("native caller entry missing or ambiguous")
            instructions = decode_function(resolver, requested_function["name"], address)
            native = native_calls(instructions, entries)
            for call in native:
                if call["target_status"] != "unique_native_entry":
                    continue
                try:
                    target_code = resolver.resolve("", call["target_entry"])
                    if call["target_entry"] not in target_code.instruction_starts:
                        raise ValueError("target is not an instruction start")
                except ValueError as error:
                    call["target_status"] = "target_extent_unavailable"
                    call["target_exclusion"] = str(error)
                    del call["target_entry"]
        except UnsupportedType as error:
            # NativeCodeResolver exposes unavailable/ambiguous ranges as ValueError.
            extent_exclusion = str(error)
        signature = signature_at(address)
        facts = {
            "address": address,
            "native_calls": native,
            "extent_exclusion": extent_exclusion,
            "native_return_instructions": [
                i.address for i in instructions if i.group(capstone.CS_GRP_RET)
            ],
            "native_memory_operands_unbound": sum(
                operand.type == capstone.CS_OP_MEM for i in instructions for operand in i.operands
            ),
            "tools": {},
        }
        for tool in TOOLS:
            function = produced[tool].get(address) or FunctionDecompilation(
                name="", address=address, decompiled_code=""
            )
            contracts = analyze_calls(function.decompiled_code, {})
            mapped = bind_calls(function, contracts, instructions, native)
            for call in mapped["calls"]:
                linked = call.get("native", {})
                if linked.get("target_status") != "unique_native_entry":
                    continue
                target = linked["target_entry"]
                target_signature = signature_at(target)
                if "native" in target_signature:
                    declared = target_signature["native"]
                    call["target_native_signature"] = {
                        "formal_order_eligible": declared["formal_order_eligible"],
                        "formal_order_exclusions": declared["formal_order_exclusions"],
                        "declared_formal_count": len(declared["parameters"]),
                        "abi_slots_verified": False,
                    }
                else:
                    call["target_native_signature"] = target_signature
                callee = callees[tool].get(target)
                heads = signatures(callee.decompiled_code) if callee else []
                if len(heads) == 1:
                    arity = _prototype_arity(heads[0][1])
                    call["target_output"] = {
                        "address": target,
                        "printed_header": heads[0][1],
                        "arity": arity,
                        "accepts_argument_count": _accepts(arity, call["argument_count"]),
                    }
                else:
                    call["target_output_exclusion"] = (
                        "target output lacks one supported printed header"
                    )
            recovery = (
                compare_signature(signature["native"], function, model)
                if "native" in signature
                else {"oracle_exclusion": signature["exclusion"]}
            )
            facts["tools"][tool] = {
                "nonempty": bool(function.decompiled_code.strip()),
                "calls": mapped,
                "declared_signature": recovery,
            }
        rows.append(facts)
    context.validate(original)
    for evidence_path, expected in hashes.items():
        if digest(Path(evidence_path)) != expected:
            raise ValueError("evidence changed during native evaluation")
    result = {
        "profile": "cpp-native-call-and-declared-facts-v1-diagnostic",
        "official_score": False,
        "execution_parity": False,
        "abi_slots_verified": False,
        "actual_field_access_verified": False,
        "cell": {k: plan["cell"][k] for k in ["id", "project", "platform", "optimization"]},
        "requested": len(requested),
        "evidence_sha256": hashes,
        "source_sha256": source_snapshot,
        "native_signatures": {
            str(a): serial_signature(v["native"]) if "native" in v else v
            for a, v in signature_cache.items()
        },
        "functions": rows,
    }
    summary = {}
    for tool in TOOLS:
        count: Counter = Counter(requested=len(rows))
        for row in rows:
            produced_row = row["tools"][tool]
            count["nonempty"] += produced_row["nonempty"]
            count["native_calls"] += len(row["native_calls"])
            for call in produced_row["calls"]["calls"]:
                count["output_calls"] += 1
                count["call_binding:" + call["binding_status"]] += 1
                if "native" in call:
                    count["linked_target:" + call["native"]["target_status"]] += 1
                if "target_output" in call:
                    count["target_output_header"] += 1
                    count["target_output_arity_disagreement"] += (
                        call["target_output"]["accepts_argument_count"] is False
                    )
            recovery = produced_row["declared_signature"]
            returned = recovery.get("return", {})
            if returned.get("oracle_eligible"):
                count["return_eligible"] += 1
                count["return_strict_agreement"] += returned["strict_agreement"]
                count["return_correct_facts"] += returned["correct_facts"]
                count["return_total_facts"] += returned["total_facts"]
            if recovery.get("formal_order_eligible"):
                count["formal_order_eligible"] += 1
                count["parameter_count_agreement"] += recovery["parameter_count_agreement"]
            for parameter in recovery.get("parameters", []):
                count["parameter_total_facts"] += parameter["total_facts"]
                count["parameter_correct_facts"] += parameter["correct_facts"]
                count["declared_field_total_facts"] += parameter["declared_field_facts"]
                count["declared_field_correct_facts"] += sum(
                    fact["status"] == "correct"
                    and any(part.startswith("field@") for part in fact["path"])
                    for fact in parameter["facts"]
                )
        summary[tool] = dict(count)
    result["summary"] = summary
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return {"cell": result["cell"], "summary": summary}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("new output path required")
    print(json.dumps(evaluate(args.plan, args.output), indent=2), flush=True)
    # The completed per-image worker owns a large cyclic native debug index.
    os._exit(0)


if __name__ == "__main__":
    main()
