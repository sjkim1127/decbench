#!/usr/bin/env python3
"""Evaluate a frozen owned-entry pilot; rank an explicit experimental Union.

Union uses perfect definition-only GED or experimental ABI types over the
common oracle-eligible union. Returns/partial facts/bytes do not enter Union.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from report_cpp_type_diagnostics import markdown, oracle_exclusions, report
from run_cpp_whole_binary import TOOLS, atomic, digest

from decbench.metrics.base import MetricConfig
from decbench.metrics.cpp_signature_evidence import native_signature, recovered_return
from decbench.metrics.cpp_type_facts import assess_recovery, extract_type_facts
from decbench.metrics.cpp_type_match import CppOracleContext, CppTypeMatchMetric
from decbench.metrics.cpp_types import UnsupportedType
from decbench.metrics.ged import GED_MAX_NODES
from decbench.models.decompilation import DecompilationResult
from decbench.pipeline.cpp_ged import evaluate_cpp_ged
from decbench.utils import binfmt
from decbench.utils.cfg_identity import (
    SourceCfgIndex,
    native_sources,
    origin_source,
    source_unit_matches,
)
from decbench.utils.pdb_info import PdbFormatError
from decbench.utils.producer_validation import inspect_producer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--data-model", choices=("LP64", "LLP64", "ILP32"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    binary = Path(plan["original"])
    if digest(binary) != plan["cell"]["binary_sha256"]:
        raise ValueError("original oracle image changed")
    if digest(Path(plan["preprocessed_archive"])) != plan["preprocessed_archive_sha256"]:
        raise ValueError("preprocessed evidence changed")
    contract = {
        "plan_sha256": digest(args.plan),
        "data_model": args.data_model,
        "python": sys.version,
        "ged_max_nodes": GED_MAX_NODES,
        "rust_joern_sha256": digest(Path(os.environ["RUST_JOERN_LIBRARY"])),
        "driver_sha256": digest(Path(__file__)),
        "source_sha256": digest(Path(__file__).with_name("report_cpp_type_diagnostics.py")),
        "producer_sha256": {
            tool: digest(args.plan.parent / "producers" / tool / "result.json") for tool in TOOLS
        },
        "owners": {
            str(p.relative_to(Path(binfmt.__file__).parents[1])): digest(p)
            for p in sorted(Path(binfmt.__file__).parents[1].rglob("*.py"))
        },
    }
    args.output.mkdir(parents=True, exist_ok=args.resume)
    contract_path = args.output / "evaluation-contract.json"
    if contract_path.exists() and json.loads(contract_path.read_text()) != contract:
        raise ValueError("evaluation resume contract changed")
    atomic(contract_path, contract)
    requested = [(r["name"], r["address"]) for r in plan["functions"]]
    addresses = {a for _, a in requested}
    context = CppOracleContext(binary)
    native = native_sources(binary, addresses)
    source_index = SourceCfgIndex()
    source_dir = args.output / "sources"
    source_dir.mkdir(exist_ok=True)
    source_paths: list[Path] = []
    sources: list[dict[str, Any]] = []
    records = tuple(r[0] for r in native.values() if len(r) == 1)
    with tarfile.open(plan["preprocessed_archive"], "r|gz") as archive:
        for member in archive:
            if not member.isfile() or not member.name.startswith(
                plan["cell"]["optimization"] + "/"
            ):
                continue
            if Path(member.name).suffix != ".ii":
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("unreadable preprocessed member")
            raw = stream.read()
            text = raw.decode("utf-8", "replace")
            primary = origin_source("\n".join(text.splitlines()[:64])).primary
            if not any(source_unit_matches(primary, r) for r in records):
                continue
            path = source_dir / f"{len(source_paths):03d}.ii"
            path.write_bytes(raw)
            source_paths.append(path)
            source_index.add(text, member.name, native_records=records)
            sources.append({"member": member.name, "sha256": digest(path), "primary": primary})
    if not source_paths:
        raise ValueError("no preprocessed TUs proved for requested native entries")
    print("prepared sources", len(sources), flush=True)
    cell = {
        "cell": plan["cell"]["id"],
        "project": plan["cell"]["project"],
        "platform": plan["cell"]["platform"],
        "optimization": plan["cell"]["optimization"],
        "requested": len(requested),
        "original_binary_sha256": digest(binary),
        "sources": sources,
        "official_score": False,
        "tools": {},
    }
    returns = []
    for _, address in requested:
        try:
            signature = native_signature(context, address, args.data_model)
            payload = asdict(signature)
            expected = (
                extract_type_facts(signature.declared_return) if signature.declared_return else None
            )
        except (UnsupportedType, PdbFormatError) as error:
            signature, expected = None, None
            payload = {"address": address, "exclusion": str(error)}
        returns.append(
            {
                "address": address,
                "native": payload,
                "tools": {},
                "signature": signature,
                "expected": expected,
            }
        )
    signatures = {
        "profile": "cpp-debug-signature-v1-diagnostic",
        "official_score": False,
        "cell": plan["cell"]["id"],
        "binary_sha256": digest(binary),
        "data_model": args.data_model,
        "debug_sha256": {
            str(p): digest(p) for p in binfmt.native_debug_paths(binary) if p.is_file()
        },
        "producer_sha256": {},
        "abi_slots_verified": False,
        "execution": "not measured",
        "summary": {},
    }
    native_population = None
    score_rows = []
    for tool in TOOLS:
        producer_dir = args.plan.parent / "producers" / tool
        producer_path = producer_dir / "result.json"
        completion = json.loads((producer_dir / "completion.json").read_text())
        contract = json.loads((producer_dir / "contract.json").read_text())
        if (
            digest(producer_path) != completion["result_sha256"]
            or digest(producer_dir / "contract.json") != completion["contract_sha256"]
            or contract["plan_sha256"] != digest(args.plan)
        ):
            raise ValueError("producer completion/contract hash mismatch")
        produced = DecompilationResult.model_validate_json(producer_path.read_text())
        by_address = {f.address: f for f in produced.functions.values()}
        if len(by_address) != len(produced.functions) or set(by_address) != addresses:
            raise ValueError("producer result does not account for exact requested population")
        shards = {p.name: digest(p) for p in (producer_dir / "functions").glob("*.json")}
        if shards != completion["shard_sha256"]:
            raise ValueError("producer function shards changed")
        outcomes = Counter(
            json.loads((producer_dir / "functions" / name).read_text())["status"] for name in shards
        )
        if sum(outcomes.values()) != len(requested):
            raise ValueError("terminal outcomes do not cover requested functions")
        checkpoint = args.output / f"{tool}-checkpoint.json"
        if args.resume and checkpoint.exists():
            if (
                digest(checkpoint)
                != json.loads(checkpoint.with_suffix(".sha256.json").read_text())["sha256"]
            ):
                raise ValueError("tool checkpoint bytes changed")
            saved = json.loads(checkpoint.read_text())
            if saved["contract_sha256"] != digest(contract_path):
                raise ValueError("tool evaluation checkpoint contract changed")
            cell["tools"][tool] = saved["evaluation"]
            score_rows.append(saved["score_row"])
            signatures["summary"][tool] = saved["return_summary"]
            signatures["producer_sha256"][str(producer_path.resolve())] = digest(producer_path)
            for item in returns:
                item["tools"][tool] = saved["return_rows"][str(item["address"])]
            print(tool, "reused evaluation checkpoint", flush=True)
            continue
        working = produced.model_copy(deep=True)
        working.binary_path, working.binary_name, working.functions = binary, binary.stem, {}
        for name, address in requested:
            function = by_address[address].model_copy(deep=True)
            function.metadata["measurement_producer_display_name"] = function.name
            function.name = name
            working.add_function(function)
        function_addresses = {k: f.address for k, f in working.functions.items()}
        profiles = {}
        for view in ("source", "abi"):
            metric = CppTypeMatchMetric(
                MetricConfig(
                    use_cache=False, extra_options={"view": view, "data_model": args.data_model}
                )
            )
            profiles[view] = metric.compute_for_binary(
                working,
                requested_functions=requested,
                oracle_context=context,
                preprocessed_sources=source_paths,
            ).model_dump(mode="json")
            print(tool, view, "eligible", len(profiles[view]["function_results"]), flush=True)
        ged = evaluate_cpp_ged(
            working, source_index=source_index, native_index=native, requested_functions=requested
        ).model_dump(mode="json")
        ged_eligible = {
            function_addresses[k]
            for k, e in ged["source_evidence"].items()
            if e["status"] == "matched"
        }
        if len(ged_eligible) != ged["source_eligible"]:
            raise ValueError("GED source admission count disagrees with evidence")
        excluded = oracle_exclusions(profiles["abi"], function_addresses)
        type_eligible = {function_addresses[k] for k in profiles["abi"]["function_results"]}
        population = (
            ged_eligible,
            type_eligible,
            excluded,
            {k: e for k, e in ged["source_evidence"].items()},
        )
        if native_population is not None and population != native_population:
            raise ValueError("producer-dependent oracle eligibility/evidence; cannot rank")
        native_population = population
        ged_perfect = {
            function_addresses[k]
            for k, v in ged["metric"]["function_results"].items()
            if v["value"] == 0
        }
        type_perfect = {
            function_addresses[k]
            for k, v in profiles["abi"]["function_results"].items()
            if v["value"] == 1
        }
        if not ged_perfect <= ged_eligible or not type_perfect <= type_eligible:
            raise ValueError("perfect result outside oracle population")
        eligible_union = ged_eligible | type_eligible
        perfect_union = ged_perfect | type_perfect
        score_rows.append(
            {
                "tool": tool,
                "version": produced.decompiler.decompiler_version,
                "requested": len(requested),
                "nonempty": completion["nonempty"],
                "ged_eligible": len(ged_eligible),
                "ged_paired": ged["paired"],
                "ged_perfect": len(ged_perfect),
                "type_eligible": len(type_eligible),
                "type_perfect": len(type_perfect),
                "union_eligible": len(eligible_union),
                "union_perfect": len(perfect_union),
                "union_rate": len(perfect_union) / len(eligible_union) if eligible_union else None,
                "oracle_unmeasurable": len(addresses - eligible_union),
                "perfect_addresses": sorted(perfect_union),
                "ged_source_statuses": ged["source_statuses"],
                "producer_cfg_statuses": ged["decompiled_statuses"],
                "type_exclusions": dict(Counter(excluded.values())),
                "producer_terminal_outcomes": outcomes,
                "worker_timeout_events": sum(
                    json.loads(p.read_text()).get("timeout", False)
                    for p in producer_dir.glob("worker-*.json")
                ),
            }
        )
        cell["tools"][tool] = {
            "profiles": profiles,
            "ged": ged,
            "function_addresses": function_addresses,
            "nonempty": completion["nonempty"],
        }
        counts = Counter(
            requested=0, native_returns=0, perfect_returns=0, correct_facts=0, total_facts=0
        )
        return_by_address = {f.address: f for f in working.functions.values()}
        for item in returns:
            counts["requested"] += 1
            expected, signature = item["expected"], item["signature"]
            if expected is None:
                item["tools"][tool] = {"status": "oracle_return_unavailable"}
                continue
            function = return_by_address[item["address"]]
            inspection = inspect_producer(function.decompiled_code, function.metadata)
            actual, recovery_error = None, None
            status = (
                "invalid_producer_output" if inspection.invalid else "unsupported_recovered_type"
            )
            if not inspection.invalid:
                try:
                    actual = recovered_return(function.decompiled_code, args.data_model)
                    status = (
                        "correct"
                        if actual.project("abi") == signature.declared_return.project("abi")
                        else "type_mismatch"
                    )
                except UnsupportedType as error:
                    recovery_error = str(error)
            assessed = assess_recovery(
                expected, extract_type_facts(actual) if actual else None, status
            )
            counts.update(
                native_returns=1,
                perfect_returns=status == "correct",
                correct_facts=assessed["correct_facts"],
                total_facts=assessed["total_facts"],
            )
            item["tools"][tool] = {
                "status": status,
                "recovery_exclusion": recovery_error,
                "actual_return": asdict(actual) if actual else None,
                "producer_validation": inspection.evidence(),
                "assessment": assessed,
            }
        signatures["summary"][tool] = counts
        signatures["producer_sha256"][str(producer_path.resolve())] = digest(producer_path)
        atomic(args.output / f"{tool}-evaluation.json", cell["tools"][tool])
        atomic(
            checkpoint,
            {
                "contract_sha256": digest(contract_path),
                "evaluation": cell["tools"][tool],
                "score_row": score_rows[-1],
                "return_summary": counts,
                "return_rows": {str(row["address"]): row["tools"][tool] for row in returns},
            },
        )
        atomic(checkpoint.with_suffix(".sha256.json"), {"sha256": digest(checkpoint)})
        print(
            tool,
            "GED",
            len(ged_perfect),
            "/",
            len(ged_eligible),
            "types",
            len(type_perfect),
            "/",
            len(type_eligible),
            flush=True,
        )
    context.validate(binary)
    oracle_evidence = None
    for tool in TOOLS:
        saved = cell["tools"][tool]
        evidence = (
            saved["ged"]["source_evidence"],
            oracle_exclusions(saved["profiles"]["abi"], saved["function_addresses"]),
        )
        if oracle_evidence is not None and oracle_evidence != evidence:
            raise ValueError("checkpoint oracle populations disagree; cannot rank")
        oracle_evidence = evidence
    decisions = args.output / "decisions"
    decisions.mkdir(exist_ok=True)
    atomic(decisions / (cell["cell"] + ".json"), cell)
    facts = report([decisions / (cell["cell"] + ".json")])
    atomic(args.output / "diagnosis.json", facts)
    (args.output / "diagnosis.md").write_text(markdown(facts))
    signatures["functions"] = [
        {k: v for k, v in row.items() if k not in {"signature", "expected"}} for row in returns
    ]
    signature_dir = args.output / "signatures"
    signature_dir.mkdir(exist_ok=True)
    atomic(signature_dir / (cell["cell"] + ".json"), signatures)
    score_rows.sort(key=lambda r: (-r["union_perfect"], r["tool"]))
    for row in score_rows:
        row["rank"] = (
            1 + sum(r["union_perfect"] > row["union_perfect"] for r in score_rows)
            if row["union_eligible"]
            else None
        )
    ranking = {
        "profile": "cpp-owned-union-v1-experimental",
        "official_score": False,
        "plan_sha256": digest(args.plan),
        "data_model": args.data_model,
        "definition": "perfect definition-only GED OR experimental ABI type; common eligible union",
        "rows": score_rows,
        "byte_match": "unmeasured; not included in this profile",
        "returns": "diagnostic only; not part of Union",
        "execution": "unmeasured",
        "policy_bounds": "definition-only CFG; experimental ABI types; address-guided entries",
        "coverage_bounds": "concrete owned entries with original-source declaration evidence",
        "transport": "stripped producer input; native/source evidence restricted to evaluation",
    }
    atomic(args.output / "ranking.json", ranking)
    lines = [
        f"# {plan['cell']['project']} owned-entry local experimental ranking",
        "",
        "Perfect GED OR ABI type over a common oracle-eligible union. Not official DecBench.",
        "",
        "| Rank | Tool | Nonempty / requested | GED perfect / oracle | "
        "ABI types perfect / oracle | Experimental Union |",
        "| ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in score_rows:
        lines.append(
            f"| {row['rank']} | {row['tool']} {row['version']} | "
            f"{row['nonempty']}/{row['requested']} | "
            f"{row['ged_perfect']}/{row['ged_eligible']} | "
            f"{row['type_perfect']}/{row['type_eligible']} | "
            f"{row['union_perfect']}/{row['union_eligible']} |"
        )
    lines += [
        "",
        "Missing/invalid/unparsed producer recovery remains in eligible denominators.",
        "Source/type oracle exclusions are explicit. Byte/return diagnostics do not enter Union.",
        "No execution parity, current-release rank or cross-project generalization is established.",
    ]
    (args.output / "ranking.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(ranking, indent=2), flush=True)


if __name__ == "__main__":
    main()
