#!/usr/bin/env python3
"""Report fixed-population C++ type coverage, fact recall and exact agreement.

Consumes saved four-tool decisions without executing a producer or changing any
metric. Declared type graphs cannot establish returns or actual memory accesses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from decbench.metrics.cpp_type_facts import PROFILE, assess_recovery, extract_type_facts
from decbench.metrics.cpp_type_graph import TypeGraph
from decbench.metrics.cpp_types import UnsupportedType

TOOLS = ("fission", "kuna", "ghidra", "angr")


def saved_graph(value: dict[str, Any]) -> TypeGraph:
    try:
        return TypeGraph.from_payload(
            {
                "schema": "decbench-cpp-type-graph-v1",
                "root": value["root"],
                "nodes": {key: {**node, "complete": True} for key, node in value["nodes"].items()},
            }
        )
    except UnsupportedType as exc:
        raise ValueError("malformed saved evaluator type graph") from exc


def validate_decisions(value: dict[str, Any]) -> list[dict[str, Any]]:
    meta = value["metadata"]
    rows: list[dict[str, Any]] = meta["decisions"]
    if not rows or len(rows) != meta["ground_truth_count"]:
        raise ValueError("inconsistent saved variable population")
    if len({row["identity"] for row in rows}) != len(rows):
        raise ValueError("duplicate oracle variable identity")
    matches = [row["matched_identity"] for row in rows if row["matched_identity"] is not None]
    if len(set(matches)) != len(matches) or len(matches) != meta["matched_count"]:
        raise ValueError("ambiguous or inconsistent saved variable correspondence")
    correct = sum(row["verdict"] == "correct" for row in rows)
    if correct != meta["correct_count"] or value["value"] != correct / len(rows):
        raise ValueError("saved exact score disagrees with decisions")
    return rows


def oracle_exclusions(profile: dict[str, Any], addresses: dict[str, int]) -> dict[int, str]:
    excluded = {}
    for error in profile["errors"]:
        keys = [name for name in addresses if error.startswith(name + ": ")]
        if len(keys) != 1:
            raise ValueError("oracle exclusion has ambiguous requested identity")
        name = keys[0]
        address = addresses[name]
        if address in excluded or name in profile["function_results"]:
            raise ValueError("duplicate or contradictory oracle population")
        excluded[address] = error[len(name) + 2 :]
    if len(excluded) + len(profile["function_results"]) != len(addresses):
        raise ValueError("requested population is not fully accounted for")
    return excluded


def report(paths: list[Path]) -> dict[str, Any]:
    summaries: dict[str, dict[str, Any]] = {}
    for tool in TOOLS:
        summaries[tool] = {
            "requested_functions": 0,
            "oracle_eligible_functions": 0,
            "oracle_excluded_functions": 0,
            "variables": 0,
            "matched_variables": 0,
            "exact_abi_variables": 0,
            "strict_abi_perfect_functions": 0,
            "strict_source_perfect_functions": 0,
            "correct_facts": 0,
            "total_facts": 0,
            "variable_categories": Counter(),
            "recorded_oracle_exclusions": Counter(),
            "dimensions": defaultdict(Counter),
            "root_dimensions": defaultdict(Counter),
            "oracle_fact_gaps": Counter(),
            "unscored_recovered_fact_slots": 0,
        }
    rows = []
    inputs = []
    seen_cells = set()
    for path in paths:
        raw = path.read_bytes()
        cell = json.loads(raw)
        if cell["cell"] in seen_cells or set(cell["tools"]) != set(TOOLS):
            raise ValueError("duplicate cell or missing producer")
        seen_cells.add(cell["cell"])
        inputs.append({"name": path.name, "sha256": hashlib.sha256(raw).hexdigest()})
        common_population = None
        for tool in TOOLS:
            producer = cell["tools"][tool]
            addresses = producer["function_addresses"]
            if len(addresses) != cell["requested"] or len(set(addresses.values())) != len(
                addresses
            ):
                raise ValueError("requested function multiplicity is ambiguous")
            source, abi = (producer["profiles"][view] for view in ("source", "abi"))
            if set(source["function_results"]) != set(abi["function_results"]):
                raise ValueError("source and ABI populations disagree")
            for profile in (source, abi):
                if profile["perfect_count"] != sum(
                    value["value"] == 1 for value in profile["function_results"].values()
                ):
                    raise ValueError("saved perfect aggregate disagrees with decisions")
            excluded = oracle_exclusions(abi, addresses)
            if oracle_exclusions(source, addresses) != excluded:
                raise ValueError("source and ABI oracle exclusions disagree")
            oracle_rows = {}
            function_recalls = []
            s = summaries[tool]
            s["requested_functions"] += len(addresses)
            s["oracle_excluded_functions"] += len(excluded)
            s["recorded_oracle_exclusions"].update(excluded.values())
            for name, address in addresses.items():
                header = {"cell": cell["cell"], "tool": tool, "function": name, "address": address}
                if address in excluded:
                    rows.append(
                        {
                            **header,
                            "status": "oracle_insufficient",
                            "reason": excluded[address],
                            "fact_recall": None,
                        }
                    )
                    continue
                value = abi["function_results"][name]
                decisions = validate_decisions(value)
                source_decisions = validate_decisions(source["function_results"][name])
                if [(row["identity"], row["matched_identity"]) for row in source_decisions] != [
                    (row["identity"], row["matched_identity"]) for row in decisions
                ]:
                    raise ValueError("source and ABI type-blind correspondence changed")
                if [
                    {key: val for key, val in d["expected"].items() if key != "view"}
                    for d in source_decisions
                ] != [
                    {key: val for key, val in d["expected"].items() if key != "view"}
                    for d in decisions
                ]:
                    raise ValueError("source and ABI oracle type graphs changed")
                if (
                    source["function_results"][name]["metadata"]["data_model"]
                    != value["metadata"]["data_model"]
                ):
                    raise ValueError("source and ABI data models changed")
                oracle_rows[address] = {
                    "data_model": value["metadata"]["data_model"],
                    "decisions": [
                        {"identity": d["identity"], "expected": d["expected"]} for d in decisions
                    ],
                }
                s["oracle_eligible_functions"] += 1
                s["variables"] += len(decisions)
                s["matched_variables"] += value["metadata"]["matched_count"]
                s["exact_abi_variables"] += value["metadata"]["correct_count"]
                s["strict_abi_perfect_functions"] += value["value"] == 1
                s["strict_source_perfect_functions"] += (
                    source["function_results"][name]["value"] == 1
                )
                diagnosed = []
                for decision in decisions:
                    expected = extract_type_facts(saved_graph(decision["expected"]))
                    actual = None
                    projection_error = None
                    verdict = decision["verdict"]
                    if verdict in {"correct", "type_mismatch"}:
                        if decision["actual"] is None or decision["matched_identity"] is None:
                            raise ValueError(
                                "typed saved decision lacks recovery or correspondence"
                            )
                        try:
                            actual = extract_type_facts(saved_graph(decision["actual"]))
                        except UnsupportedType as exc:
                            if verdict == "correct":
                                raise ValueError("exact recovery exceeds fact profile") from exc
                            projection_error = str(exc)
                            verdict = "unsupported_recovered_type"
                    result = assess_recovery(expected, actual, verdict)
                    diagnosed.append(
                        {
                            "identity": decision["identity"],
                            "matched_identity": decision["matched_identity"],
                            "previous_verdict": decision["verdict"],
                            "projection_error": projection_error,
                            "source_evidence_unobservable": decision["identity"]
                            in value["metadata"].get("unobservable_source", []),
                            **result,
                        }
                    )
                    s["variable_categories"][result["category"]] += 1
                    s["correct_facts"] += result["correct_facts"]
                    s["total_facts"] += result["total_facts"]
                    s["unscored_recovered_fact_slots"] += len(
                        result["unscored_recovered_fact_slots"]
                    )
                    s["oracle_fact_gaps"].update(gap.reason for gap in expected.gaps)
                    for fact in result["facts"]:
                        s["dimensions"][fact["attribute"]][fact["status"]] += 1
                        if fact["path"] == ("root",):
                            s["root_dimensions"][fact["attribute"]][fact["status"]] += 1
                correct = sum(d["correct_facts"] for d in diagnosed)
                total = sum(d["total_facts"] for d in diagnosed)
                function_recalls.append(correct / total)
                rows.append(
                    {
                        **header,
                        "status": "assessed",
                        "correct_facts": correct,
                        "total_facts": total,
                        "fact_recall": correct / total,
                        "strict_abi_value": value["value"],
                        "strict_source_value": source["function_results"][name]["value"],
                        "producer_validation": value["metadata"].get("producer_validation"),
                        "variables": diagnosed,
                    }
                )
            population = {
                "requested": sorted(addresses.values()),
                "excluded": excluded,
                "oracle_rows": oracle_rows,
            }
            if common_population is not None and common_population != population:
                raise ValueError("producer-dependent requested/oracle population")
            common_population = population
            s.setdefault("function_fact_recalls", []).extend(function_recalls)
        if path.read_bytes() != raw:
            raise ValueError("input evidence changed during diagnosis")
    for s in summaries.values():
        requested, eligible = s["requested_functions"], s["oracle_eligible_functions"]
        s["oracle_coverage"] = eligible / requested if requested else None
        s["fact_recall"] = s["correct_facts"] / s["total_facts"] if s["total_facts"] else None
        recalls = s.pop("function_fact_recalls", [])
        s["mean_function_fact_recall"] = sum(recalls) / len(recalls) if recalls else None
        s["strict_abi_perfect_rate"] = (
            s["strict_abi_perfect_functions"] / eligible if eligible else None
        )
        if s["oracle_excluded_functions"] + eligible != requested:
            raise ValueError("unaccounted requested entries")
    return {
        "profile": PROFILE,
        "official_score": False,
        "measurement": "saved four-tool decision diagnosis; no fresh producer/native execution",
        "capabilities": {
            "declared_variable_type_facts": True,
            "argument_vs_local_identity": "not retained in saved decisions",
            "return_type_facts": "not measured",
            "actual_accessed_field_facts": "not measured",
            "compilation": "not measured in this report",
            "execution": "not measured in this report",
        },
        "inputs": inputs,
        "summary": summaries,
        "rows": rows,
    }


def markdown(result: dict[str, Any]) -> str:
    lines = [
        "# C++ declared-type diagnosis (experimental)",
        "",
        "Saved outputs; independent type facts; no new official score or ranking.",
        "",
        "| Tool | Oracle coverage | Declared-type fact recall | Strict ABI-perfect |",
        "| --- | ---: | ---: | ---: |",
    ]
    for tool, s in result["summary"].items():
        recall = f"{s['fact_recall']:.1%}" if s["fact_recall"] is not None else "unmeasurable"
        facts = (
            f"{s['correct_facts']}/{s['total_facts']} ({recall})"
            if s["total_facts"]
            else "unmeasurable"
        )
        perfect = (
            f"{s['strict_abi_perfect_functions']}/{s['oracle_eligible_functions']}"
            if s["oracle_eligible_functions"]
            else "unmeasurable"
        )
        lines.append(
            f"| {tool} | {s['oracle_eligible_functions']}/{s['requested_functions']} | "
            f"{facts} | {perfect} |"
        )
    lines += [
        "",
        "## Root variable facts (separate from nested layout requirements)",
        "",
        "| Tool | Type-kind facts | Storage-width facts |",
        "| --- | ---: | ---: |",
    ]
    for tool, s in result["summary"].items():
        counts = []
        for attribute in ("type_kind", "size_bytes"):
            dimension = s["root_dimensions"].get(attribute, {})
            total = sum(dimension.values())
            counts.append(f"{dimension.get('correct', 0)}/{total}" if total else "unmeasurable")
        lines.append(f"| {tool} | {counts[0]} | {counts[1]} |")
    lines += [
        "",
        "## Failure diagnosis (variables within the eligible population)",
        "",
        "| Tool | Correspondence | Recovery/support gap | Observed type mismatch |",
        "| --- | ---: | ---: | ---: |",
    ]
    for tool, s in result["summary"].items():
        c = s["variable_categories"]
        lines.append(
            f"| {tool} | {c.get('correspondence_failure', 0)} | "
            f"{c.get('recovery_information_gap', 0)} | {c.get('type_mismatch', 0)} |"
        )
    lines += [
        "",
        "Oracle exclusions remain separate function-level counts; units are not added together.",
        "Recovery/support gaps do not prove a decompiler defect: unsupported evaluator parsing",
        "and missing emitted declarations cannot always be separated in saved decisions.",
        "Observed type mismatches are descriptor disagreements, not proven execution errors.",
        "",
        "Fact recall includes type kind, width and supported declared layout facts.",
        "Same-width integers can earn width credit while failing pointer-kind facts.",
        "Missing/invalid recovery contributes zero over the same oracle fact denominator.",
        "A fact recall of 100% does not replace the strict whole-type result.",
        "Micro recall weights facts equally; JSON also retains macro function recall.",
        "Pointees are expanded through at most two pointer hops, with explicit depth gaps.",
        "",
        "Argument/local roles, returns, actual field accesses, compilation and execution",
        "are not measured here. Full class layouts are not evidence of executed accesses.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    paths = sorted(args.reports.glob("*.json"))
    if not paths:
        parser.error("no saved cell reports")
    if args.output.suffix != ".json":
        parser.error("output must have a .json suffix")
    if args.output.resolve().parent == args.reports.resolve():
        parser.error("output must be outside the input report directory")
    targets = {args.output.resolve(), args.output.with_suffix(".md").resolve()}
    if targets & {p.resolve() for p in paths}:
        parser.error("output must not overwrite input evidence")
    result = report(paths)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    args.output.with_suffix(".md").write_text(markdown(result))
    print(markdown(result))


if __name__ == "__main__":
    main()
