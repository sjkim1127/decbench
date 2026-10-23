#!/usr/bin/env python3
"""Replay saved four-tool type decisions under an independent layout proposal.

This reuses frozen type-blind correspondence, not decompiler executions. It never
overwrites input results, registers a metric, or writes scoreboard overlays.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from decbench.metrics.cpp_field_layout import PROFILE, normalize_field_layout
from decbench.metrics.cpp_type_graph import TypeGraph
from decbench.metrics.cpp_types import UnsupportedType

TOOLS = ("fission", "kuna", "ghidra", "angr")


def graph_from_decision(value: dict[str, Any]) -> TypeGraph:
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


def compare_decisions(metadata: dict[str, Any]) -> dict[str, Any]:
    """Oracle support is decided before inspecting any recovered type."""
    decisions = metadata["decisions"]
    if len(decisions) != metadata["ground_truth_count"] or not decisions:
        raise ValueError("saved decision population disagrees with ground truth count")
    if len({row["identity"] for row in decisions}) != len(decisions):
        raise ValueError("duplicate oracle variable identity")
    expected = []
    exclusions = []
    for row in decisions:
        try:
            expected.append(
                normalize_field_layout(graph_from_decision(row["expected"]), metadata["data_model"])
            )
        except UnsupportedType as exc:
            exclusions.append({"identity": row["identity"], "reason": str(exc)})
    if exclusions:
        return {"eligible": False, "oracle_exclusions": exclusions, "decisions": []}
    results = []
    for row, oracle in zip(decisions, expected, strict=True):
        previous = row["verdict"]
        verdict = previous
        actual = None
        reason = None
        if previous in {"correct", "type_mismatch"}:
            if row["actual"] is None or row["matched_identity"] is None:
                raise ValueError("typed saved decision lacks recovery or correspondence")
            try:
                actual = normalize_field_layout(
                    graph_from_decision(row["actual"]), metadata["data_model"]
                )
                verdict = "correct" if oracle.graph == actual.graph else "type_mismatch"
            except UnsupportedType as exc:
                verdict = "unsupported_recovered_layout"
                reason = str(exc)
        elif previous not in {
            "unmatched",
            "unsupported_recovered_type",
            "invalid_producer_output",
            "inconsistent_recovered_storage_width",
        }:
            raise ValueError("unknown saved decision verdict")
        results.append(
            {
                "identity": row["identity"],
                "matched_identity": row["matched_identity"],
                "previous_verdict": previous,
                "verdict": verdict,
                "reason": reason,
                "expected": asdict(oracle),
                "actual": asdict(actual) if actual is not None else None,
            }
        )
    correct = sum(row["verdict"] == "correct" for row in results)
    return {
        "eligible": True,
        "value": correct / len(results),
        "correct_count": correct,
        "ground_truth_count": len(results),
        "decisions": results,
    }


def audit(paths: list[Path]) -> dict[str, Any]:
    summary: dict[str, dict[str, Any]] = {
        tool: {
            "requested": 0,
            "previous_eligible": 0,
            "previous_source_perfect": 0,
            "previous_abi_perfect": 0,
            "layout_eligible": 0,
            "layout_perfect": 0,
            "abi_perfect_on_layout_population": 0,
            "layout_variables": 0,
            "layout_correct": 0,
            "verdicts": Counter(),
            "changes": Counter(),
        }
        for tool in TOOLS
    }
    inputs = []
    rows = []
    seen_cells = set()
    for path in paths:
        raw = path.read_bytes()
        cell = json.loads(raw)
        if cell["cell"] in seen_cells:
            raise ValueError("duplicate cell identity")
        seen_cells.add(cell["cell"])
        if set(cell["tools"]) != set(TOOLS):
            raise ValueError("all four producers required in every cell")
        inputs.append({"name": path.name, "sha256": hashlib.sha256(raw).hexdigest()})
        population = None
        requested_addresses = None
        for tool in TOOLS:
            profiles = cell["tools"][tool]["profiles"]
            source, abi = profiles["source"], profiles["abi"]
            if set(source["function_results"]) != set(abi["function_results"]):
                raise ValueError("source/ABI populations differ")
            addresses = cell["tools"][tool]["function_addresses"]
            if len(addresses) != cell["requested"] or len(set(addresses.values())) != len(
                addresses
            ):
                raise ValueError("producer function multiplicity disagrees with plan")
            if requested_addresses is not None and requested_addresses != set(addresses.values()):
                raise ValueError("producer-dependent requested function population")
            requested_addresses = set(addresses.values())
            current_population = {}
            s = summary[tool]
            s["requested"] += cell["requested"]
            s["previous_eligible"] += len(abi["function_results"])
            s["previous_source_perfect"] += source["perfect_count"]
            s["previous_abi_perfect"] += abi["perfect_count"]
            for name, function in abi["function_results"].items():
                metadata = function["metadata"]
                row = compare_decisions(metadata)
                address = addresses[name]
                current_population[address] = {
                    "data_model": metadata["data_model"],
                    "expected": [d["expected"] for d in metadata["decisions"]],
                    "eligible": row["eligible"],
                    "oracle_exclusions": row.get("oracle_exclusions", []),
                }
                rows.append(
                    {
                        "cell": cell["cell"],
                        "tool": tool,
                        "function": name,
                        "address": address,
                        "previous_abi_value": function["value"],
                        **row,
                    }
                )
                if not row["eligible"]:
                    continue
                s["layout_eligible"] += 1
                s["layout_perfect"] += row["value"] == 1.0
                s["abi_perfect_on_layout_population"] += function["value"] == 1.0
                s["layout_variables"] += row["ground_truth_count"]
                s["layout_correct"] += row["correct_count"]
                for decision in row["decisions"]:
                    s["verdicts"][decision["verdict"]] += 1
                    if decision["previous_verdict"] != decision["verdict"]:
                        s["changes"][
                            decision["previous_verdict"] + " -> " + decision["verdict"]
                        ] += 1
            if population is not None and population != current_population:
                raise ValueError("producer-dependent oracle population or type evidence")
            population = current_population
        if path.read_bytes() != raw:
            raise ValueError("input report changed during replay")
    return {
        "profile": PROFILE,
        "official_score": False,
        "measurement": "saved decision replay; no fresh producer or native-oracle execution",
        "input_reports": inputs,
        "cells": len(paths),
        "summary": summary,
        "rows": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    paths = sorted(args.reports.glob("*.json"))
    if not paths:
        parser.error("no saved cell reports")
    if args.output.resolve() in {p.resolve() for p in paths}:
        parser.error("output must not overwrite input evidence")
    result = audit(paths)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
