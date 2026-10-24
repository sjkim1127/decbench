#!/usr/bin/env python3
"""Rank a complete frozen C++ diagnostic cohort on common oracle populations.

Perfect definition-only GED OR experimental ABI type follows the existing
whole-binary pilot's rule. It is not the default DecBench Union or a byte score.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from evaluate_cpp_cohort import TOOLS, atomic, digest
from report_cpp_type_diagnostics import markdown, oracle_exclusions, report


def rank(root: Path, output: Path) -> dict[str, Any]:
    contract_path = root / "contract.json"
    contract = json.loads(contract_path.read_bytes())
    completion = json.loads((root / "completion.json").read_bytes())
    if completion["contract_sha256"] != digest(contract_path):
        raise ValueError("completion contract changed")
    plans = {json.loads(Path(p).read_bytes())["cell"]["id"]: p for p in contract["plans"]}
    completed = completion["rows"]
    if (
        len(plans) != len(contract["plans"])
        or len(completed) != len(plans)
        or {row["cell"] for row in completed} != set(plans)
    ):
        raise ValueError("incomplete or duplicate cell population")
    for path, expected in contract["plans"].items():
        if digest(Path(path)) != expected:
            raise ValueError("cohort plan changed")
    totals = {tool: Counter() for tool in TOOLS}
    versions: dict[str, set[str]] = defaultdict(set)
    populations: dict[str, Counter] = defaultdict(Counter)
    ledger, paths = [], []
    capture_kinds: set[str] = set()
    seen = set()
    for done in completed:
        path = root / "cells" / (done["cell"] + ".json")
        if done["status"] != "complete" or done["contract_sha256"] != digest(contract_path):
            raise ValueError("evaluator failure is not an oracle exclusion; finish the cohort")
        if digest(path) != done["result_sha256"]:
            raise ValueError("cell result changed")
        cell = json.loads(path.read_bytes())
        plan = json.loads(Path(plans[done["cell"]]).read_bytes())
        capture_kinds.add(cell.get("capture_kind", "frozen_artifact"))
        expected = {r["address"] for r in plan["functions"]}
        if len(expected) != len(plan["functions"]) or cell["requested"] != len(expected):
            raise ValueError("requested address multiplicity differs")
        if cell["cell"] != done["cell"] or set(cell["tools"]) != set(TOOLS):
            raise ValueError("cell or tools differ")
        for location, checksum in cell["evidence_sha256"].items():
            if digest(Path(location)) != checksum:
                raise ValueError("cell input/oracle evidence changed")
        if (
            digest(Path(plan["original"])) != cell["original_binary_sha256"]
            or digest(Path(plan["input"])) != cell["stripped_binary_sha256"]
        ):
            raise ValueError("native image changed")
        population = None
        for tool in TOOLS:
            values = cell["tools"][tool]
            mapping = values["function_addresses"]
            if len(mapping) != len(expected) or set(mapping.values()) != expected:
                raise ValueError("producer denominator differs")
            ged, abi = values["ged"], values["profiles"]["abi"]
            source = {
                mapping[k] for k, v in ged["source_evidence"].items() if v["status"] == "matched"
            }
            typed = {mapping[k] for k in abi["function_results"]}
            exclusions = oracle_exclusions(abi, mapping)
            evidence = (ged["source_evidence"], typed, exclusions)
            if population is not None and population != evidence:
                raise ValueError("producer-dependent oracle evidence; ranking refused")
            population = evidence
            if len(source) != ged["source_eligible"]:
                raise ValueError("source eligibility disagrees")
            structure_perfect = {
                mapping[k] for k, v in ged["metric"]["function_results"].items() if v["value"] == 0
            }
            type_perfect = {
                mapping[k] for k, v in abi["function_results"].items() if v["value"] == 1
            }
            if not structure_perfect <= source or not type_perfect <= typed:
                raise ValueError("perfect result outside oracle population")
            eligible, perfect = source | typed, structure_perfect | type_perfect
            if not eligible <= expected:
                raise ValueError("oracle entry not requested")
            totals[tool].update(
                requested=len(expected),
                nonempty=values["nonempty"],
                ged_eligible=len(source),
                ged_paired=ged["paired"],
                ged_perfect=len(structure_perfect),
                type_eligible=len(typed),
                type_perfect=len(type_perfect),
                union_eligible=len(eligible),
                union_perfect=len(perfect),
                unmeasurable=len(expected - eligible),
            )
            versions[tool].add(values["producer"]["decompiler_version"])
            reverse = {address: key for key, address in mapping.items()}
            for address in sorted(expected):
                key = reverse[address]
                identity = (cell["cell"], address, tool)
                if identity in seen:
                    raise ValueError("duplicate scored row")
                seen.add(identity)
                ledger.append(
                    {
                        "cell": cell["cell"],
                        "address": address,
                        "tool": tool,
                        "ged_eligible": address in source,
                        "type_eligible": address in typed,
                        "ged_perfect": address in structure_perfect if address in source else None,
                        "type_perfect": address in type_perfect if address in typed else None,
                        "union_perfect": address in perfect if address in eligible else None,
                        "source_evidence": ged["source_evidence"][key],
                        "producer_cfg_evidence": ged["decompiled_evidence"][key],
                        "type_exclusion": exclusions.get(address),
                    }
                )
        for dimension in ("project", "platform", "optimization"):
            populations[dimension][cell[dimension]] += len(expected)
        paths.append(path)
    facts = report(paths)
    rows = []
    for tool in TOOLS:
        counts = totals[tool]
        fact = facts["summary"][tool]
        rows.append(
            {
                "tool": tool,
                "versions": sorted(versions[tool]),
                **dict(counts),
                "union_rate": (
                    counts["union_perfect"] / counts["union_eligible"]
                    if counts["union_eligible"]
                    else None
                ),
                "unconditional_union_rate": counts["union_perfect"] / counts["requested"],
                "declared_type_correct_facts": fact["correct_facts"],
                "declared_type_total_facts": fact["total_facts"],
            }
        )
    if (
        len({(r["requested"], r["union_eligible"], r["declared_type_total_facts"]) for r in rows})
        != 1
    ):
        raise ValueError("aggregate populations differ")
    rows.sort(key=lambda row: (-row["union_perfect"], row["tool"]))
    for row in rows:
        row["rank"] = (
            1 + sum(r["union_perfect"] > row["union_perfect"] for r in rows)
            if row["union_eligible"]
            else None
        )
    capture = "fresh metric computation on frozen producer outputs; no fresh decompilation"
    if capture_kinds == {"fresh_address_guided_stripped"}:
        capture = "fresh stripped producer captures and fresh metric computation"
    elif "fresh_address_guided_stripped" in capture_kinds:
        capture = "fresh metric computation on mixed captures; inspect per-cell provenance"
    result = {
        "profile": "cpp-common-oracle-union-v1-experimental",
        "official_score": False,
        "definition": "perfect definition-only GED OR experimental ABI type; common eligible union",
        "contract_sha256": digest(contract_path),
        "cohort": dict(populations),
        "dataset_revision": contract["dataset_revision"],
        "rows": rows,
        "byte_match": "unmeasured; excluded",
        "execution": "unmeasured",
        "capture": capture,
    }
    output.mkdir(parents=True, exist_ok=False)
    atomic(output / "ranking.json", result)
    atomic(output / "ledger.json", ledger)
    atomic(output / "type-facts.json", facts)
    (output / "type-facts.md").write_text(markdown(facts))
    lines = [
        "# Local C++ diagnostic ranking",
        "",
        (
            "Fresh re-scoring of fixed producer captures. Experimental, not official DecBench."
            if capture_kinds == {"frozen_artifact"}
            else capture.capitalize() + ". Experimental, not official DecBench."
        ),
        "",
        "| Rank | Tool / captured version | Nonempty / requested | GED perfect / oracle | "
        "ABI perfect / oracle | Experimental Union / eligible | Union / requested |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['rank']} | {row['tool']} {'/'.join(row['versions'])} | "
            f"{row['nonempty']}/{row['requested']} | {row['ged_perfect']}/{row['ged_eligible']} | "
            f"{row['type_perfect']}/{row['type_eligible']} | "
            f"{row['union_perfect']}/{row['union_eligible']} | "
            f"{row['union_perfect']}/{row['requested']} |"
        )
    lines += [
        "",
        "Unmeasurable entries remain in the requested ledger with reasons.",
        "Missing, invalid or unparsed recovery stays a miss inside common oracle eligibility.",
        "Declared type-fact recall is separate; no runtime field-access, byte or execution credit.",
        "Captured versions are not claims about current releases or latest main.",
    ]
    (output / "ranking.md").write_text("\n".join(lines) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(rank(args.evaluation, args.output), indent=2))


if __name__ == "__main__":
    main()
