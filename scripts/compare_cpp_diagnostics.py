#!/usr/bin/env python3
"""Compare fixed-oracle C++ diagnostics and export bounded investigation packets.

No producer, compiler or target program runs. Exit 1 on lost facts/exact matches;
exit 2 on incompatible oracle populations. Unexpected evaluator errors propagate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from report_cpp_type_diagnostics import TOOLS, report, saved_graph

from decbench.metrics.cpp_type_facts import assess_recovery, extract_type_facts

PROFILE = "cpp-diagnostic-comparison-v1"


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class IncompatibleOracle(ValueError):
    """A before/after quality comparison is undefined for these populations."""


@dataclass
class Snapshot:
    contexts: dict[str, Any]
    cases: dict[tuple[str, str, int, str], Any]
    inputs: list[dict[str, str]]
    evidence: dict[str, Any]


def read_json(path: Path, inputs: list[dict[str, str]]) -> Any:
    raw = path.read_bytes()
    inputs.append({"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()})
    return json.loads(raw)


def facts(assessment: dict[str, Any]) -> dict[tuple[str, ...], dict[str, Any]]:
    indexed = {}
    for fact in assessment["facts"]:
        key = (*fact["path"], fact["attribute"])
        if key in indexed or fact["status"] not in {"correct", "mismatch", "missing"}:
            raise ValueError("duplicate fact slot or unknown fact status")
        indexed[key] = fact
    if (
        len(indexed) != assessment["total_facts"]
        or sum(f["status"] == "correct" for f in indexed.values()) != assessment["correct_facts"]
    ):
        raise ValueError("fact aggregate disagrees with evidence")
    return indexed


def load_snapshot(reports: Path, signatures: Path) -> Snapshot:
    inputs: list[dict[str, str]] = []
    report_paths = sorted(reports.glob("*.json"))
    signature_paths = sorted(signatures.glob("*.json"))
    if not report_paths or not signature_paths:
        raise ValueError("empty saved decision or signature capture directory")
    cells = {}
    evidence: dict[str, Any] = {}
    for path in report_paths:
        cell = read_json(path, inputs)
        if cell["cell"] in cells or cell["official_score"] is not False:
            raise ValueError("duplicate or non-experimental decision cell")
        cells[cell["cell"]] = cell
        evidence[cell["cell"]] = {"decision_report": inputs[-1]}
    diagnosed = report(report_paths)
    native_cells = {}
    for path in signature_paths:
        cell = read_json(path, inputs)
        if cell["cell"] in native_cells:
            raise ValueError("duplicate signature cell")
        if (
            cell["profile"] != "cpp-debug-signature-v1-diagnostic"
            or cell["official_score"] is not False
            or cell["abi_slots_verified"] is not False
            or cell["execution"] != "not measured"
        ):
            raise ValueError("unsupported signature evidence contract")
        native_cells[cell["cell"]] = cell
        if cell["cell"] not in evidence:
            raise ValueError("signature cell missing from decision capture")
        evidence[cell["cell"]].update(
            signature_report=inputs[-1], producer_files=cell["producer_sha256"]
        )
    if cells.keys() != native_cells.keys():
        raise ValueError("decision and signature capture cells differ")
    contexts, native_functions = {}, {}
    cases = {}
    for cell_id, cell in sorted(cells.items()):
        signature = native_cells[cell_id]
        if cell["original_binary_sha256"] != signature["binary_sha256"]:
            raise ValueError("decision and native image hashes differ")
        expected_model = "LLP64" if cell["platform"] == "windows" else "LP64"
        if signature["data_model"] != expected_model:
            raise ValueError("native data model differs from decision platform")
        functions = {}
        counts = {
            tool: Counter(
                requested=0, native_returns=0, perfect_returns=0, correct_facts=0, total_facts=0
            )
            for tool in TOOLS
        }
        for function in signature["functions"]:
            address = function["address"]
            if address in functions or set(function["tools"]) != set(TOOLS):
                raise ValueError("duplicate native function or missing producer")
            functions[address] = function
            native = function["native"]
            if native["address"] != address:
                raise ValueError("native signature address differs from requested entry")
            roles = native.get("roles", [])
            if len({r["identity"] for r in roles}) != len(roles):
                raise ValueError("duplicate native variable role identity")
            graph_payload = native.get("declared_return")
            expected_graph = saved_graph(graph_payload) if graph_payload else None
            expected = extract_type_facts(expected_graph) if expected_graph else None
            exclusion = native.get("return_exclusion") or native.get("exclusion")
            if expected is None and not exclusion:
                raise ValueError("unmeasurable return lacks an explicit oracle exclusion")
            if expected is not None and exclusion:
                raise ValueError("native return is both eligible and excluded")
            for tool in TOOLS:
                recovery = function["tools"][tool]
                counts[tool]["requested"] += 1
                if expected is None:
                    if recovery != {"status": "oracle_return_unavailable"}:
                        raise ValueError("recovery credit without native return oracle")
                    assessed = None
                else:
                    actual_payload = recovery["actual_return"]
                    actual_graph = saved_graph(actual_payload) if actual_payload else None
                    status = recovery["status"]
                    if status in {"correct", "type_mismatch"}:
                        if actual_graph is None or expected_graph is None:
                            raise ValueError("typed return lacks a graph")
                        equal = actual_graph.project("abi") == expected_graph.project("abi")
                        if equal != (status == "correct"):
                            raise ValueError("saved strict return verdict disagrees with graphs")
                    assessed = assess_recovery(
                        expected, extract_type_facts(actual_graph) if actual_graph else None, status
                    )
                    if canonical(assessed) != canonical(recovery["assessment"]):
                        raise ValueError("saved return assessment disagrees with native evidence")
                    counts[tool].update(
                        native_returns=1,
                        perfect_returns=status == "correct",
                        correct_facts=assessed["correct_facts"],
                        total_facts=assessed["total_facts"],
                    )
                unit = {
                    "identity": "declared_return",
                    "role": (
                        "void_return"
                        if expected_graph
                        and expected_graph.nodes[expected_graph.root].kind == "void"
                        else "nonvoid_return"
                    ),
                    "assessment": assessed,
                    "recovery": recovery,
                }
                cases[cell_id, tool, address, "returns"] = {
                    "oracle_exclusion": exclusion,
                    "units": [unit] if assessed else [],
                    "exact": (
                        {"declared_return": recovery["status"] == "correct"} if assessed else {}
                    ),
                }
        if len(functions) != cell["requested"]:
            raise ValueError("native requested count differs from decision capture")
        for tool in TOOLS:
            addresses = set(cell["tools"][tool]["function_addresses"].values())
            if addresses != functions.keys() or dict(counts[tool]) != signature["summary"][tool]:
                raise ValueError("native population or summary disagrees with decision capture")
        native_functions[cell_id] = functions
        contexts[cell_id] = {
            "binary_sha256": signature["binary_sha256"],
            "debug_sha256": sorted(signature["debug_sha256"].values()),
            "data_model": signature["data_model"],
            "project": cell["project"],
            "platform": cell["platform"],
            "optimization": cell["optimization"],
            "sources": sorted((s["member"], s["sha256"]) for s in cell["sources"]),
            "native": {str(a): f["native"] for a, f in sorted(functions.items())},
        }
    for row in diagnosed["rows"]:
        cell_id, tool, address = row["cell"], row["tool"], row["address"]
        function = native_functions[cell_id][address]
        roles = {r["identity"]: r["role"] for r in function["native"].get("roles", [])}
        units = []
        if row["status"] == "assessed":
            for variable in row["variables"]:
                facts(variable)
                units.append(
                    {
                        "identity": variable["identity"],
                        "role": roles.get(variable["identity"], "unknown"),
                        "assessment": variable,
                        "recovery": variable,
                    }
                )
            left = row["producer_validation"]
            right = function["tools"][tool].get("producer_validation")
            if left and right and left["text_sha256"] != right["text_sha256"]:
                raise ValueError("variable and return captures used different producer text")
        cases[cell_id, tool, address, "variables"] = {
            "oracle_exclusion": row.get("reason") if row["status"] != "assessed" else None,
            "units": units,
            "exact": (
                {"abi": row["strict_abi_value"] == 1, "source": row["strict_source_value"] == 1}
                if units
                else {}
            ),
            "diagnosis": row,
        }
    return Snapshot(contexts, cases, inputs, evidence)


def compare(before: Snapshot, after: Snapshot) -> dict[str, Any]:
    if canonical(before.contexts) != canonical(after.contexts):
        raise IncompatibleOracle("binary, debug, source, native roles/types or data model changed")
    if before.cases.keys() != after.cases.keys():
        raise IncompatibleOracle("requested function or diagnostic lane population changed")
    summaries: dict[str, Any] = defaultdict(Counter)
    changes, packets = [], []
    for key in sorted(before.cases):
        left, right = before.cases[key], after.cases[key]
        cell, tool, address, lane = key
        if left["oracle_exclusion"] != right["oracle_exclusion"]:
            raise IncompatibleOracle("oracle eligibility or exclusion reason changed")
        a = {u["identity"]: u for u in left["units"]}
        b = {u["identity"]: u for u in right["units"]}
        if len(a) != len(left["units"]) or len(b) != len(right["units"]) or a.keys() != b.keys():
            raise IncompatibleOracle("oracle variable multiplicity or identity changed")
        stats = summaries[f"{tool}/{lane}"]
        stats["requested_functions"] += 1
        stats["eligible_functions"] += bool(a)
        if left["exact"].keys() != right["exact"].keys():
            raise IncompatibleOracle("strict comparison dimensions changed")
        for dimension, exact in left["exact"].items():
            stats[f"{dimension}_exact_before"] += exact
            stats[f"{dimension}_exact_after"] += right["exact"][dimension]
            lost_exact = exact and not right["exact"][dimension]
            stats[f"{dimension}_lost_exact"] += lost_exact
            stats["lost_exact_matches"] += lost_exact
        transitions = []
        for identity, old in a.items():
            new = b[identity]
            x, y = old["assessment"], new["assessment"]
            old_facts, new_facts = facts(x), facts(y)
            if (
                old["role"] != new["role"]
                or {k: f["value"] for k, f in old_facts.items()}
                != {k: f["value"] for k, f in new_facts.items()}
                or canonical(x["oracle_fact_gaps"]) != canonical(y["oracle_fact_gaps"])
            ):
                raise IncompatibleOracle(
                    "oracle fact slots, values, gaps or variable roles changed"
                )
            group = summaries[f"{tool}/{lane}/{old['role']}"]
            verdict_key = "previous_verdict" if lane == "variables" else "status"
            exact_before = old["recovery"][verdict_key] == "correct"
            exact_after = new["recovery"][verdict_key] == "correct"
            for target in (stats, group):
                target["units"] += 1
                target["total_facts"] += len(old_facts)
                target["correct_before"] += x["correct_facts"]
                target["correct_after"] += y["correct_facts"]
                target["exact_units_before"] += exact_before
                target["exact_units_after"] += exact_after
                target["lost_exact_units"] += exact_before and not exact_after
            gains, losses = [], []
            for slot, old_fact in old_facts.items():
                new_fact = new_facts[slot]
                recovered = old_fact["status"] != "correct" and new_fact["status"] == "correct"
                lost = old_fact["status"] == "correct" and new_fact["status"] != "correct"
                evidence = {
                    "slot": slot,
                    "expected": old_fact["value"],
                    "before": old_fact,
                    "after": new_fact,
                }
                if recovered:
                    gains.append(evidence)
                if lost:
                    losses.append(evidence)
            for target in (stats, group):
                target["gained_facts"] += len(gains)
                target["lost_facts"] += len(losses)
            if canonical(old["recovery"]) != canonical(new["recovery"]):
                transitions.append(
                    {
                        "identity": identity,
                        "role": old["role"],
                        "gained": gains,
                        "lost": losses,
                        "before": old["recovery"],
                        "after": new["recovery"],
                    }
                )
        header = {"cell": cell, "tool": tool, "address": address, "lane": lane}
        if transitions or left["exact"] != right["exact"]:
            changes.append(
                {
                    **header,
                    "transitions": transitions,
                    "exact_before": left["exact"],
                    "exact_after": right["exact"],
                }
            )
        if (
            right["oracle_exclusion"] is not None
            or any(not exact for exact in right["exact"].values())
            or any(f["status"] != "correct" for u in b.values() for f in u["assessment"]["facts"])
        ):
            if right["oracle_exclusion"] is not None and tool != TOOLS[0]:
                continue
            context = {k: v for k, v in after.contexts[cell].items() if k != "native"}
            context["native_function"] = after.contexts[cell]["native"][str(address)]
            packets.append(
                {
                    **header,
                    "id": hashlib.sha256(canonical(key).encode()).hexdigest()[:24],
                    "oracle_context": context,
                    "applies_to": list(TOOLS) if right["oracle_exclusion"] else [tool],
                    "baseline_evidence": before.evidence[cell],
                    "candidate_evidence": after.evidence[cell],
                    "before": left,
                    "after": right,
                }
            )
    regression = any(
        s["lost_facts"] or s["lost_exact_matches"] or s["lost_exact_units"]
        for s in summaries.values()
    )
    measurable = any(s["total_facts"] for s in summaries.values())
    return {
        "profile": PROFILE,
        "official_score": False,
        "comparable": True,
        "gate": (
            "regression"
            if regression
            else "no_observed_regression" if measurable else "unmeasurable"
        ),
        "scope": "saved declared-type evidence; no execution or physical ABI validation",
        "summary": dict(summaries),
        "changes": changes,
        "packets": packets,
    }


def markdown(result: dict[str, Any]) -> str:
    lines = [
        "# C++ diagnostic comparison (experimental)",
        "",
        "Gate: " + result["gate"],
        "",
        "| Tool / lane / role | Facts before | Facts after | Gained | Lost |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, s in sorted(result["summary"].items()):
        if not s["total_facts"]:
            lines.append(f"| {name} | unmeasurable | unmeasurable | — | — |")
            continue
        lines.append(
            f"| {name} | {s['correct_before']}/{s['total_facts']} | "
            f"{s['correct_after']}/{s['total_facts']} | "
            f"{s['gained_facts']} | {s['lost_facts']} |"
        )
    lines += [
        "",
        "## Strict function agreement (separate populations)",
        "",
        "| Tool / lane | Eligible / requested | Strict dimension | Before | After | Lost |",
        "| --- | ---: | --- | ---: | ---: | ---: |",
    ]
    for name, s in sorted(result["summary"].items()):
        if name.count("/") != 1:
            continue
        dimensions = ("abi", "source") if name.endswith("/variables") else ("declared_return",)
        for dimension in dimensions:
            if not s["eligible_functions"]:
                lines.append(
                    f"| {name} | 0/{s['requested_functions']} | "
                    f"{dimension} | unmeasurable | unmeasurable | — |"
                )
                continue
            lines.append(
                f"| {name} | {s['eligible_functions']}/{s['requested_functions']} | "
                f"{dimension} | {s[dimension + '_exact_before']} | "
                f"{s[dimension + '_exact_after']} | {s[dimension + '_lost_exact']} |"
            )
    lines += [
        "",
        "## Exact units by role (ABI variable or declared return)",
        "",
        "| Tool / lane / role | Units | Exact before | Exact after | Lost |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, s in sorted(result["summary"].items()):
        if name.count("/") == 2:
            lines.append(
                f"| {name} | {s['units']} | {s['exact_units_before']} | "
                f"{s['exact_units_after']} | {s['lost_exact_units']} |"
            )
    lines += [
        "",
        "Each lane retains its own population; rows are not summed into a ranking.",
        "Zero-fact populations are unmeasurable. Return void/nonvoid roles stay separate.",
        "Packets are local evidence references, not standalone execution reproducers.",
        "No observed regression does not establish semantic correctness or release readiness.",
    ]
    return "\n".join(lines) + "\n"


def investigation_queue(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, Any] = {}
    for packet in packets:
        case = packet["after"]
        excluded = case["oracle_exclusion"] is not None
        tasks = (
            [("function", "oracle_insufficient", case["oracle_exclusion"])]
            if excluded
            else [
                (u["role"], u["assessment"]["category"], u["assessment"]["reason"])
                for u in case["units"]
                if u["assessment"]["category"] != "correct"
            ]
        )
        if not tasks:
            tasks = [("function", "strict_disagreement", "outside_bounded_fact_contract")]
        for role, category, reason in tasks:
            descriptor = {
                "tools": packet["applies_to"],
                "lane": packet["lane"],
                "role": role,
                "category": category,
                "reason": reason,
                "unit": (
                    "function"
                    if role == "function"
                    else "variable" if packet["lane"] == "variables" else "return"
                ),
            }
            group_id = hashlib.sha256(canonical(descriptor).encode()).hexdigest()[:24]
            group = groups.setdefault(
                group_id,
                {
                    **descriptor,
                    "id": group_id,
                    "occurrences": 0,
                    "packet_ids": set(),
                    "functions": set(),
                    "projects": set(),
                    "optimizations": set(),
                },
            )
            group["occurrences"] += 1
            group["packet_ids"].add(packet["id"])
            group["functions"].add((packet["cell"], packet["address"]))
            group["projects"].add(packet["oracle_context"]["project"])
            group["optimizations"].add(packet["oracle_context"]["optimization"])
    return [
        {
            **{
                k: v
                for k, v in group.items()
                if k not in {"functions", "packet_ids", "projects", "optimizations"}
            },
            "function_count": len(group["functions"]),
            "packet_ids": sorted(group["packet_ids"]),
            "projects": sorted(group["projects"]),
            "optimizations": sorted(group["optimizations"]),
        }
        for _, group in sorted(groups.items())
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "baseline-reports",
        "candidate-reports",
        "baseline-signatures",
        "candidate-signatures",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New, non-existing directory")
    parser.add_argument(
        "--verify-producer-files",
        action="store_true",
        help="Rehash the original files referenced by both saved signature captures",
    )
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output directory must not already exist")
    before = load_snapshot(args.baseline_reports, args.baseline_signatures)
    after = load_snapshot(args.candidate_reports, args.candidate_signatures)
    try:
        result = compare(before, after)
    except IncompatibleOracle as exc:
        result = {
            "profile": PROFILE,
            "official_score": False,
            "comparable": False,
            "gate": "incompatible_oracle",
            "reason": str(exc),
        }
    for entry in before.inputs + after.inputs:
        if hashlib.sha256(Path(entry["path"]).read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("input evidence changed during comparison")
    verified_producers = set()
    if args.verify_producer_files:
        for snapshot in (before, after):
            for evidence in snapshot.evidence.values():
                for path, digest in evidence["producer_files"].items():
                    if (path, digest) in verified_producers:
                        continue
                    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
                        raise ValueError("original producer file differs from saved capture")
                    verified_producers.add((path, digest))
    result["inputs"] = {"baseline": before.inputs, "candidate": after.inputs}
    result["producer_files_verified"] = (
        len(verified_producers) if args.verify_producer_files else None
    )
    packets = result.pop("packets", [])
    result["investigation_packets"] = len(packets)
    queue = investigation_queue(packets)
    result["investigation_groups"] = len(queue)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "comparison.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    if result["comparable"]:
        (args.output / "comparison.md").write_text(markdown(result))
    if packets:
        (args.output / "queue.json").write_text(
            json.dumps(
                {
                    "profile": PROFILE,
                    "official_score": False,
                    "groups": queue,
                    "bounds": "Investigation categories; defect ownership and ranks unestablished",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        (args.output / "packets").mkdir()
        for packet in packets:
            (args.output / "packets" / (packet["id"] + ".json")).write_text(
                json.dumps(packet, indent=2, sort_keys=True) + "\n"
            )
    print(json.dumps({"gate": result["gate"], "packets": len(packets)}))
    raise SystemExit(
        0
        if result["gate"] == "no_observed_regression"
        else (
            1
            if result["gate"] == "regression"
            else 2 if result["gate"] == "incompatible_oracle" else 3
        )
    )


if __name__ == "__main__":
    main()
