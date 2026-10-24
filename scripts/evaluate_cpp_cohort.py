#!/usr/bin/env python3
"""Recompute existing C++ diagnostics for a frozen multi-image producer cohort.

Source and native debug remain evaluator-only. Workers execute no corpus or
recovered program. No default metric or published leaderboard is changed.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

TOOLS = ("fission", "kuna", "ghidra", "angr")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def evaluate(plan_path: Path, dataset: Path) -> dict[str, Any]:
    from evaluate_cpp_native_facts import _load

    from decbench.metrics.base import MetricConfig
    from decbench.metrics.cpp_type_match import CppOracleContext, CppTypeMatchMetric
    from decbench.models.decompilation import DecompilationResult
    from decbench.pipeline.cpp_ged import evaluate_cpp_ged
    from decbench.utils import binfmt
    from decbench.utils.cfg_identity import (
        SourceCfgIndex,
        native_sources,
        origin_source,
        source_unit_matches,
    )

    plan = json.loads(plan_path.read_bytes())
    cell = plan["cell"]
    binary, stripped = Path(plan["original"]), Path(plan["input"])
    for path, key in ((binary, "binary_sha256"), (stripped, "stripped_sha256")):
        if digest(path) != cell[key]:
            raise ValueError("frozen image differs")
    if binfmt.executable_regions(binary) != binfmt.executable_regions(stripped):
        raise ValueError("stripped and original executable regions differ")
    evidence = dict(plan.get("input_evidence_sha256", {}))
    for path, expected in evidence.items():
        if digest(Path(path)) != expected:
            raise ValueError("capture evidence changed: " + path)
    requested = [(row["name"], row["address"]) for row in plan["functions"]]
    addresses = {address for _, address in requested}
    if len(addresses) != len(requested) or any(address < 0 for address in addresses):
        raise ValueError("ambiguous requested population")
    for companion in binfmt.native_debug_paths(binary):
        if companion.is_file():
            evidence[str(companion)] = digest(companion)
    context = CppOracleContext(binary)
    native = native_sources(binary, addresses)
    database = binary.parent / "compile_commands.json"
    if database.exists():
        evidence[str(database)] = digest(database)
        native = native.with_compilation_database(database)
    index = SourceCfgIndex()
    archive = binary.parent / "preprocessed.tar.gz"
    all_modes = not archive.exists()
    if all_modes:
        archive = dataset / "sources" / cell["project"] / "preprocessed-all-modes.tar.gz"
    sources = []
    if archive.exists():
        evidence[str(archive)] = digest(archive)
        with tarfile.open(archive, "r|gz") as stream:
            for member in stream:
                if not member.isfile() or Path(member.name).suffix not in (".i", ".ii"):
                    continue
                if all_modes and not member.name.startswith(cell["optimization"] + "/"):
                    continue
                content = stream.extractfile(member)
                if content is None:
                    raise ValueError("unreadable TU")
                data = content.read()
                text = data.decode("utf-8", "replace")
                source = origin_source("\n".join(text.splitlines()[:64]))
                if source.primary is None:
                    source = origin_source(text)
                if not any(
                    source_unit_matches(source.primary, record)
                    for records in native.values()
                    for record in records
                ):
                    continue
                index.add(
                    text,
                    member.name,
                    native_records=tuple(
                        records[0] for records in native.values() if len(records) == 1
                    ),
                )
                sources.append(
                    {
                        "member": member.name,
                        "primary": source.primary,
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
    print(cell["id"], "prepared", len(sources), "TUs", flush=True)
    output = {
        "cell": cell["id"],
        "project": cell["project"],
        "platform": cell["platform"],
        "optimization": cell["optimization"],
        "requested": len(requested),
        "original_binary_sha256": digest(binary),
        "stripped_binary_sha256": digest(stripped),
        "sources": sources,
        "source_inputs": index.inputs,
        "tools": {},
        "official_score": False,
        "capture": plan.get("capture", "frozen producer artifact"),
        "requested_functions": plan["functions"],
    }
    for tool in TOOLS:
        path = plan_path.parent / "producers" / tool / "result.json"
        by_address = _load(path, plan.get("producer_sha256", {}).get(tool), evidence)
        if set(by_address) != addresses:
            raise ValueError("producer capture does not account for every requested entry")
        result = DecompilationResult.model_validate_json(path.read_text())
        version = result.decompiler.model_dump(mode="json")
        result.binary_path, result.binary_name, result.functions = binary, binary.stem, {}
        for name, address in requested:
            function = by_address[address].model_copy(deep=True)
            function.metadata["measurement_producer_display_name"] = function.name
            oracle = context.pdb.at_address(address) if context.pdb else None
            function.name = oracle.name if oracle else name
            result.add_function(function)
        if len(result.functions) != len(requested):
            raise ValueError("storage keys collapsed requested population")
        profiles = {}
        for view in ("source", "abi"):
            metric = CppTypeMatchMetric(
                MetricConfig(
                    use_cache=False,
                    extra_options={
                        "view": view,
                        "data_model": "LLP64" if cell["platform"] == "windows" else "LP64",
                    },
                )
            )
            profiles[view] = metric.compute_for_binary(
                result,
                oracle_context=context,
                requested_functions=requested,
            ).model_dump(mode="json")
        ged = evaluate_cpp_ged(
            result, source_index=index, native_index=native, requested_functions=requested
        ).model_dump(mode="json")
        output["tools"][tool] = {
            "profiles": profiles,
            "ged": ged,
            "function_addresses": {key: f.address for key, f in result.functions.items()},
            "nonempty": sum(bool(f.decompiled_code.strip()) for f in result.functions.values()),
            "producer": version,
            "producer_sha256": digest(path),
        }
        print(
            cell["id"],
            tool,
            "GED",
            ged["metric"]["perfect_count"],
            "of",
            ged["source_eligible"],
            "types",
            profiles["abi"]["perfect_count"],
            "of",
            len(profiles["abi"]["function_results"]),
            flush=True,
        )
    context.validate(binary)
    native.validate(binary)
    for path, expected in evidence.items():
        if digest(Path(path)) != expected:
            raise ValueError("capture/oracle evidence changed during evaluation")
    output["evidence_sha256"] = evidence
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plans-root", type=Path)
    parser.add_argument(
        "--cell", action="append", help="Explicit pilot cells; omitted means the complete plan pool"
    )
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--parser-library", type=Path)
    parser.add_argument("--dataset-revision")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--worker-plan", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_plan:
        atomic(args.output, evaluate(args.worker_plan, args.dataset))
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)
    if not args.plans_root or not args.parser_library or not args.dataset_revision:
        parser.error("plans-root, parser-library and dataset-revision are required")
    if args.jobs < 1 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("positive jobs and timeout required")
    plans = sorted(args.plans_root.glob("*/plan.json"))
    if args.cell:
        wanted = set(args.cell)
        plans = [p for p in plans if json.loads(p.read_bytes())["cell"]["id"] in wanted]
        if {json.loads(p.read_bytes())["cell"]["id"] for p in plans} != wanted:
            raise ValueError("unknown pilot cell")
    if not plans:
        raise ValueError("empty cohort")
    import rust_joern

    from decbench.metrics import cpp_type_match

    owners = Path(cpp_type_match.__file__).parents[1]
    contract = {
        "schema": "cpp-cohort-evaluation-v1",
        "official_score": False,
        "dataset_revision": args.dataset_revision,
        "dataset": str(args.dataset.resolve()),
        "plans": {str(path.resolve()): digest(path) for path in plans},
        "owners": {str(path): digest(path) for path in sorted(owners.rglob("*.py"))},
        "scripts": {
            str(path): digest(path) for path in sorted(Path(__file__).parent.glob("*cpp*.py"))
        },
        "wrapper": {str(Path(rust_joern.__file__)): digest(Path(rust_joern.__file__))},
        "parser_sha256": digest(args.parser_library),
        "python": sys.version,
        "timeout": args.timeout,
        "metric_cache": False,
    }
    args.output.mkdir(parents=True, exist_ok=args.resume)
    lock = (args.output / ".lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    contract_path = args.output / "contract.json"
    if contract_path.exists() and json.loads(contract_path.read_bytes()) != contract:
        raise ValueError("evaluation resume contract changed")
    atomic(contract_path, contract)
    library = args.output.resolve() / "backend" / args.parser_library.name
    library.parent.mkdir(exist_ok=True)
    if library.exists() and digest(library) != contract["parser_sha256"]:
        raise ValueError("frozen parser changed")
    if not library.exists():
        library.write_bytes(args.parser_library.read_bytes())
    cells = [json.loads(path.read_bytes())["cell"]["id"] for path in plans]
    if len(set(cells)) != len(cells) or any(
        not re.fullmatch(r"[A-Za-z0-9_-]+", cell) for cell in cells
    ):
        raise ValueError("duplicate cell")
    records = {}
    for cell in cells:
        target = args.output / "cells" / (cell + ".json")
        checkpoint = args.output / "checkpoints" / (cell + ".json")
        if checkpoint.exists():
            saved = json.loads(checkpoint.read_bytes())
            if saved["contract_sha256"] != digest(contract_path) or (
                saved["status"] == "complete" and digest(target) != saved["result_sha256"]
            ):
                raise ValueError("completed checkpoint changed")
            records[cell] = saved
    pending = [(path, cell) for path, cell in zip(plans, cells, strict=True) if cell not in records]

    stop = threading.Event()

    def one(item: tuple[Path, str]) -> tuple[str, dict[str, Any]]:
        path, cell = item
        for group in ("plans", "owners", "scripts", "wrapper"):
            if any(digest(Path(p)) != value for p, value in contract[group].items()):
                raise ValueError("immutable evaluation source changed")
        log = args.output / (cell + ".log")
        target = args.output / "cells" / (cell + ".json")
        command = [
            sys.executable,
            "-X",
            "faulthandler",
            str(Path(__file__).resolve()),
            "--worker-plan",
            str(path.resolve()),
            "--dataset",
            str(args.dataset.resolve()),
            "--output",
            str(target.resolve()),
        ]
        started = time.monotonic()
        with log.open("wb") as stream:
            child = subprocess.Popen(
                command,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env={
                    **os.environ,
                    "DECBENCH_NO_CACHE": "1",
                    "RUST_JOERN_LIBRARY": str(library),
                    "RAYON_NUM_THREADS": "1",
                },
            )
            while True:
                if stop.is_set() or time.monotonic() - started > args.timeout:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)
                    code = child.wait()
                    if stop.is_set():
                        raise RuntimeError(
                            "evaluation interrupted; unfinished cell remains pending"
                        )
                    status = "evaluator_timeout"
                    break
                try:
                    code = child.wait(timeout=1)
                    status = "complete" if code == 0 else "evaluator_error"
                    break
                except subprocess.TimeoutExpired:
                    continue
        record = {
            "cell": cell,
            "status": status,
            "returncode": code,
            "seconds": time.monotonic() - started,
            "log_sha256": digest(log),
            "contract_sha256": digest(contract_path),
        }
        if status == "complete":
            record["result_sha256"] = digest(target)
        atomic(args.output / "checkpoints" / (cell + ".json"), record)
        return cell, record

    pool = ThreadPoolExecutor(max_workers=args.jobs)
    try:
        for offset in range(0, len(pending), args.jobs):
            for cell, record in pool.map(one, pending[offset : offset + args.jobs]):
                records[cell] = record
                print(cell, record["status"], round(record["seconds"], 1), flush=True)
    except BaseException:
        stop.set()
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    atomic(
        args.output / "completion.json",
        {
            "contract_sha256": digest(contract_path),
            "requested_cells": len(cells),
            "rows": [records[cell] for cell in cells],
        },
    )
    if any(record["status"] != "complete" for record in records.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
