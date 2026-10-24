#!/usr/bin/env python3
"""Freeze real native entries and capture bounded, restartable producer shards.

This is a local experimental transport lane, not a default metric or leaderboard.
Debug/source evidence is used only to freeze the requested evaluator population.
Workers receive stripped inputs and anonymous entry addresses.
"""

from __future__ import annotations

import argparse
import fcntl
import inspect
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from decbench.utils.cpp_scale_store import ScaleStore, address, canonical, digest, records

TOOLS = ("fission", "kuna", "ghidra", "angr")


def initialize(args: argparse.Namespace) -> None:
    if args.database.exists():
        raise ValueError("inventory output must be new")
    dataset = args.dataset.resolve()
    manifest_path = dataset / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    checksums = {r["path"]: r["sha256"] for r in manifest["files"]}
    sample = json.loads(args.sample.read_bytes())
    cells = [r for r in sample["cells"] if not args.cells or r["id"] in args.cells]
    if not cells or (args.cells and {r["id"] for r in cells} != set(args.cells)):
        raise ValueError("unknown or empty cell selection")
    args.database.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.database.with_suffix(".building.sqlite")
    if temporary.exists():
        raise ValueError("unfinished inventory build exists; inspect it before retrying")
    store = ScaleStore(temporary)
    try:
        store.bind(
            "inventory",
            {
                "schema": 1,
                "dataset": str(dataset),
                "manifest_sha256": digest(manifest_path),
                "sample_sha256": digest(args.sample),
                "cells": [r["id"] for r in cells],
                "scope": (
                    "packaged native CU/object inventory; "
                    "header/dependency entries may be included"
                ),
                "oracle_qualified": False,
            },
        )
        for cell in cells:
            native, stripped = (dataset / cell[k] for k in ("binary", "stripped"))
            manifest_cell = next(r for r in manifest["records"] if r["binary"] == cell["binary"])
            for key, value in manifest_cell.items():
                if key in cell and cell[key] != value:
                    raise ValueError("sample and manifest disagree: " + key)
            for path, expected in (
                (native, cell["binary_sha256"]),
                (stripped, cell["stripped_sha256"]),
            ):
                if digest(path) != expected:
                    raise ValueError("image hash mismatch: " + str(path))
            if (
                not cell.get("debug_removed", cell.get("debug_directory_removed", False))
                or not cell["code_sections_equal"]
            ):
                raise ValueError("unqualified producer input transport")
            from decbench.utils import binfmt

            if binfmt.executable_regions(native) != binfmt.executable_regions(stripped):
                raise ValueError("original and stripped code differ")
            index = native.parent / (
                "function-identities.json"
                if cell["platform"] == "windows"
                else "dwarf-functions.json"
            )
            if digest(index) != checksums.get(str(index.relative_to(dataset))):
                raise ValueError("native inventory hash differs from manifest")
            meta = {k: v for k, v in cell.items() if k != "rows"}
            meta.update(
                original=str(native), stripped_path=str(stripped), native_index_sha256=digest(index)
            )
            with store.db:
                store.db.execute("INSERT INTO cells VALUES (?,?)", (cell["id"], canonical(meta)))
                with index.open() as stream:
                    for row in records(stream):
                        if row["binary_sha256"] != cell["binary_sha256"]:
                            raise ValueError("native entry belongs to another image")
                        if cell["platform"] == "windows":
                            if not row["project_owned"]:
                                continue
                            value, name = row["va"], row["leaf_name"]
                        else:
                            value, name = row["address"], row["name"]
                        key = address(value)
                        previous = store.db.execute(
                            "SELECT aliases FROM targets WHERE cell=? AND address=?",
                            (cell["id"], key),
                        ).fetchone()
                        aliases = sorted(set(json.loads(previous[0]) if previous else []) | {name})
                        store.db.execute(
                            "INSERT INTO targets VALUES (?,?,?,?) ON CONFLICT(cell,address) "
                            "DO UPDATE SET name=excluded.name,aliases=excluded.aliases",
                            (cell["id"], key, aliases[0], canonical(aliases)),
                        )
                count = store.db.execute(
                    "SELECT count(*) FROM targets WHERE cell=?", (cell["id"],)
                ).fetchone()[0]
                if count != cell["available_unique_addresses"]:
                    raise ValueError("native inventory count differs")
            print(canonical({"cell": cell["id"], "requested": count}), flush=True)
        store.schedule(list(args.tools), args.chunk_size)
        store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        store.close()
    temporary.replace(args.database)


def worker(request_path: Path, output: Path) -> None:
    from run_cpp_whole_binary import TOOLS as BACKENDS

    from decbench.decompilers.base import DecompilerConfig

    request = json.loads(request_path.read_bytes())
    tool = request["tool"]
    backend = BACKENDS[tool](DecompilerConfig(**request["config"]))
    original_input = Path(request["input"])
    isolated = request_path.parent / "isolated-input"
    isolated.mkdir()
    binary = isolated / original_input.name
    shutil.copyfile(original_input, binary)
    if digest(binary) != request["input_sha256"]:
        raise ValueError("isolated stripped input changed")
    functions = [(f"sub_{a:x}", a) for a in request["addresses"]]
    if not backend.is_available():
        raise RuntimeError("producer unavailable: " + tool)
    if tool == "kuna":
        from decbench.decompilers.raw.kuna_raw import RawKunaDecompiler

        assert isinstance(backend, RawKunaDecompiler)
        raw = output.with_suffix(".native.json")
        command = backend._build_command(binary)
        for _, entry in functions:
            command.extend(("--addr", hex(entry)))
        with raw.open("wb") as stream:
            status = subprocess.call(command, stdout=stream)
        if status:
            raise RuntimeError("Kuna nonzero exit: " + str(status))
        with raw.open() as source, output.open("w") as destination:
            for record in records(source):
                entry = record.get("address")
                address(entry)
                function = backend._build_function(
                    record, str(record.get("name") or f"sub_{entry:x}"), entry
                )
                if function is None:
                    value = {
                        "name": f"sub_{entry:x}",
                        "address": entry,
                        "decompiled_code": "",
                        "metadata": {"producer_error": record.get("error")},
                    }
                else:
                    value = function.model_dump(mode="json")
                destination.write(canonical(value) + "\n")
        raw.unlink()
    else:
        result = backend.decompile_binary(binary, functions=functions)
        if result.decompiler.extra.get("error") or result.decompiler.timeout_occurred:
            raise RuntimeError(
                "producer failed: " + canonical(result.decompiler.model_dump(mode="json"))
            )
        with output.open("w") as destination:
            for function in result.functions.values():
                destination.write(canonical(function.model_dump(mode="json")) + "\n")


def producer_contract(args: argparse.Namespace) -> dict[str, Any]:
    from run_cpp_whole_binary import TOOLS as BACKENDS

    from decbench.decompilers.base import DecompilerConfig

    backend = BACKENDS[args.tool](
        DecompilerConfig(
            function_timeout_seconds=args.function_timeout,
            binary_timeout_seconds=args.batch_timeout,
        )
    )
    if not backend.is_available():
        raise RuntimeError("producer unavailable: " + args.tool)
    root = Path(inspect.getfile(DecompilerConfig)).parents[1]
    envkeys = (
        "FISSION_BIN",
        "KUNA_BIN",
        "FISSION_RESOURCE_ROOT",
        "FISSION_WORKING_DIR",
        "GHIDRA_INSTALL_DIR",
        "JAVA_HOME",
        "_JAVA_OPTIONS",
        "DECBENCH_KUNA_MODE",
        "DECBENCH_KUNA_MAX_FN_SECONDS",
    )
    environment = {k: os.environ.get(k) for k in envkeys}
    executable_key = {"fission": "FISSION_BIN", "kuna": "KUNA_BIN"}.get(args.tool)
    executable = None
    if executable_key:
        candidate = environment[executable_key] or shutil.which(
            "kuna" if args.tool == "kuna" else "fission_cli"
        )
        if not candidate:
            raise ValueError("producer executable not resolved")
        executable = {"path": str(Path(candidate).resolve()), "sha256": digest(Path(candidate))}
        os.environ[executable_key] = executable["path"]
        environment[executable_key] = executable["path"]
    return {
        "version": backend.get_version(),
        "tool": args.tool,
        "executable": executable,
        "config": backend.config.model_dump(),
        "environment": environment,
        "python": sys.version,
        "sources": {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob("*.py"))},
        "driver": digest(Path(__file__)),
        "whole_binary_driver": digest(Path(__file__).with_name("run_cpp_whole_binary.py")),
    }


def log_tail(path: Path) -> str:
    with path.open("rb") as stream:
        stream.seek(max(0, path.stat().st_size - 16384))
        return stream.read(16384).decode("utf-8", "replace")


def run(args: argparse.Namespace) -> None:
    from run_cpp_whole_binary import stop_worker

    if not args.database.is_file():
        raise ValueError("scale database does not exist")
    with args.database.with_suffix(".lock").open("a") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = ScaleStore(args.database)
        try:
            contract = producer_contract(args)
            store.bind("producer:" + args.tool, contract)
            inventory = json.loads(
                store.db.execute("SELECT value FROM contract WHERE name='inventory'").fetchone()[0]
            )
            if digest(Path(inventory["dataset"]) / "manifest.json") != inventory["manifest_sha256"]:
                raise ValueError("dataset manifest changed")
            for row in store.db.execute("SELECT metadata FROM cells"):
                cell = json.loads(row[0])
                if digest(Path(cell["stripped_path"])) != cell["stripped_sha256"]:
                    raise ValueError("stripped input changed")
            recovered = store.recover(args.tool)
            print(canonical({"recovered_shards": recovered}), flush=True)
            started = time.monotonic()
            completed = 0
            while not args.max_batches or completed < args.max_batches:
                if shutil.disk_usage(args.database.parent).free < args.reserve_gib * 2**30:
                    raise RuntimeError("disk reserve reached; incomplete population retained")
                job = store.claim(args.tool)
                if job is None:
                    break
                cell = json.loads(
                    store.db.execute(
                        "SELECT metadata FROM cells WHERE id=?", (job["cell"],)
                    ).fetchone()[0]
                )
                requested = store.requested(job)
                batch_start = time.monotonic()
                with tempfile.TemporaryDirectory(
                    prefix="cpp-shard-", dir=args.database.parent
                ) as directory:
                    directory_path = Path(directory)
                    request, output = (
                        directory_path / "request.json",
                        directory_path / "output.jsonl",
                    )
                    request.write_text(
                        canonical(
                            {
                                "tool": args.tool,
                                "config": contract["config"],
                                "input": cell["stripped_path"],
                                "input_sha256": cell["stripped_sha256"],
                                "addresses": [a for _, a in requested],
                            }
                        )
                    )
                    log = args.database.parent / f"{args.database.stem}-{args.tool}-last.log"
                    command = [
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "worker",
                        str(request),
                        str(output),
                    ]
                    with log.open("wb") as destination:
                        process = subprocess.Popen(
                            command, stdout=destination, stderr=destination, start_new_session=True
                        )
                        failure = None
                        try:
                            while process.poll() is None:
                                if time.monotonic() - batch_start > args.batch_timeout:
                                    failure = "timeout"
                                    break
                                if (
                                    shutil.disk_usage(args.database.parent).free
                                    < args.reserve_gib * 2**30
                                ):
                                    raise RuntimeError("disk reserve reached")
                                if (
                                    sum(p.stat().st_size for p in directory_path.iterdir())
                                    + log.stat().st_size
                                    > args.max_spool_mib * 2**20
                                ):
                                    failure = "output_limit"
                                    break
                                time.sleep(0.5)
                        finally:
                            stop_worker(process)
                            process.wait()
                    if process.returncode and failure is None:
                        failure = "producer_error"
                    evidence = {
                        "seconds": time.monotonic() - batch_start,
                        "returncode": process.returncode,
                        "failure": failure,
                        "log_sha256": digest(log),
                        "log_tail": log_tail(log),
                        "missing_outcome": failure or "missing",
                    }
                    if failure:
                        store.finish(job, iter(()), evidence)
                    else:
                        with output.open() as stream:
                            store.finish(job, (json.loads(line) for line in stream), evidence)
                    completed += 1
                    print(
                        canonical(
                            {
                                "job": job["id"],
                                "cell": job["cell"],
                                "tool": args.tool,
                                "expected": job["expected"],
                                **evidence,
                            }
                        ),
                        flush=True,
                    )
            print(
                canonical({"elapsed_seconds": time.monotonic() - started, **store.summary()}),
                flush=True,
            )
        finally:
            store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--dataset", type=Path, required=True)
    init.add_argument("--sample", type=Path, required=True)
    init.add_argument("--database", type=Path, required=True)
    init.add_argument("--cells", nargs="*")
    init.add_argument("--tools", nargs="+", choices=TOOLS, default=list(TOOLS))
    init.add_argument("--chunk-size", type=int, default=128)
    capture = sub.add_parser("capture")
    capture.add_argument("--database", type=Path, required=True)
    capture.add_argument("--tool", choices=TOOLS, required=True)
    capture.add_argument("--function-timeout", type=int, default=30)
    capture.add_argument("--batch-timeout", type=int, default=600)
    capture.add_argument("--max-batches", type=int, default=0)
    capture.add_argument("--reserve-gib", type=float, default=8)
    capture.add_argument("--max-spool-mib", type=int, default=512)
    status = sub.add_parser("status")
    status.add_argument("--database", type=Path, required=True)
    task = sub.add_parser("worker")
    task.add_argument("request", type=Path)
    task.add_argument("output", type=Path)
    args = parser.parse_args()

    def interrupted(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt("controller interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    if args.command == "init":
        initialize(args)
    elif args.command == "capture":
        if (
            min(args.function_timeout, args.batch_timeout, args.reserve_gib, args.max_spool_mib)
            <= 0
            or args.max_batches < 0
        ):
            parser.error("resource limits must be positive")
        run(args)
    elif args.command == "status":
        if not args.database.is_file():
            parser.error("scale database does not exist")
        store = ScaleStore(args.database)
        try:
            print(json.dumps(store.summary(), indent=2))
        finally:
            store.close()
    else:
        worker(args.request, args.output)


if __name__ == "__main__":
    main()
