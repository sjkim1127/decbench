#!/usr/bin/env python3
"""Freeze owned native entries, then checkpoint address-guided stripped producers."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import inspect
import json
import os
import pickle
import signal
import subprocess
import sys
import tarfile
import time
import traceback
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any

from decbench.decompilers.base import DecompilerConfig
from decbench.decompilers.raw.angr_raw import RawAngrDecompiler
from decbench.decompilers.raw.fission_raw import RawFissionDecompiler
from decbench.decompilers.raw.ghidra_raw import RawGhidraDecompiler
from decbench.decompilers.raw.kuna_raw import RawKunaDecompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils import binfmt
from decbench.utils.cfg_identity import native_sources
from decbench.utils.function_identity import dwarf_function_identities

TOOLS: dict[
    str,
    type[RawFissionDecompiler]
    | type[RawKunaDecompiler]
    | type[RawGhidraDecompiler]
    | type[RawAngrDecompiler],
] = {
    "fission": RawFissionDecompiler,
    "kuna": RawKunaDecompiler,
    "ghidra": RawGhidraDecompiler,
    "angr": RawAngrDecompiler,
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def plan(args: argparse.Namespace) -> None:
    output = args.output
    if output.exists():
        raise ValueError("plan directory must be new")
    sample = json.loads(args.sample.read_text())
    cell = next(c for c in sample["cells"] if c["id"] == args.cell)
    original, stripped = (args.dataset / cell[key] for key in ("binary", "stripped"))
    if digest(original) != cell["binary_sha256"] or digest(stripped) != cell["stripped_sha256"]:
        raise ValueError("frozen image hash mismatch")
    if binfmt.executable_regions(original) != binfmt.executable_regions(stripped):
        raise ValueError("stripped code differs from original image")
    if binfmt.dwarf_info(stripped) is not None:
        raise ValueError("producer input still contains debug information")
    with tarfile.open(args.source_archive) as archive:
        owned_files = {m.name.removeprefix("./") for m in archive if m.isfile()}
    root = PurePosixPath(args.owner_root)
    identities = dwarf_function_identities(original)
    native = native_sources(original, {i.address for i in identities})
    included, excluded = [], []
    for identity in identities:
        rows = native.get(identity.address, [])
        owned = []
        for row in rows:
            for location in row.locations:
                path = PurePosixPath(location.path)
                if not path.is_relative_to(root):
                    continue
                relative = str(path.relative_to(root))
                if relative in owned_files and not any(
                    relative == p or relative.startswith(p.rstrip("/") + "/")
                    for p in args.exclude_prefix
                ):
                    owned.append(relative)
        record = {
            "address": identity.address,
            "name": identity.name,
            "native": [asdict(r) for r in rows],
        }
        if owned:
            included.append(
                {
                    **record,
                    "owned_files": sorted(set(owned)),
                    "native_identity_ambiguous": len(rows) != 1,
                }
            )
        else:
            excluded.append(
                {**record, "reason": "no declaration in allowed original project files"}
            )
    if not included:
        raise ValueError("no project-owned concrete entries")
    output.mkdir(parents=True)
    inputs = output / "producer-input"
    inputs.mkdir()
    isolated = inputs / "input.bin"
    isolated.write_bytes(stripped.read_bytes())
    payload = {
        "schema": "cpp-whole-binary-plan-v1",
        "official_score": False,
        "cell": cell,
        "original": str(original.resolve()),
        "input": str(isolated.resolve()),
        "owner_root": str(root),
        "exclude_prefixes": args.exclude_prefix,
        "ownership": "concrete native entry with declaration in original main-tree files",
        "source_archive": str(args.source_archive.resolve()),
        "source_archive_sha256": digest(args.source_archive),
        "preprocessed_archive": str(args.preprocessed_archive.resolve()),
        "preprocessed_archive_sha256": digest(args.preprocessed_archive),
        "sample_sha256": digest(args.sample),
        "functions": included,
        "excluded_entries": excluded,
        "discovery": "oracle address guided; not blind discovery",
        "source_limit": "missing/optimized-out/unresolved entries are outside concrete inventory",
    }
    atomic(output / "plan.json", payload)
    print(
        json.dumps(
            {
                "owned_entries": len(included),
                "excluded_entries": len(excluded),
                "all_concrete_entries": len(identities),
            }
        ),
        flush=True,
    )


def producer(args: argparse.Namespace) -> None:
    payload = json.loads(args.plan.read_text())
    input_path = Path(payload["input"])
    if digest(input_path) != payload["cell"]["stripped_sha256"]:
        raise ValueError("stripped input changed")
    rows = payload["functions"]
    addresses = {r["address"] for r in rows}
    if len(addresses) != len(rows):
        raise ValueError("duplicate target address")
    output = args.plan.parent / "producers" / args.tool
    output.mkdir(parents=True, exist_ok=True)
    with (output / "run.lock").open("a") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        config = DecompilerConfig(
            function_timeout_seconds=args.function_timeout,
            binary_timeout_seconds=args.batch_timeout,
        )
        backend = TOOLS[args.tool](config)
        if not backend.is_available():
            raise RuntimeError("producer unavailable: " + args.tool)
        version = backend.get_version()
        binary_files = {
            key: {"path": os.environ[key], "sha256": digest(Path(os.environ[key]))}
            for key in ("FISSION_BIN", "KUNA_BIN")
            if key in os.environ
        }
        contract = {
            "plan_sha256": digest(args.plan),
            "tool": args.tool,
            "version": version,
            "config": config.model_dump(),
            "chunk_size": args.chunk_size,
            "driver_sha256": digest(Path(__file__)),
            "executables": binary_files,
            "environment": {
                k: os.environ.get(k)
                for k in (
                    "FISSION_RESOURCE_ROOT",
                    "FISSION_WORKING_DIR",
                    "GHIDRA_INSTALL_DIR",
                    "JAVA_HOME",
                    "_JAVA_OPTIONS",
                )
            },
            "adapter_sha256": digest(Path(inspect.getfile(type(backend)))),
            "python": sys.version,
            "package_sources": {
                str(p.relative_to(Path(inspect.getfile(DecompilerConfig)).parents[1])): digest(p)
                for p in sorted(Path(inspect.getfile(DecompilerConfig)).parents[1].rglob("*.py"))
            },
        }
        contract_path = output / "contract.json"
        if contract_path.exists() and json.loads(contract_path.read_text()) != contract:
            raise ValueError("resume contract changed; use a new output plan directory")
        atomic(contract_path, contract)
        shards = output / "functions"
        shards.mkdir(exist_ok=True)
        completion_path = output / "completion.json"
        if completion_path.exists():
            completion = json.loads(completion_path.read_text())
            if (
                digest(output / "result.json") != completion["result_sha256"]
                or digest(contract_path) != completion["contract_sha256"]
            ):
                raise ValueError("completed result changed")
            observed_shards = {p.name: digest(p) for p in shards.glob("*.json")}
            if observed_shards != completion["shard_sha256"]:
                raise ValueError("completed checkpoint shards changed")
            print(json.dumps({"tool": args.tool, "reused_completed_result": True}), flush=True)
            return
        completed = {}
        for path in sorted(shards.glob("*.json")):
            value = json.loads(path.read_text())
            if value["address"] not in addresses or value["address"] in completed:
                raise ValueError("invalid completed function shard population")
            completed[value["address"]] = value
        progress = output / "partial.pkl"
        if progress.exists():
            with progress.open("rb") as stream:
                partial = pickle.load(stream)  # Locally generated adapter checkpoint only.
            if not isinstance(partial, DecompilationResult):
                raise ValueError("unexpected local adapter checkpoint")
            for function in partial.functions.values():
                if function.address not in addresses:
                    raise ValueError("checkpoint contains foreign address")
                if function.address not in completed and function.decompiled_code.strip():
                    value = {
                        "address": function.address,
                        "status": "nonempty",
                        "recovered_from_partial": True,
                        "function": function.model_dump(mode="json"),
                    }
                    atomic(shards / f"{function.address:x}.json", value)
                    completed[function.address] = value
        pending = sorted(addresses - completed.keys())
        chunks = [pending[i : i + args.chunk_size] for i in range(0, len(pending), args.chunk_size)]
        for chunk in chunks:
            if digest(input_path) != payload["cell"]["stripped_sha256"]:
                raise ValueError("stripped input changed before chunk")
            invocation = time.time_ns()
            event = {
                "addresses": chunk,
                "started_unix_ns": invocation,
                "contract_sha256": digest(contract_path),
            }
            atomic(output / f"invocation-{invocation}.json", event)
            started = time.monotonic()
            try:
                result = backend.decompile_binary(
                    input_path, functions=[(f"sub_{a:x}", a) for a in chunk], progress_path=progress
                )
                found = {f.address: f for f in result.functions.values()}
                if len(found) != len(result.functions) or not set(found) <= set(chunk):
                    raise ValueError("ambiguous or foreign producer addresses")
                event["metadata"] = result.decompiler.model_dump(mode="json")
                timed_out = result.decompiler.timeout_occurred
                error = result.decompiler.extra.get("error")
            except Exception:
                found, timed_out, error = {}, False, traceback.format_exc()
                event["worker_error"] = error
            if digest(input_path) != payload["cell"]["stripped_sha256"]:
                raise ValueError("stripped input changed during chunk")
            for address in chunk:
                function = found.get(address) or FunctionDecompilation(
                    name=f"sub_{address:x}", address=address, decompiled_code=""
                )
                status = (
                    "nonempty"
                    if function.decompiled_code.strip()
                    else (
                        "missing_after_batch_timeout"
                        if timed_out
                        else "backend_error" if error else "empty_or_missing"
                    )
                )
                value = {
                    "address": address,
                    "status": status,
                    "invocation": invocation,
                    "function": function.model_dump(mode="json"),
                }
                atomic(shards / f"{address:x}.json", value)
                completed[address] = value
            event.update(elapsed_seconds=time.monotonic() - started, completed=True)
            atomic(output / f"invocation-{invocation}.json", event)
            atomic(
                output / "state.json",
                {
                    "completed": len(completed),
                    "requested": len(rows),
                    "plan_sha256": digest(args.plan),
                },
            )
            print(
                json.dumps(
                    {"tool": args.tool, "completed": len(completed), "requested": len(rows)}
                ),
                flush=True,
            )
        result = DecompilationResult(
            binary_path=input_path,
            binary_name=input_path.stem,
            decompiler=DecompilerMetadata(decompiler_name=args.tool, decompiler_version=version),
        )
        for address in sorted(completed):
            result.add_function(
                FunctionDecompilation.model_validate(completed[address]["function"])
            )
        atomic(output / "result.json", result.model_dump(mode="json"))
        atomic(
            output / "completion.json",
            {
                "result_sha256": digest(output / "result.json"),
                "contract_sha256": digest(contract_path),
                "requested": len(rows),
                "nonempty": sum(v["status"] == "nonempty" for v in completed.values()),
                "shard_sha256": {p.name: digest(p) for p in sorted(shards.glob("*.json"))},
            },
        )


def stop_worker(worker: subprocess.Popen) -> None:
    if worker.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.kill(worker.pid, signal.SIGSTOP)
    inventory = subprocess.check_output(["ps", "-axo", "pid=,ppid="], text=True)
    parentage = {
        int(pid): int(parent)
        for pid, parent in (line.split() for line in inventory.splitlines() if line.strip())
    }
    descendants, frontier = [], [worker.pid]
    while frontier:
        children = [pid for pid, parent in parentage.items() if parent in frontier]
        descendants.extend(children)
        frontier = children
    for pid in reversed(descendants):
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(worker.pid, signal.SIGKILL)
    worker.wait()


def supervise(args: argparse.Namespace) -> None:
    output = args.plan.parent / "producers" / args.tool
    output.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "produce",
        "--plan",
        str(args.plan),
        "--tool",
        args.tool,
        "--chunk-size",
        str(args.chunk_size),
        "--function-timeout",
        str(args.function_timeout),
        "--batch-timeout",
        str(args.batch_timeout),
    ]
    stamp = time.time_ns()
    with (output / f"worker-{stamp}.log").open("w") as log:
        worker = subprocess.Popen(
            command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
        )
        try:
            code = worker.wait(timeout=args.worker_timeout)
        except subprocess.TimeoutExpired:
            stop_worker(worker)
            code = 124
        except BaseException:
            stop_worker(worker)
            atomic(
                output / f"worker-{stamp}.json",
                {"command": command, "exit_code": 130, "interrupted": True},
            )
            raise
    atomic(
        output / f"worker-{stamp}.json",
        {
            "command": command,
            "exit_code": code,
            "timeout": code == 124,
            "bounds": "unfinished chunks resume; completed failures stay terminal",
        },
    )
    raise SystemExit(code)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan")
    for name in ("sample", "dataset", "source-archive", "preprocessed-archive", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--cell", required=True)
    p.add_argument("--owner-root", required=True)
    p.add_argument("--exclude-prefix", action="append", default=[])
    for name in ("produce", "run"):
        p = sub.add_parser(name)
        p.add_argument("--plan", type=Path, required=True)
        p.add_argument("--tool", choices=TOOLS, required=True)
        p.add_argument("--chunk-size", type=int, default=64)
        p.add_argument("--function-timeout", type=float, default=30)
        p.add_argument("--batch-timeout", type=float, default=600)
        if name == "run":
            p.add_argument("--worker-timeout", type=float, default=1800)
    args = parser.parse_args()
    if args.command == "plan":
        plan(args)
    else:
        if args.chunk_size < 1 or args.function_timeout <= 0 or args.batch_timeout <= 0:
            parser.error("positive chunk size and timeouts required")
        if args.command == "run":
            if args.worker_timeout <= 0:
                parser.error("positive worker timeout required")
            supervise(args)
        else:
            producer(args)


if __name__ == "__main__":
    main()
