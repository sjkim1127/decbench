#!/usr/bin/env python3
"""Project a complete disk capture into bounded inputs for the existing C++ evaluator.

Every scheduled tool and target must be accounted for. There is no successful-only
or completed-prefix export. Oracle policies and default metrics stay unchanged.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import zlib
from pathlib import Path
from typing import Any

from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
)
from decbench.utils.cpp_scale_store import ScaleStore, canonical, digest


def export(database: Path, output: Path, reserve_gib: float = 8) -> dict[str, Any]:
    if not database.is_file() or output.exists():
        raise ValueError("existing store and new output directory required")
    with database.with_suffix(".lock").open("a") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = ScaleStore(database)
        try:
            contract = {
                r["name"]: json.loads(r["value"])
                for r in store.db.execute("SELECT * FROM contract")
            }
            tools = contract["schedule"]["tools"]
            if set(tools) != {"fission", "kuna", "ghidra", "angr"}:
                raise ValueError("existing four-tool evaluator requires the complete tool contract")
            if not store.summary()["capture_complete"]:
                raise ValueError("capture is incomplete; no successful-prefix ranking")
            output.mkdir(parents=True)
            marker = output / "INCOMPLETE"
            marker.write_text("Export is incomplete. Do not evaluate this directory.\n")
            projection = {
                "schema": "cpp-scale-projection-v1",
                "capture_contract": contract,
                "plans": {},
                "requested_functions": store.summary()["requested_functions"],
            }
            for cell_row in store.db.execute("SELECT * FROM cells ORDER BY id"):
                cell = json.loads(cell_row["metadata"])
                for job_row in store.db.execute(
                    "SELECT * FROM jobs WHERE cell=? AND tool=? ORDER BY lo", (cell["id"], tools[0])
                ):
                    if shutil.disk_usage(output).free < reserve_gib * 2**30:
                        raise RuntimeError("disk reserve reached; export is not complete")
                    job = dict(job_row)
                    entries = store.requested(job)
                    shard_id = cell["id"] + "-" + job["lo"]
                    directory = output / shard_id
                    directory.mkdir()
                    shard_cell = {**cell, "id": shard_id}
                    plan = {
                        "cell": shard_cell,
                        "original": cell["original"],
                        "input": cell["stripped_path"],
                        "functions": [{"name": n, "address": a} for n, a in entries],
                        "producer_sha256": {},
                        "capture_kind": "fresh_address_guided_stripped",
                        "capture": (
                            "fresh stripped producer capture; "
                            "complete disk-backed native inventory"
                        ),
                    }
                    snapshots: dict[str, Any] = {"contracts": contract}
                    for tool in tools:
                        matching = store.db.execute(
                            "SELECT * FROM jobs WHERE cell=? AND tool=? AND lo=? AND hi=? "
                            "AND expected=? AND status='complete'",
                            (cell["id"], tool, job["lo"], job["hi"], job["expected"]),
                        ).fetchall()
                        if len(matching) != 1:
                            raise ValueError("tool shard population differs")
                        producer = contract["producer:" + tool]
                        result = DecompilationResult(
                            binary_path=Path(cell["stripped_path"]),
                            binary_name=Path(cell["stripped_path"]).name,
                            decompiler=DecompilerMetadata(
                                decompiler_name=tool,
                                decompiler_version=producer["version"],
                                total_time_seconds=json.loads(matching[0]["evidence"])["seconds"],
                                extra={
                                    "capture_job": matching[0]["id"],
                                    "capture_attempt": matching[0]["attempt"],
                                },
                            ),
                        )
                        rows = store.db.execute(
                            "SELECT * FROM outputs WHERE job=? ORDER BY address",
                            (matching[0]["id"],),
                        ).fetchall()
                        if len(rows) != len(entries) or {int(r["address"], 16) for r in rows} != {
                            a for _, a in entries
                        }:
                            raise ValueError("completed shard denominator differs")
                        snapshots[tool] = {"job": dict(matching[0]), "rows": []}
                        for row in rows:
                            entry = int(row["address"], 16)
                            if row["payload"] is not None:
                                raw = zlib.decompress(row["payload"])
                                if hashlib.sha256(raw).hexdigest() != row["sha256"]:
                                    raise ValueError("stored producer payload hash differs")
                                function = FunctionDecompilation.model_validate_json(raw)
                                if function.address != entry:
                                    raise ValueError("stored producer address differs")
                            else:
                                function = FunctionDecompilation(
                                    name=f"sub_{entry:x}",
                                    address=entry,
                                    decompiled_code="",
                                    metadata={"scale_capture_outcome": row["outcome"]},
                                )
                            result.add_function(function)
                            snapshots[tool]["rows"].append(
                                {
                                    "address": row["address"],
                                    "outcome": row["outcome"],
                                    "sha256": row["sha256"],
                                }
                            )
                        if len(result.functions) != len(entries):
                            raise ValueError("storage identity collapsed")
                        path = directory / "producers" / tool / "result.json"
                        path.parent.mkdir(parents=True)
                        path.write_text(result.model_dump_json())
                        plan["producer_sha256"][tool] = digest(path)
                    snapshot = directory / "capture-evidence.json"
                    snapshot.write_text(canonical(snapshots))
                    plan["input_evidence_sha256"] = {str(snapshot.resolve()): digest(snapshot)}
                    path = directory / "plan.json"
                    path.write_text(canonical(plan))
                    projection["plans"][str(path.resolve())] = digest(path)
            ready = output / "projection.json"
            ready.write_text(canonical(projection))
            with ready.open("rb") as stream:
                os.fsync(stream.fileno())
            marker.unlink()
            return {
                "shards": len(projection["plans"]),
                "requested_functions": projection["requested_functions"],
                "projection_sha256": digest(ready),
                "ranking_ready": False,
            }
        finally:
            store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reserve-gib", type=float, default=8)
    args = parser.parse_args()
    if args.reserve_gib <= 0:
        parser.error("positive disk reserve required")
    print(json.dumps(export(args.database, args.output, args.reserve_gib), indent=2))


if __name__ == "__main__":
    main()
