"""Scale transport invariants; fixtures are not corpus quality evidence."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from decbench.utils.cpp_scale_store import ScaleStore, address, canonical, records


def seeded(tmp_path: Path, size: int = 5) -> ScaleStore:
    store = ScaleStore(tmp_path / "test.sqlite")
    with store.db:
        store.db.execute("INSERT INTO cells VALUES ('a','{}')")
        store.db.executemany(
            "INSERT INTO targets VALUES ('a',?,?,?)",
            [(address(i), f"f{i}", canonical([f"f{i}"])) for i in range(size)],
        )
    store.schedule(["kuna", "angr"], 2)
    return store


def test_atomic_shards_recover_and_fence_stale_writer(tmp_path: Path) -> None:
    store = seeded(tmp_path)
    try:
        job = store.claim("kuna")
        assert job is not None
        assert store.recover("kuna") == 1
        replacement = store.claim("kuna")
        assert replacement is not None
        with pytest.raises(ValueError, match="stale"):
            store.finish(job, iter(()), {})
        store.finish(replacement, iter([{"address": 0, "decompiled_code": "int f() {}"}]), {})
        rows = list(store.db.execute("SELECT address,outcome FROM outputs ORDER BY address"))
        assert [tuple(row) for row in rows] == [(address(0), "nonempty"), (address(1), "missing")]
        assert not store.summary()["capture_complete"]
        assert not store.summary()["ranking_ready"]
        with pytest.raises(ValueError, match="stale"):
            store.finish(replacement, iter(()), {})
    finally:
        store.close()


@pytest.mark.parametrize("addresses", [[0, 0], [0, 999]])
def test_duplicate_or_foreign_record_rolls_back_entire_batch(
    tmp_path: Path, addresses: list[int]
) -> None:
    store = seeded(tmp_path)
    try:
        job = store.claim("kuna")
        assert job is not None
        with pytest.raises(ValueError, match="foreign or duplicate"):
            store.finish(job, iter({"address": a} for a in addresses), {})
        assert store.db.execute("SELECT count(*) FROM outputs").fetchone()[0] == 0
        assert (
            store.db.execute("SELECT status FROM jobs WHERE id=?", (job["id"],)).fetchone()[0]
            == "running"
        )
    finally:
        store.close()


def test_malformed_stream_cannot_commit_partial_capture(tmp_path: Path) -> None:
    store = seeded(tmp_path)
    try:
        job = store.claim("kuna")
        assert job is not None
        with pytest.raises(ValueError, match="truncated"):
            store.finish(job, records(io.StringIO('[{"address":0},')), {})
        assert store.db.execute("SELECT count(*) FROM outputs").fetchone()[0] == 0
    finally:
        store.close()


def test_reopen_preserves_complete_denominator_and_contract(tmp_path: Path) -> None:
    store = seeded(tmp_path)
    store.bind("source", {"hash": "a"})
    first = store.claim("kuna")
    assert first is not None
    store.finish(first, iter(()), {"missing_outcome": "timeout"})
    store.close()
    store = ScaleStore(tmp_path / "test.sqlite")
    try:
        store.bind("source", {"hash": "a"})
        with pytest.raises(ValueError, match="resume contract"):
            store.bind("source", {"hash": "b"})
        while job := store.claim("kuna"):
            store.finish(job, iter(()), {})
        assert not store.summary()["capture_complete"]
        while job := store.claim("angr"):
            store.finish(job, iter(()), {})
        assert store.summary()["capture_complete"]
        assert store.db.execute("SELECT count(*) FROM outputs").fetchone()[0] == 10
        assert (
            store.db.execute("SELECT count(*) FROM outputs WHERE outcome='timeout'").fetchone()[0]
            == 2
        )
    finally:
        store.close()


def test_streaming_large_realistic_records_and_boundaries() -> None:
    value = {
        "count": 3,
        "functions": [{"code": "x" * 65530}, {"address": 2**64 - 1}, {"name": "한글"}],
        "metadata": {"ok": True},
    }
    assert list(records(io.StringIO(json.dumps(value)))) == value["functions"]
    assert list(records(io.StringIO("[]"))) == []


@pytest.mark.parametrize(
    "text",
    [
        '{"functions":[],"functions":[]}',
        '{"functions":[{"a":1,"a":2}]}',
        '{"functions":[]} null',
        '{"functions":[1,]}',
        '{"functions":[NaN]}',
        '{"functions":{}}',
        '{"other":[]}',
        "[1,2",
    ],
)
def test_stream_rejects_invalid_documents(text: str) -> None:
    with pytest.raises(ValueError):
        list(records(io.StringIO(text)))


def test_record_memory_bound() -> None:
    with pytest.raises(ValueError, match="memory bound"):
        list(records(io.StringIO(json.dumps([{"code": "x" * 400000}])), limit=128 << 10))


@pytest.mark.parametrize("value", [-1, 2**64, True, "1000", 1.5])
def test_address_is_not_a_signed_sqlite_integer(value: object) -> None:
    with pytest.raises(ValueError):
        address(value)


def test_max_unsigned_address_round_trip(tmp_path: Path) -> None:
    store = ScaleStore(tmp_path / "test.sqlite")
    try:
        with store.db:
            store.db.execute("INSERT INTO cells VALUES ('a','{}')")
            store.db.execute("INSERT INTO targets VALUES ('a',?,'f','[]')", (address(2**64 - 1),))
        store.schedule(["kuna"], 1)
        job = store.claim("kuna")
        assert job is not None
        assert store.requested(job) == [("f", 2**64 - 1)]
        store.finish(job, iter([{"address": 2**64 - 1}]), {})
        assert store.summary()["capture_complete"]
    finally:
        store.close()


def test_export_requires_all_tools_and_detects_payload_corruption(tmp_path: Path) -> None:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from export_cpp_scale import export

    database = tmp_path / "all.sqlite"
    store = ScaleStore(database)
    try:
        store.bind("inventory", {"source": "fixture-control-only"})
        with store.db:
            store.db.execute(
                "INSERT INTO cells VALUES ('a',?)",
                (
                    canonical(
                        {
                            "id": "a",
                            "original": "/fixture/original",
                            "stripped_path": "/fixture/stripped",
                        }
                    ),
                ),
            )
            for value in range(3):
                store.db.execute(
                    "INSERT INTO targets VALUES ('a',?,'same','[\"same\"]')", (address(value),)
                )
        tools = ["fission", "kuna", "ghidra", "angr"]
        store.schedule(tools, 2)
        for tool in tools:
            store.bind("producer:" + tool, {"version": "test"})
        with pytest.raises(ValueError, match="incomplete"):
            export(database, tmp_path / "incomplete", reserve_gib=0.001)
        assert not (tmp_path / "incomplete").exists()
        for tool in tools:
            while job := store.claim(tool):
                store.finish(
                    job,
                    iter(
                        {"address": value, "name": "same", "decompiled_code": ""}
                        for _, value in store.requested(job)
                    ),
                    {"seconds": 0},
                )
        result = export(database, tmp_path / "plans", reserve_gib=0.001)
        assert result["shards"] == 2
        assert result["requested_functions"] == 3
        assert not (tmp_path / "plans" / "INCOMPLETE").exists()
        projection = json.loads((tmp_path / "plans" / "projection.json").read_bytes())
        requested = []
        for path in projection["plans"]:
            plan = json.loads(Path(path).read_bytes())
            requested.extend(r["address"] for r in plan["functions"])
            for tool in tools:
                capture = json.loads(
                    (Path(path).parent / "producers" / tool / "result.json").read_bytes()
                )
                assert len(capture["functions"]) == len(plan["functions"])
        assert sorted(requested) == [0, 1, 2]
        with store.db:
            store.db.execute("UPDATE outputs SET payload=? WHERE tool='kuna'", (b"corrupt",))
        import zlib

        with pytest.raises(zlib.error):
            export(database, tmp_path / "corrupt", reserve_gib=0.001)
        assert (tmp_path / "corrupt" / "INCOMPLETE").exists()
    finally:
        store.close()


def test_changed_shard_identity_is_rejected(tmp_path: Path) -> None:
    store = seeded(tmp_path)
    try:
        job = store.claim("kuna")
        assert job is not None
        job["tool"] = "angr"
        with pytest.raises(ValueError, match="stale"):
            store.finish(job, iter(()), {})
        with pytest.raises(ValueError, match="unrecognized"):
            store.finish(job, iter(()), {"missing_outcome": "oracle_exclusion"})
    finally:
        store.close()


def test_supervisor_stops_detached_producer_descendant(tmp_path: Path) -> None:
    import contextlib
    import os
    import signal
    import subprocess
    import sys
    import time

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from run_cpp_whole_binary import stop_worker

    pidfile = tmp_path / "pid"
    source = (
        "import subprocess,sys,time; from pathlib import Path; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
        "start_new_session=True); Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(60)"
    )
    parent = subprocess.Popen([sys.executable, "-c", source, str(pidfile)], start_new_session=True)
    child = None
    try:
        for _ in range(100):
            if pidfile.exists():
                child = int(pidfile.read_text())
                break
            time.sleep(0.02)
        assert child is not None
        stop_worker(parent)
        assert parent.poll() is not None
        observed = subprocess.run(
            ["ps", "-p", str(child), "-o", "stat="], capture_output=True, text=True
        )
        assert not observed.stdout.strip() or observed.stdout.strip().startswith("Z")
    finally:
        if parent.poll() is None:
            stop_worker(parent)
        if child:
            with contextlib.suppress(ProcessLookupError):
                os.kill(child, signal.SIGKILL)


@pytest.mark.parametrize("incomplete", [True, False])
def test_evaluator_refuses_incomplete_or_subset_scale_projection(
    tmp_path: Path, incomplete: bool
) -> None:
    import subprocess
    import sys

    plans = tmp_path / "plans"
    plans.mkdir()
    if incomplete:
        (plans / "INCOMPLETE").write_text("building")
    else:
        (plans / "projection.json").write_text('{"plans":{}}')
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_cpp_cohort.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--plans-root",
            str(plans),
            "--dataset",
            str(tmp_path),
            "--dataset-revision",
            "unit-control",
            "--parser-library",
            str(tmp_path / "not-loaded"),
            "--output",
            str(tmp_path / "result"),
            "--cell",
            "subset",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert ("incomplete scale projection" if incomplete else "partial population") in result.stderr
    assert not (tmp_path / "result").exists()
