"""Disk-backed experimental C++ producer cohorts; never a metric or site store."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TextIO


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def address(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
        raise ValueError("address must be an unsigned 64-bit integer")
    return f"{value:016x}"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError("non-finite JSON constant: " + value)


class _Reader:
    def __init__(self, stream: TextIO, limit: int):
        self.stream, self.limit = stream, limit
        self.buffer, self.eof = "", False
        self.decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)

    def refill(self) -> None:
        data = self.stream.read(65536)
        self.eof = not data
        self.buffer += data
        if len(self.buffer) > self.limit:
            raise ValueError("JSON record exceeds configured memory bound")

    def peek(self) -> str:
        self.buffer = self.buffer.lstrip()
        while not self.buffer and not self.eof:
            self.refill()
            self.buffer = self.buffer.lstrip()
        return self.buffer[:1]

    def take(self, expected: str) -> None:
        if self.peek() != expected:
            raise ValueError("expected JSON token " + expected)
        self.buffer = self.buffer[1:]

    def value(self) -> Any:
        self.peek()
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buffer)
            except json.JSONDecodeError:
                if self.eof:
                    raise ValueError("invalid or truncated JSON") from None
                self.refill()
                continue
            if end == len(self.buffer) and not self.eof:
                self.refill()
                continue
            self.buffer = self.buffer[end:]
            return value


def records(stream: TextIO, field: str = "functions", limit: int = 32 << 20) -> Iterator[Any]:
    """Yield a root array or one named array; exhaustion validates the whole document.

    Consumers must not publish provisional rows before this iterator is exhausted.
    Other top-level values and individual records are bounded by ``limit``.
    """
    reader = _Reader(stream, limit)

    def array() -> Iterator[Any]:
        reader.take("[")
        if reader.peek() != "]":
            while True:
                yield reader.value()
                if reader.peek() != ",":
                    break
                reader.take(",")
        reader.take("]")

    if reader.peek() == "[":
        yield from array()
    else:
        reader.take("{")
        keys: set[str] = set()
        if reader.peek() != "}":
            while True:
                key = reader.value()
                if not isinstance(key, str) or key in keys:
                    raise ValueError("invalid or duplicate top-level key")
                keys.add(key)
                reader.take(":")
                if key == field:
                    yield from array()
                else:
                    reader.value()
                if reader.peek() != ",":
                    break
                reader.take(",")
        reader.take("}")
        if field not in keys:
            raise ValueError("missing JSON array: " + field)
    if reader.peek():
        raise ValueError("trailing JSON content")


class ScaleStore:
    """A bounded producer ledger with atomic shards and an immutable input contract.

    One external controller lock owns a store. No worker writes SQLite directly;
    a claimed attempt fences stale completion messages after recovery.
    """

    def __init__(self, path: Path):
        self.db = sqlite3.connect(path, timeout=60)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA foreign_keys=ON;
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS contract (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cells (id TEXT PRIMARY KEY, metadata TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS targets (
                cell TEXT REFERENCES cells(id), address TEXT, name TEXT NOT NULL,
                aliases TEXT NOT NULL, PRIMARY KEY(cell,address));
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY, cell TEXT REFERENCES cells(id), tool TEXT NOT NULL,
                lo TEXT NOT NULL, hi TEXT NOT NULL, expected INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', attempt INTEGER NOT NULL DEFAULT 0,
                evidence TEXT, UNIQUE(cell,tool,lo));
            CREATE TABLE IF NOT EXISTS outputs (
                job INTEGER REFERENCES jobs(id), cell TEXT, tool TEXT, address TEXT,
                outcome TEXT NOT NULL, payload BLOB, sha256 TEXT,
                PRIMARY KEY(cell,tool,address),
                FOREIGN KEY(cell,address) REFERENCES targets(cell,address));
            CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(tool,status,id);
            """)

    def close(self) -> None:
        self.db.close()

    def bind(self, name: str, value: Any) -> None:
        text = canonical(value)
        with self.db:
            row = self.db.execute("SELECT value FROM contract WHERE name=?", (name,)).fetchone()
            if row is not None and row[0] != text:
                raise ValueError("resume contract differs: " + name)
            self.db.execute("INSERT OR IGNORE INTO contract VALUES (?,?)", (name, text))

    def schedule(self, tools: list[str], chunk: int) -> None:
        if chunk < 1 or len(set(tools)) != len(tools) or not tools:
            raise ValueError("invalid shard size or tool population")
        self.bind("schedule", {"tools": tools, "chunk": chunk})
        with self.db:
            for cell in self.db.execute("SELECT id FROM cells ORDER BY id").fetchall():
                pending: list[str] = []
                for row in self.db.execute(
                    "SELECT address FROM targets WHERE cell=? ORDER BY address", (cell[0],)
                ):
                    pending.append(row[0])
                    if len(pending) == chunk:
                        self._schedule(cell[0], tools, pending)
                        pending = []
                if pending:
                    self._schedule(cell[0], tools, pending)

    def _schedule(self, cell: str, tools: list[str], entries: list[str]) -> None:
        self.db.executemany(
            "INSERT OR IGNORE INTO jobs(cell,tool,lo,hi,expected) VALUES (?,?,?,?,?)",
            [(cell, tool, entries[0], entries[-1], len(entries)) for tool in tools],
        )

    def recover(self, tool: str) -> int:
        with self.db:
            cursor = self.db.execute(
                "UPDATE jobs SET status='pending',attempt=attempt+1 "
                "WHERE tool=? AND status='running'",
                (tool,),
            )
        return cursor.rowcount

    def claim(self, tool: str) -> dict[str, Any] | None:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT * FROM jobs WHERE tool=? AND status='pending' ORDER BY id LIMIT 1", (tool,)
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["attempt"] += 1
            self.db.execute(
                "UPDATE jobs SET status='running',attempt=? WHERE id=?",
                (result["attempt"], result["id"]),
            )
        return result

    def requested(self, job: dict[str, Any]) -> list[tuple[str, int]]:
        return [
            (row["name"], int(row["address"], 16))
            for row in self.db.execute(
                "SELECT name,address FROM targets WHERE cell=? AND address BETWEEN ? AND ? "
                "ORDER BY address",
                (job["cell"], job["lo"], job["hi"]),
            )
        ]

    def finish(
        self, job: dict[str, Any], values: Iterator[dict[str, Any]], evidence: dict[str, Any]
    ) -> None:
        """Commit a complete verified shard, including absent/error rows, or nothing."""
        allowed = {"missing", "timeout", "producer_error", "output_limit"}
        if evidence.get("missing_outcome", "missing") not in allowed:
            raise ValueError("unrecognized producer failure outcome")
        requested = {address(a) for _, a in self.requested(job)}
        if len(requested) != job["expected"]:
            raise ValueError("requested population changed")
        with self.db:
            current = self.db.execute("SELECT * FROM jobs WHERE id=?", (job["id"],)).fetchone()
            if (
                current is None
                or current["status"] != "running"
                or current["attempt"] != job["attempt"]
                or any(current[key] != job[key] for key in ("cell", "tool", "lo", "hi", "expected"))
            ):
                raise ValueError("stale or unclaimed completion")
            returned: set[str] = set()
            for row in values:
                key = address(row["address"])
                if key not in requested or key in returned:
                    raise ValueError("foreign or duplicate producer address")
                returned.add(key)
                payload = canonical(row).encode()
                outcome = "nonempty" if row.get("decompiled_code", "").strip() else "empty"
                self.db.execute(
                    "INSERT INTO outputs VALUES (?,?,?,?,?,?,?)",
                    (
                        job["id"],
                        job["cell"],
                        job["tool"],
                        key,
                        outcome,
                        zlib.compress(payload),
                        hashlib.sha256(payload).hexdigest(),
                    ),
                )
            for key in sorted(requested - returned):
                self.db.execute(
                    "INSERT INTO outputs VALUES (?,?,?,?,?,?,?)",
                    (
                        job["id"],
                        job["cell"],
                        job["tool"],
                        key,
                        evidence.get("missing_outcome", "missing"),
                        None,
                        None,
                    ),
                )
            self.db.execute(
                "UPDATE jobs SET status='complete',evidence=? WHERE id=?",
                (canonical(evidence), job["id"]),
            )

    def summary(self) -> dict[str, Any]:
        def counts(sql: str) -> list[dict[str, Any]]:
            return [dict(r) for r in self.db.execute(sql)]

        unfinished = self.db.execute(
            "SELECT count(*) FROM jobs WHERE status!='complete'"
        ).fetchone()[0]
        return {
            "schema": "cpp-producer-scale-v1",
            "ranking_ready": False,
            "bounds": "producer transport only; native inventory is not oracle eligibility",
            "requested_functions": self.db.execute("SELECT count(*) FROM targets").fetchone()[0],
            "capture_complete": unfinished == 0
            and self.db.execute("SELECT count(*) FROM jobs").fetchone()[0] > 0,
            "jobs": counts("SELECT tool,status,count(*) AS count FROM jobs GROUP BY tool,status"),
            "outputs": counts(
                "SELECT tool,outcome,count(*) AS count FROM outputs GROUP BY tool,outcome"
            ),
        }
