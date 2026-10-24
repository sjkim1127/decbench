# Experimental C++ scale transport

The target is tens of thousands of real native entries per tool. Native inventory,
producer coverage, oracle eligibility and perfect recovery are separate numbers.
This lane does not make the qualification corpus scoring-ready and does not update
any published ranking, default metric, byte score, cache generation or parser pin.

`scripts/run_cpp_scale.py` freezes packaged native inventories into SQLite. A native
entry is counted once per binary/address, even when several debug DIEs or aliases
refer to it. These inventories can include header/dependency implementations; they
are not automatically a strict project-owned source population. Image and inventory
hashes must agree with the package manifest, and stripped executable regions must
match the originals. Addresses use unsigned 64-bit hexadecimal text, including on
PE/Mach-O; display names are never the storage identity.

## Capture

Use the existing development environment and backend installs documented in
[benchmarking.md](benchmarking.md). Dataset, sample metadata, tools and chunk size
are frozen before any tool output is read. Producer workers receive only stripped
inputs and anonymous addresses. Do not point them at debug images or source bundles.

```sh
PYTHONPATH=. python scripts/run_cpp_scale.py init \
  --dataset /absolute/path/to/qualification-v2 \
  --sample /absolute/path/to/frozen/sample.json \
  --database /absolute/path/to/run/cohort.sqlite \
  --cells 02 05 --chunk-size 256

PYTHONPATH=. python scripts/run_cpp_scale.py capture \
  --database /absolute/path/to/run/cohort.sqlite --tool kuna
# Repeat for fission, ghidra and angr, with their normal backend environment.

PYTHONPATH=. python scripts/run_cpp_scale.py status \
  --database /absolute/path/to/run/cohort.sqlite
```

An omitted cell filter includes every image in the supplied frozen sample metadata,
using the full packaged native inventories, not the sample's selected function rows.
There is no fabricated, duplicated or size-selected function population. SHA checks
bind the source metadata to the original manifest. Qualification exclusions remain
an evaluator decision later.

Each shard is a fresh isolated process and an atomic transaction. Completed shards
are retained after interruption; the running shard is retried. A fencing attempt
rejects stale completions. SIGTERM/interrupt cleanup uses the existing supervisor
to stop detached producer descendants as well as the worker process. Missing,
empty, producer-error and batch-timeout outcomes
stay in the requested population. Unexpected adapter/transport errors block that
shard instead of becoming oracle exclusions. The producer source tree, driver,
executable, version, environment and timeout contract must match when resuming.
Use a new store when these change. Never edit the saved contract to force a resume.

The controller holds an exclusive file lock and runs one shard at a time. Small
bounded spools and zlib-compressed function records avoid full-cohort Python object
graphs and repeated whole-result pickle writes. The default disk reserve is 8 GiB;
spool overflow and batch timeouts are reported explicitly. Disk guards are checked
while a child runs. Native whole-program analysis memory is still owned by each
backend and is not limited merely by reducing the number of output functions.

Kuna is invoked with a bounded list of `--addr` entries and its existing adapter's
variable/line transport. Fission/Ghidra/angr use their existing address-guided raw
adapters. **This first transport implementation reloads analysis per shard.** In
particular Ghidra and angr can spend substantial time rebuilding whole-program
analysis. It establishes durable scale operation, not a claimed throughput win.
No change to analysis order or output quality is claimed.

## Evaluation and ranking

Export only after all four requested tools finish:

```sh
PYTHONPATH=. python scripts/export_cpp_scale.py \
  --database /absolute/path/to/run/cohort.sqlite \
  --output /absolute/path/to/run/plans

PYTHONPATH=. DECBENCH_NO_CACHE=1 python scripts/evaluate_cpp_cohort.py \
  --plans-root /absolute/path/to/run/plans \
  --dataset /absolute/path/to/qualification-v2 \
  --dataset-revision EXACT_DATASET_REVISION \
  --parser-library /absolute/path/to/pinned/librust_joern.dylib \
  --output /absolute/path/to/run/evaluation --jobs 1 --timeout 1800
# Add --resume on subsequent invocations with the identical contract.

PYTHONPATH=. python scripts/rank_cpp_cohort.py \
  --evaluation /absolute/path/to/run/evaluation \
  --output /absolute/path/to/run/ranking
```

Exports retain every scheduled entry for each tool. Empty rows represent capture
failures; they do not remove the oracle's eligibility. A complete projection binds
all shard plans, producer evidence, normalized output hashes and the full native
population. A partial export must not be evaluated. The existing evaluator operates
on bounded shards with its existing fail-closed identity/type/CFG contracts, and its
existing per-shard checkpoints resume evaluation independently from capture.

`capture_complete` describes producer accounting only. `ranking_ready` remains false
in capture reports. Only successful complete evaluation of every frozen shard can
produce the local experimental common-oracle ranking. A native-entry inventory,
queue/storage stress test, one-tool capture, successful compilation, or parser
acceptance is not a four-tool benchmark. Byte matching and execution equivalence
remain separate, compiler/ABI-qualified stages.
