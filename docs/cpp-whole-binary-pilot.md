# Whole-binary owned-entry pilot and local ranking

This is a POSIX-host experimental runner, qualified locally on one Linux AArch64
ELF/DWARF Snappy O0 image. It does not change default metrics, Union, published
overlays or dataset readiness. No target or recovered program executes.

## Population before producer execution

`scripts/run_cpp_whole_binary.py plan` rechecks the frozen original/stripped
hashes, executable-region equality and absence of readable stripped DWARF. The
producer receives an isolated copy of the stripped image. The original debug,
source archive and semantic names stay on the evaluation side; producer requests
use anonymous `sub_ADDRESS` names and entry addresses, never oracle function ends.
This is address-guided decompilation, not a blind function-discovery benchmark.

The planner enumerates concrete DWARF entries using the existing identity/native
source owners. A target needs a declaration under the explicit build-time source
root whose relative path occurs in the original main-tree source archive, outside
explicit dependency prefixes. Project headers are included. Multiple native
identities at an owned address remain in the request population; downstream
oracles abstain rather than picking the most favorable identity.

Every other concrete entry is retained in the inventory with source evidence and
an exclusion reason. This is all entries in the *proved ownership scope*, not all
possible machine functions: missing debug entries, generated files absent from
the source archive and unresolved ownership are not silently called complete.
The source archive itself may omit gitlink dependencies, explicitly excluded here.

```sh
PYTHONPATH=. python scripts/run_cpp_whole_binary.py plan \
  --sample FROZEN_SAMPLE_JSON --dataset QUALIFICATION_ROOT --cell CELL_ID \
  --owner-root ABSOLUTE_SOURCE_ROOT_FROM_DEBUG \
  --source-archive ORIGINAL_MAIN_TREE_TAR \
  --preprocessed-archive ALL_MODES_II_TAR \
  --exclude-prefix third_party --output NEW_RUN_DIRECTORY
```

The sample supplies immutable image/optimization coordinates, not the target
selection. Its sampled function rows are ignored; the native inventory owns the
new complete request list.

## Execution, failures and resume

Configure the existing backends using `FISSION_BIN`, `FISSION_RESOURCE_ROOT`,
`FISSION_WORKING_DIR`, `KUNA_BIN`, `GHIDRA_INSTALL_DIR` and `JAVA_HOME` as needed.
Use one tool per process; PyGhidra binds one JVM install to a process.

```sh
PYTHONPATH=. python scripts/run_cpp_whole_binary.py run \
  --plan RUN/plan.json --tool fission --chunk-size 64 \
  --function-timeout 30 --batch-timeout 600 --worker-timeout 1800
# Repeat for kuna, ghidra and angr, keeping the same plan.
```

`run` supervises a separate `produce` worker. It bounds wall time and kills its
descendants/process group on timeout or keyboard interruption. Each completed
batch writes atomic per-address shards and an invocation record. Every requested
address receives a nonempty, empty/missing, backend-error or missing-after-batch-
timeout outcome. A nonempty result is not a claim of valid code or correctness.
Timeout after a batch is not attributed as a proved per-function timeout.

The same command resumes completed shards and adapter partial checkpoints where
available. Completed failures stay terminal; they are not retried until they
happen to pass. Unfinished work can be retried and earlier interrupted invocation
records remain. The adapter checkpoint is locally generated pickle; this path
does not ingest uploaded checkpoints. Fission/Kuna buffer native batch JSON, so
mid-call recovery is bounded by completed batches. Ghidra/angr can also preserve
per-function partial records. This does not provide universal preemption inside
one native function. An outer timeout can require another invocation to finish.

Resume checks the plan, driver/adapter/package source hashes, tool version,
explicit executable hashes and selected environment. Completed result/shard
hashes must agree. Different contracts need a new run directory. Resource paths
and Ghidra versions are recorded; external installations/resource trees are not
fully content-addressed by this pilot. Benchmark speed comparisons need a separate
controlled timing run: batching and Kuna's cached whole-image preparation differ.

## Evaluation and the ranking rule

Set `RUST_JOERN_LIBRARY` to the explicit pinned shared library. The evaluator
fingerprints it, the Python owners, plan, configuration and producer results.

```sh
PYTHONPATH=. DECBENCH_NO_CACHE=1 python scripts/evaluate_cpp_whole_binary.py \
  --plan RUN/plan.json --data-model LP64 --output RUN/evaluation
# Continue matching checkpoints after interruption:
PYTHONPATH=. DECBENCH_NO_CACHE=1 python scripts/evaluate_cpp_whole_binary.py \
  --plan RUN/plan.json --data-model LP64 --output RUN/evaluation --resume
```

Original `.ii` members must match the requested native TUs. Source identity and
definition-only CFG resolution use the existing C++ GED owner. Source/ABI types
use the existing experimental C++ metric and type-blind correspondence, with
actual preprocessed evidence. Oracles are shared only as immutable preparation;
metric-result caches are disabled. Unexpected evaluator failures stop the run.

Before ranking, all four tools must account for the same requested addresses,
and their source eligibility/evidence and type exclusions must agree. Missing,
invalid or unparsed producer recovery stays a miss within that oracle population.
Per-tool evaluation checkpoints retain hashes and are reused only under the
same contract. The final decision report revalidates common variable populations.

The ranking profile is `cpp-owned-union-v1-experimental`:

- **S:** addresses with qualified source-definition CFGs.
- **T:** addresses admitted by the experimental ABI type oracle.
- **E = S union T:** the same eligible population for every tool.
- A tool succeeds at an address if GED is perfect or ABI types are perfect.
- Rank by successful addresses / E, using competition ranks for ties.
- Report E / all requested entries and every exclusion. An empty E is
  unmeasurable and has no rank. Never substitute per-tool successful populations.

This resembles DecBench's perfect-any-metric presentation but is **not the
official DecBench Union or public leaderboard**. Byte matching/recompilation is
unmeasured and absent. The C++ type policy and definition-only GED are experimental;
templates, implicit lifetime and exception effects have explicit bounds. Ranking
one image does not establish general C++ quality or an execution-equivalence rank.

Return declarations, void/nonvoid results, formal/local fact recovery and output
health remain separate diagnostics. They never enter Union. The evaluation emits
the same decision/signature capture schemas used by the diagnostic comparison
tool, so concrete failures can feed the [diagnostic improvement
loop](cpp-diagnostic-loop.md).

## Measured first scope

Snappy 1.2.2 at upstream revision `2a6c78c781cb76ad191795449cb2267f33138150`,
GCC 13.3, O0, Linux AArch64: 357 concrete DWARF entry addresses, 200 proved
project-owned targets and 157 excluded declaration entries (system C++ headers).
The 200 include one ambiguous native entry, explicitly excluded where needed by
the metric oracles. Source CFG eligibility is 110/200; ABI types 72/200; their
eligible union is 136/200. The 64 with neither oracle remain unmeasurable.

These figures describe the local pilot, not an increase from the earlier
250-function mixed-platform sample; the populations differ and must not be
ranked against each other. Version labels and executable hashes identify the
fixed local producers; Fission's `0.2.3` label is not a claim to measure current
main or the identically named public leaderboard build.
