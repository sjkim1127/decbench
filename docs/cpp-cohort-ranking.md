# Frozen multi-image C++ diagnostic ranking

This extends the whole-binary pilot's existing perfect-any-metric rule to a
frozen set of image plans. It is experimental and independent of default GED,
type_match, byte_match, official Union, website and published overlays. No corpus
or recovered program executes. The producer artifacts are reused; only metric
computations are fresh. Captured version labels do not describe current releases.

Each plan has a `cell` (id, project, platform, optimization, image hashes),
`original`, `input`, `functions` (distinct native entry addresses), and expected
`producer_sha256` values for all four tools. Producer files live at
`producers/{fission,kuna,ghidra,angr}/result.json` next to the plan. Original
capture completion/contract evidence or explicit frozen hashes are mandatory.
Every requested entry has a producer row, including empty/missing recovery.
`input_evidence_sha256` binds raw captures and normalization code when present.
If an old normalizer changed, reingest the original raw captures into a new
plan; do not overwrite historical evidence hashes or call that fresh decompilation.

```sh
PYTHONPATH=. DECBENCH_NO_CACHE=1 python scripts/evaluate_cpp_cohort.py \
  --plans-root FROZEN_PLANS --dataset QUALIFICATION_ROOT \
  --dataset-revision IMMUTABLE_DATASET_COMMIT --parser-library EXPLICIT_LIBRARY \
  --output NEW_RUN --jobs 2 --timeout 900
# Resume the identical contract after interruption:
PYTHONPATH=. DECBENCH_NO_CACHE=1 python scripts/evaluate_cpp_cohort.py \
  --plans-root FROZEN_PLANS --dataset QUALIFICATION_ROOT \
  --dataset-revision IMMUTABLE_DATASET_COMMIT --parser-library EXPLICIT_LIBRARY \
  --output NEW_RUN --jobs 2 --timeout 900 --resume
PYTHONPATH=. python scripts/rank_cpp_cohort.py \
  --evaluation NEW_RUN --output NEW_RANK_DIRECTORY
```

The evaluator uses the existing exact source/native CFG join and C++ source/ABI
type metric. Original preprocessed TUs must match native provenance; missing TUs,
unknown locations and unsupported semantics stay explicit oracle exclusions.
Debug images, companions and source archives are validated before/after each
image. Producer output never receives oracle declarations, names or layouts.
Renaming to native semantic names happens only after address-based ingestion.

The driver has no fixed function/sample count. `--cell` explicitly selects pilot
cells; omitting it evaluates the complete input pool. One subprocess owns one
image. Bounded workers, process-group timeouts, source/library/configuration
fingerprints and per-cell atomic checkpoints support resumption. Completed
failures remain terminal and block ranking; they are not converted into oracle
abstention or silently retried. Use a new run for changed contracts/failure retry.
Interrupting unfinished workers leaves their cells pending. Metric results are
never reused across experiments; immutable oracle preparation is shared only
within an image. The metric implementation is unchanged.

## Rank and denominators

For every image all tools must share the same requested native entries, source
CFG evidence, type-oracle exclusions and complete expected type facts. The type
fact reporter independently validates source/ABI and cross-tool populations.

- S: common eligible source-definition CFG entries.
- T: common eligible experimental ABI-type entries.
- E = S union T.
- A success is a perfect directed GED match OR a perfect ABI-type match.
- Rank by successes / E, with competition ranks for ties. E must be nonempty.
- Also show E / requested, successes / requested, separate GED/type columns,
  nonempty output, producer CFG statuses and every unmeasurable requested row.

No successful-producer-only intersection is used. A missing, invalid or unparsed
producer result is a miss inside E. Unexpected evaluator errors/timeouts prevent
completion and ranking rather than changing E. Each `(cell,address,tool)` occurs
once in `ledger.json`. `ranking.json` and `ranking.md` retain captured tool
versions and frozen dataset identity. `type-facts.json` / `.md` expose coverage,
partial declared variable-type fact recovery and strict agreement independently;
these facts are not physical memory-access recovery or execution evidence.

Byte matching, compiler/ABI recompilation, dynamic correctness and runtime
object/exception semantics are unmeasured and excluded. Constructor experimental
options are not enabled by this driver. Selecting a different library creates
another evaluation profile; its rank is not a claim of decompiler improvement.
The qualified subset may be much smaller than requested, and sampled/optimized
variants may be correlated. This is a bounded local comparison, not C++ corpus
qualification, a current-release leaderboard or an official DecBench score.
