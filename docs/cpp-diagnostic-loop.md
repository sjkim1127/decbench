# C++ diagnostic improvement loop (experimental)

`scripts/compare_cpp_diagnostics.py` connects saved type diagnosis and native
signature captures to a before/after investigation workflow. It does not run
decompilers, compile recovered code or execute programs. No default metric,
cache generation, Union or published score changes.

## Workflow

1. Freeze each tool's stripped output and retain the original native debug and
   source evidence. Generate the existing decision and signature captures for
   every requested function, including excluded and failed entries.
2. Group diagnostic failures by lane, role, category and recorded reason. Inspect
   packet references and original output before attributing a problem to a
   decompiler, adapter, evaluator policy or incomplete oracle evidence.
3. Fix the responsible implementation using a general invariant. The queue is
   investigation evidence, not proof of defect ownership or a tuning target.
4. Capture the candidate against the same input/oracle population. Use separate
   immutable files for baseline and candidate outputs; do not overwrite evidence.
5. Compare the snapshots. Inspect each gain, lost fact, strict exact loss and
   changed value correspondence. A net gain cannot hide a lost correct fact.
6. Independently qualify compilation, physical ABI and execution when required.
   Passing this declared-type comparison is not an execution or release gate.

```sh
PYTHONPATH=. DECBENCH_NO_CACHE=1 python scripts/compare_cpp_diagnostics.py \
  --baseline-reports BASELINE_CELL_DECISIONS \
  --candidate-reports CANDIDATE_CELL_DECISIONS \
  --baseline-signatures BASELINE_NATIVE_SIGNATURES \
  --candidate-signatures CANDIDATE_NATIVE_SIGNATURES \
  --verify-producer-files --output NEW_COMPARISON_DIRECTORY
```

Use complete cell directories containing only capture JSON files. Both sides
are interpreted with the same current diagnostic implementation. This is not
a comparison of scores produced by different historical evaluator policies.

## Integrity and comparison contract

The tool regenerates variable diagnosis using the existing owner. It rechecks
saved return assessments against the native and recovered graphs. Each side
must retain matching decision/signature addresses, native image hashes, producer
text hashes where both lanes recorded them, and consistent summary counts.

The snapshots must have identical requested cells/addresses, original image and
debug digest populations, source member/digests, platform/data model, native
roles/type graphs, oracle exclusions, variable identities, expected fact slots,
values and gaps. Native graph transport is compared conservatively as recorded;
equivalent graph-ID renumbering is not normalized by this comparison tool.
Transport/policy changes require a separate oracle audit and a new baseline.

Producer hashes may change between snapshots. Their recorded file references
and hashes travel with packets. `--verify-producer-files` rereads those files;
without it the tool only verifies the saved decision/signature inputs, and the
comparison records `producer_files_verified: null`. Original binaries and debug
files are not reread here; this uses their existing capture hashes.

Missing/unsupported/invalid recovery retains the original oracle facts. Formal,
local and unknown-role variable facts remain separate from declared returns;
void and nonvoid returns remain separate. These are not physical ABI slots or
actual accessed-field measurements. There is no combined ranking score.

## Output and exit status

- `comparison.json`: provenance, separate lane/role totals, strict exact counts,
  every changed unit with its before/after correspondence and fact gains/losses.
- `comparison.md`: bounded fact comparison, without a combined rank.
- `queue.json`: failure groups, their units, projects/optimization spread and
  packet references. Counts of variable/return occurrences are not function
  counts; common oracle exclusions are deduplicated across the four tools.
- `packets/*.json`: exact cell/address, current oracle context, before/after
  diagnostic evidence and hashed source-capture/producer file references.
  These require the retained local artifacts; they are not standalone execution
  reproducers and should not be copied wholesale into upstream PRs or prompts.

For a completed report, exit 0 means no observed lost fact or strict exact match
in measurable evidence. Strict losses include ABI variables, source/ABI-perfect
functions and declared returns.
Exit 1 means a regression, even if aggregate recall increased. Exit 2 means
incompatible oracle populations: no score delta is emitted. Exit 3 means no
measurable facts. Malformed captures and unexpected evaluator failures raise
errors instead of becoming oracle exclusions. The output directory must be new.

Baseline versus itself is a wiring/determinism control. It is not evidence of
decompiler improvement. This pipeline does not infer semantic correctness from
parsing, fact recall, strict declared-type agreement or absence of regressions.

## Parser qualification before score comparison

The local Rust-Joern constructor work adds a separate `scripts/qualify_corpus.py`
lane in that repository. Export the **exact prepared parser bytes**, language,
filename, SHA256 and source/producer origin references into a frozen `rows`
manifest, then qualify baseline and candidate in new output directories. Do not
pass original source/class declarations into a producer row. Class context for
source evaluation must come from its exact preprocessed TU and retain offsets
and hashes; a caller-supplied type name does not prove member order.

The runner has no 250-row limit. Its per-input subprocesses and hash-checked
atomic checkpoints retain parse rejection, no-method output, timeout, crash,
evaluator error and pending work separately. `--max-new` bounds a pass;
`--resume` continues the same manifest/backend/options contract. A library,
wrapper or driver change requires a new run directory. Completed failures are
not retried until they pass. This qualification can precede the existing
whole-binary evaluation and packet comparison without changing either metric.

The constructor profile is opt-in and models only proved scalar/pointer members
on normal completion. It is not automatically enabled in `evaluate_cpp_ged` or
the production shim: constructor support must be qualified against source
identity, producer validity and changed CFG semantics before entering scores.
The unchanged original Joern may omit initializers; matching that omission is
not evidence of preserved effects. Parsing acceptance is never a ranking gate
by itself. The current whole-binary evaluator still checkpoints per tool;
parser qualification is independently resumable but not a per-function metric
checkpoint implementation. Large multi-image end-to-end runs and exception
semantics remain further qualification work.

## Multi-image rank after qualification

Use [the frozen cohort ranking lane](cpp-cohort-ranking.md) to turn complete
four-tool metric captures into a common-population local comparison. Its
requested-entry ledger and separate type-fact report remain available for the
improvement loop. Rank success must not hide excluded oracle coverage, producer
failures or changed expected facts. Its existing perfect-any-metric experiment
does not enable constructor semantics or promote local results to official Union.
