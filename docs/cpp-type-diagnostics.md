# C++ type diagnosis: coverage, facts and exact agreement

Local experimental profile: `cpp-declared-type-facts-v1-diagnostic`. It is not
registered as a DecBench metric and never contributes to default scores or Union.

## Three numbers

1. **Oracle coverage:** eligible functions / all requested functions. Preserve
   every earlier oracle exclusion and its exact reason; an unsupported evaluator
   policy is not automatically defective dataset evidence.
2. **Declared-type fact recall:** correctly recovered facts / the same known
   oracle facts for every producer. Unmatched variables, missing type recovery,
   invalid output and inconsistent storage widths remain in this denominator.
3. **Strict function agreement:** preserve the existing source and ABI type
   perfect counts. Do not replace them with partial-fact perfection.

No facts over an empty eligible population means **unmeasurable**, not zero.
Per-dimension counts, root-variable counts and macro function recall accompany
micro fact recall so deeply nested objects do not invisibly change the weighting.

## Facts and bounds

Each typed fact has an anonymous structural path, attribute and value. Assess
type kind (including signed/unsigned), storage width, array count/stride and
fixed declared field offsets/types. References project to pointer storage and
enums to their underlying type, following the existing experimental ABI view.
Record/base grouping is flattened only at fixed, unambiguous offsets. Names,
sizes and types never choose variable correspondence; field positions use
offsets rather than field types. A recovered integer with the correct width can
earn width credit while still failing pointer-kind and pointee facts.

Graphs are expanded independently through at most **two pointer hops**. This
finite unfolding avoids using local graph IDs, sharing or recursive typedef
representation as type evidence. Arrays retain their boundaries and are not
expanded once per element. Graph/fact/work bounds prevent exponential expansion.
Special/unlocated/overlapping/empty record members and union alternatives produce
explicit fact gaps while retaining independently known enclosing kind/width.
Unknown facts never become assumptions or producer-supplied denominator changes.
Extra recovered fact slots are reported, without a claimed precision score.
Fact recall of 100% therefore does not imply complete C++ type recovery.

## Four failure classes

- `oracle_insufficient`: a recorded function exclusion. The exact reason may be
  missing/ambiguous debug evidence or unsupported oracle/evaluator policy.
- `correspondence_failure`: no type-blind source/recovered value pairing proved.
  This does not establish whether the producer or evidence extraction is at fault.
- `recovery_information_gap`: missing facts or unsupported recovered types. A
  missing declaration and evaluator parsing limitations cannot always be separated
  using saved decisions. Confirmed invalid output remains a distinct subreason.
- `type_mismatch`: different observed fact values or recorded inconsistent storage
  width. This is a type-descriptor disagreement, **not proof of an execution bug**.

`correct` retains exact agreement. `representation_difference` records an old
strict mismatch with no disagreement under this narrower fact contract. No such
case is silently promoted to a strict type-perfect function.

Oracle exclusions count functions; the other categories count variables. They
must not be added together as if they had the same unit. All identities, original
verdicts, expected/actual fact values, gaps and existing output-validator evidence
are retained in the machine-readable report.

## Reproduction and evidence limits

```sh
PYTHONPATH=. DECBENCH_NO_CACHE=1 python scripts/report_cpp_type_diagnostics.py \
  --reports SAVED_CELL_REPORTS --output /tmp/cpp-type-diagnosis.json
python -m pytest --no-cov tests/test_cpp_type_facts.py
```

The command writes JSON plus a Markdown readout, hashes the saved inputs and
checks equal requested/oracle populations, unique functions/variables,
one-to-one pairing, matching source/ABI evidence and internally consistent saved
aggregates. Unexpected evaluator failures surface rather than reducing coverage.

This first implementation consumes the existing complete-oracle decision capture.
It does not salvage partial types from the earlier excluded functions. The saved
capture does **not** retain argument/local classification, return types or actual
field-access evidence. These capabilities are marked unmeasured. Declared layout
facts cannot be presented as facts about instructions actually executed/accessed.
Compilation and execution are also marked unmeasured, not successful or failed.
An explicit future evidence transport is required for those evaluation lanes.

Original metric algorithms, cache generations, decompiler outputs, matching,
Rust-Joern, dataset flags, public overlays and website remain unchanged. This is
diagnosis of frozen output, not a current-tool leaderboard or decompiler gain.
