# Native call identity and declared facts

Local profile `cpp-native-call-and-declared-facts-v1-diagnostic` is implemented
by `scripts/evaluate_cpp_native_facts.py` and `scripts/cpp_native_call_facts.py`.
It does not register a metric or modify existing C results, caches or Union.

## Native identity

A frozen requested function must have one physical native debug entry, an exact
executable extent and complete instruction decoding. The stripped and debug
images must have identical executable regions. Read encoded direct call targets
from instructions. An exact target is accepted only if one native entry exists
there and the existing native-code resolver proves an instruction start.
Indirect calls, ambiguous/ICF entries, unproved stubs and missing target extents
stay explicit. No display-name, nearest-address or argument-count fallback is
permitted. Tail branches are not silently counted as calls.

A producer call can link to native code only when an unscoped line mapping
covers that call's byte span and points to exactly one native call instruction.
Every candidate claimant participates in ambiguity checks, including rows with
multiple candidates or invalid mappings. A shared PC is not assigned to one
convenient occurrence. Variable-definition-scoped maps are never used to infer
call identity. Invalid producer outputs remain requested but cannot earn links.

A uniquely linked target can select another output from the **same producer and
capture contract** at that exact address. The printed target header's arity can
then be compared as a cross-output diagnostic. Native declared formal evidence
is separately recorded. None of this proves that a producer's line-mapping
assertion is semantically correct, or certifies recovered physical ABI slots.

## Declared signature and field facts

Existing native DWARF/PDB readers and type graphs supply declared returns and
parameters at an exact entry. Return availability is independent of parameter
support: unavailable PDB member-parameter lowering does not erase a readable
return type. Unexpected evaluator errors propagate; recognized unsupported
native evidence retains a per-dimension exclusion.

Parameter correspondence uses declaration order only for a bounded fixed,
nonmember, nonartificial scalar/pointer subset with a supported return. It does
not match by type/name/size. Hidden aggregate returns, variadics, inherited
formal populations and unusual calling conventions require further evidence.
Unknown recovered types, parameter-count disagreements and invalid output remain
misses within a known oracle fact population. Do not drop them from denominators.

Facts reuse `cpp_type_facts`: kind, size, bounded pointees and declared fields at
fixed bit offsets. Graph gaps remain explicit. Field declarations do not prove
that a field was accessed. Native memory operands are counted as unbound; this
profile does not associate a register with a runtime object or a field. Reports
must retain `abi_slots_verified=false`, `actual_field_access_verified=false`
and `execution_parity=false`. Void and nonvoid return populations are reported
separately; these facts are not combined into an official ranking.

## Reproduction contract

```sh
PYTHONPATH=. DECBENCH_NO_CACHE=1 python scripts/evaluate_cpp_native_facts.py \
  --plan FROZEN_PLAN.json --output NEW_RESULT.json
```

One immutable image is evaluated per subprocess. Plans include original/stripped
hashes, every requested address and either authenticated capture completion or
explicit normalized-output hashes. The optional `context_root` is same-image,
same-version, same-configuration producer output; it supplies target headers,
not extra scored functions. Saved raw captures can be reingested with input
hashes and adapter hashes, without invoking a decompiler again. This must not be
presented as a fresh current-main run.

The worker freezes local script and default package hashes before extraction,
checks every evidence hash at the end, writes the complete result and exits
without a large cyclic-debug-index teardown. A completed result is not a test
suite, execution validation, full C++ qualification or release gate.


## Optional Fission call-only scope

The local producer prototype adds `call_site` to a line mapping, with an empty
`defined_variables` list and exactly its instruction PC in `addresses`. This
scope is independent of variable definitions. Old producers and serialization
remain supported with no call scope. Native validation and unique AST occurrence
ownership remain mandatory; cloned/shared claims do not earn multiple links.
No printed-name or nearest-PC fallback is introduced.

The adapter also retains optional `type_shape` observations as metadata. These
are partial inferred layouts (`layout_complete: false`), outside the default
metrics and full-object C++ policy. Their presence alone grants no field or
object credit and does not verify a memory-access occurrence.

The same-source Fission baseline/candidate replay and byte audit for the frozen
200-entry mixed-platform Snappy O0 cohort are retained under
`Fission/benchmark/artifacts/fission-call-provenance/2026-10-24`. This transport
experiment does not refresh the earlier four-tool ranking, recompile outputs,
prove execution parity, or modify published Union.
