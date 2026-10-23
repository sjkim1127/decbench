# Native C++ signature evidence (local diagnostic)

Profile: `cpp-debug-signature-v1-diagnostic`, separate from default metrics/Union.

The earlier saved type decisions omit variable roles and return types. This
capture reads the exact original native function at each frozen requested entry,
using existing DWARF/PDB identity and companion validation. It retains formal,
local and unknown variable roles keyed by their original debug identities.
DWARF artificial flags and debug formal order are retained. PDB formal flags are
preserved without guessing their argument order from symbol emission order.

`PdbFunction.signature_type_index` retains the existing procedure type reference,
including resolution of procedure-ID records. It is optional for compatibility;
existing type/CFG logic does not consume it. Return types follow that exact TPI
procedure/member-function record, never a name-based search. DWARF returns use
the selected function DIE's type references. Missing/ambiguous native entries and
unsupported complete type graphs retain explicit exclusions.

Return recovery parses one error-free isolated output definition, including
pointer/reference declarators. Unknown types, ambiguous definitions, trailing
returns, qualified indirections, member/function pointers and aggregate returns
abstain. Existing output inspection runs first; invalid output stays in the
return oracle population with zero recovered facts. Producer parsing failures
also remain misses rather than new oracle exclusions.

## Scope

This measures **declared** scalar/pointer/reference return types, including void.
It does not validate return instructions, ordered effects or execution. Readouts
must show void and non-void populations separately. Bounded type facts preserve
the earlier two-pointer-hop contract; complete return-type agreement is also
retained separately.

Debug formal order is not a physical calling convention. Hidden aggregate result
parameters, indirect aggregate passing and `this` adjustments need further ABI
proof. `abi_slots_verified` therefore remains false. Aggregate returns abstain.
Role annotations may label the already scored variables without changing any
existing value correspondence. Actual memory-access/field-use facts remain a
separate, unimplemented lane.

## Reproduce

```sh
PYTHONPATH=. DECBENCH_NO_CACHE=1 python scripts/capture_cpp_signatures.py \
  --sample FROZEN_SAMPLE_JSON --dataset ORIGINAL_DATASET_ROOT \
  --raw FROZEN_RAW_ROOT --producers FOUR_TOOL_PRODUCER_ROOT \
  --cell CELL_ID --output /tmp/signature-cell.json
python -m pytest --no-cov tests/test_cpp_signature_evidence.py
```

Use one process per immutable cell to bound native-reader memory. The driver
does not execute binaries, invoke a decompiler or compile recovered output.
Original image, debug companion and producer-file hashes are checked; native
context reuse requires unchanged inputs. Missing producer records are empty
recovery at the fixed requested address. Duplicate identities fail evaluation.
Unexpected evaluator errors surface instead of silently shrinking coverage.

The output remains local research. No official score, ranking, producer gain,
calling-ABI qualification, dataset readiness or execution parity follows from it.
