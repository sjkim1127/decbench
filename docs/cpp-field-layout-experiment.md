# Experimental C++ field-layout projection

Status: local proposal, unregistered and outside all default metrics and Union.
Profile: `cpp-field-layout-v1-experimental`.

## Question and contract

Can an explicitly recovered flat C record earn storage-layout agreement with an
oracle that represents the same typed fields using nested records or ordinary
inheritance? Existing source and ABI graph views retain base/field boundaries.
This experiment projects each side independently, after frozen type-blind
variable correspondence. Oracle facts never fill missing recovered definitions.

The projection expands fixed-offset record members and ordinary bases into leaf
fields with absolute bit offsets. It preserves whole-object size, scalar kind
and width, pointer depth and recursive pointees, and array count/element stride.
Each expanded member retains its original edge-index path in separate evidence.
Names, cv qualifiers, source integer ranks and base/member grouping do not take
part in this comparison. The original source graph remains available unchanged.

Supported pointers require an explicit LP64, LLP64 or ILP32 width. This data-model
selection is **not** a complete target calling-convention or alignment profile.
Union, bitfield, virtual/computed/vptr storage, empty/opaque records and overlapping
member/base spans are excluded conservatively. Tail-padding reuse is therefore
not supported. Arrays remain arrays rather than a list of ordinary fields.
Explicit producer padding arrays remain fields, not guessed compiler padding.
The graph and expanded leaf populations are bounded.

## What agreement means

Agreement establishes only equivalence under this field-layout projection. It
does not establish source type identity, alignment equality, effective-type or
aliasing compatibility, constructor/destructor/exception behavior, calling ABI,
or executable equivalence. Same-size objects, erased `void *` pointees and opaque
byte buffers cannot substitute for complete typed fields.

The current graph does not transport alignment. No compilable C header with
certified layout is emitted. A future C exporter needs target alignment, packing
and representability evidence plus compiler layout controls. Function signatures
also need separate `this`, aggregate passing and hidden-result ABI evidence.

## Local replay

`scripts/audit_cpp_field_layout.py --reports SAVED_CELL_REPORTS --output NEW_JSON`
consumes frozen four-tool source/ABI decision reports. Run from the repository
with `PYTHONPATH=.`. It hashes inputs and preserves addresses, correspondence,
invalid-output verdicts, storage-width failures and missing recovery. It requires
the same oracle graphs and population across all four tools. Unsupported oracle
layouts are explicit new exclusions shared by every producer; unsupported
recovery stays a miss. Original results and original eligibility are retained
alongside the supported layout subset. This is not a fresh native-oracle or
decompiler run, nor an official score or tool improvement.

Tests include an actual Clang-generated ELF/DWARF inheritance/flat-record control,
recursive pointers, nesting, arrays, incorrect field types/offsets/extents, bounded
expansion and unsupported layout cases. The compiler fixture is compiled only.

No existing metric algorithm/cache generation, adapter, Rust-Joern dependency,
dataset qualification flag, public result overlay or website is changed.
