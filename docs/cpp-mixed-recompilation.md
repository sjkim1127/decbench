# Mixed-platform C++ recompilation qualification

`scripts/run_cpp_mixed_recompile.py` is a local experimental driver. It does
not register a metric, modify legacy `byte_match`, or enter default Union.

## Population and original controls

The configuration supplies frozen image/source/TU hashes, original project
roots, explicit TU members and toolchain commands. One physical entry requires
a native declaration in an original project-owned file; system and third-party
headers do not establish ownership. Native aliases share one requested address.
Keep the complete inventory and select the configured count by a stable hash
before looking at producer outputs or control outcomes.

The producer receives an isolated stripped image and entry addresses. Original
source, DWARF and PDB stay with the evaluator. `run_cpp_whole_binary.py run`
provides supervised, checkpointed capture for Fission, Kuna, Ghidra and angr.

Compile all recorded original preprocessed TUs, then link a debug library using
the corresponding compiler/ABI. A positive control requires a unique original
and rebuilt function identity, exact native extents, complete disassembly and
equal assembly under the explicitly recorded normalization profile. Merely
compiling the TU is insufficient. Failed controls remain in the requested
population as environment/comparison qualification failures.

Linux uses an immutable Docker image. macOS uses Xcode and records compiler,
SDK and deployment versions. Windows uses a native MSVC runner with an exact
compiler file-version/SDK guard; record the runner image version and tool hashes.
A runner label is not an immutable VM image. Do not substitute clang-cl or
MinGW for MSVC. Original-TU control failures disclose remaining reproducibility
limits even when compiler version strings match.

## Bounded recovered-output profile

The initial profile compiles each unchanged producer body as C with one fixed
prefix of standard includes and pseudo-type aliases. It injects no oracle
prototypes, fields, signatures or function bodies and performs no diagnostic
repair. Every producer uses the same prefix within each platform. This is
deliberately **not** the legacy `compile_with_fixup` profile.

All four adapters describe their output as C-like pseudocode with partial
declarations. A C compiler rejecting namespace calls or missing declarations
does not establish malformed C++, nor does it establish a decompiler defect.
Reports retain the producer language contract and bounded source findings;
unresolved dialect/context failures stay explicitly unresolved. These results
are qualification diagnostics, not a fair general decompiler quality ranking.

Recovered objects must match the original format/architecture. ELF uses a
unique function symbol and bounded size; Mach-O requires symbol/DWARF agreement;
COFF requires a unique symbol plus a CodeView procedure length whose relocation
fields refer to that same symbol. All comparisons require complete decoding.
Do not take an entire multi-function text section as a function.

## Four result categories

| Category | Meaning |
| --- | --- |
| `environment_unsupported` | Original control, identity or exact extraction was not qualified |
| `output_compile_failure` | Qualified original, but empty/missing entry or compiler rejection under this bounded profile |
| `compiled_mismatch` | Qualified original and compiled output, but normalized assembly differs |
| `perfect_match` | Qualified original and exactly equal normalized assembly |

Each category is reported against the full frozen request count. Eligibility is
also reported separately. `perfect_match` is not literal byte equality or
execution parity. Compiler success is not execution correctness.

## Reproduction stages

```sh
export PYTHONPATH=.
python scripts/run_cpp_mixed_recompile.py plan --config CONFIG.json --output RUN
python scripts/run_cpp_whole_binary.py run --plan RUN/linux/plan.json --tool fission
# Repeat capture for every configured platform and all four tools.
python scripts/run_cpp_mixed_recompile.py controls --config CONFIG.json --output RUN --platform linux
# Native Windows transport compiles frozen TUs and recovered sources on MSVC.
python scripts/run_cpp_mixed_recompile.py compare-controls --config CONFIG.json --output RUN --platform linux
python scripts/run_cpp_mixed_recompile.py sources --config CONFIG.json --output RUN --platform linux
python scripts/run_cpp_mixed_recompile.py compile --config CONFIG.json --output RUN --platform linux
# Repeat platform stages; retain native Windows source/compile/result hashes.
python scripts/run_cpp_mixed_recompile.py report --config CONFIG.json --output RUN
```

The 2026-10-23 pilot freezes 200 Snappy O0 entries across Linux AArch64 (67),
Windows x86-64 (67) and macOS arm64 (66). It controls project/optimization while
varying platform, architecture and compiler together; it does not isolate their
individual causal effects or represent the whole C++ corpus. Detailed commands,
toolchain evidence and raw results are retained in the local validation bundle.

## Experimental evidence and declaration profiles

The default remains `legacy` normalization with the minimal fixed C scaffold.
The opt-in `relocation-v2` and `producer-context-v2` profiles live in
`scripts/cpp_recompile_support.py`; neither changes a registered metric, cache
generation, published result, or Union. Report both profiles separately: changing
the comparison or declaration policy is not a decompiler improvement.

### Native comparison evidence

`relocation-v2` preserves ARM64 branch registers, tested bits and local destination
offsets. An instruction stream must decode completely. Page/address consumers
are normalized only with unique native symbol, import-slot, or format-declared
Mach-O C-string evidence. Track page producers within basic blocks, invalidate
them on writes and control transfers, and preserve unknown offsets. Nonzero
Mach-O object relocation addends are not guessed. Calls retain the legacy
external-target blindness; this remains an assembly-shape diagnostic, not a
proof of equal effects, call targets or execution.

For Windows, original and rebuilt PDB entries join on full procedure name,
proven translation unit, source file and first line. The TU proof binds original
compile commands, module paths, frozen preprocessing source maps and TU hashes
to the native runner's object commands. A differing first line can join only
inside the same unique, error-free, non-template qualified source definition.
Short-name, lowest-address and cross-image same-address fallbacks are forbidden.
Known missing evidence is explicit; unexpected evaluator errors propagate.

### Producer-only declarations

Use `declaration_profile: producer-context-v2` and each platform's
`context_result_root` to read authenticated outputs from the same tool, version,
stripped image and capture contract. Supplemental whole-image captures provide
declarations only and do not enlarge the frozen scoring population. Require
unique addresses and consensus printed signatures. Source and debug types never
supply recovered prototypes, layouts or bodies. Existing known-library
prototypes are allowed only without a conflicting producer signature.

Parsed ordinary qualified names may be transported bijectively to stable C
identifiers. Preserve strings and comments; unsupported operators, templates,
implicit class scope and invalid output are not repaired. Incomplete forward
types may describe emitted pointers only, without guessed fields, sizes or
by-value layouts. This profile is bounded to the qualified 64-bit ABIs. Unknown
calls fail compilation (`-Werror=implicit-function-declaration` or MSVC
`/we4013`); do not let an implicit `int` prototype manufacture a comparison.

The mixed Snappy pilot increased positive original controls from 125 to 187 of
the same 200 requested entries (Linux 54/67, Windows 67/67, macOS 66/66), without
losing an old control. Thirteen Linux data-reference cases remain unqualified.
This is evaluator coverage, not broader C++ qualification.

Strict declaration context also introduces losses that must stay visible.
Against normalization alone on the common 187 eligible entries, Fission loses
33 compilations, Kuna 3, Ghidra 4 and angr 10; missing or conflicting context is
not automatically an output defect. Ghidra loses one previous perfect match
because an explicit pointer prototype changes independent argument-load order.
Other matches increase, but that loss must not be hidden or special-cased away.
Retain minimal-scaffold, normalization-only and full-context reports, with
per-row transitions, so policy changes remain distinguishable from tool changes.

## Caller-owned declarations (`caller-contract-v3`)

This separate opt-in declaration profile preserves producer declarations when
supplemental callee output disagrees. An emitted declaration is part of the
caller's translation unit; another function's recovered signature is additional
evidence, not authority to override that declaration. The v2 profile is retained.

`scripts/cpp_call_contracts.py` records call spans, argument counts, visible
lexical bindings, declaration text and scope, and supplemental prototype arity.
It distinguishes direct functions, objects/function pointers, macros, indirect
expressions, missing context and incomplete parsing. An empty C declaration
argument list `f()` is **unspecified**, not a zero-argument prototype or evidence
of correct argument recovery. Variadic minimum arity is recorded separately.
Arity agreement alone never proves type or ABI compatibility.

File-scope prototype injection is withheld for any name bound anywhere in the
caller, even when that binding is not visible at a particular call. This avoids
introducing a different conflict elsewhere; it does not resolve the unbound
call. Incomplete parsing also withholds external injection. Existing macros and
compiler builtins are not replaced. Caller declarations, argument expressions,
casts and bodies are preserved. Native compiler rejection remains a result.
Cross-output disagreements stay in `declaration_evidence.call_contracts` even
when the local translation unit compiles.

On the fixed mixed-platform 200-entry pilot, 32 of the 33 Fission compilation
losses introduced by v2's supplemental declarations compile again under v3.
The remaining Windows output has unresolved `va_start` context. Kuna loses one
previous compiled mismatch because an incomplete parse cannot establish that
external injection is safe. Prior perfect matches are all retained; perfect
counts stay Fission 1, Kuna 19, Ghidra 9 and angr 8. This is an evaluator-policy
comparison, not a decompiler-quality improvement. The same 187 original controls
remain eligible and no registered metric or Union is changed.
