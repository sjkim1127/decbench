#!/usr/bin/env python
"""One-shot branch helper for the canonical C++ identity migration."""

from pathlib import Path


def patch_run_benchmark() -> None:
    path = Path("scripts/run_benchmark.py")
    text = path.read_text()
    start = text.index("def _relabel_to_dwarf(")
    end = text.index("\n\ndef _timed_decompile(", start)
    replacement = '''def _relabel_to_dwarf(
    result: DecompilationResult, addr2name: dict[int, str], unstripped: Path
) -> None:
    """Canonicalize stripped-binary results against the full DWARF target set.

    ``addr2name`` is the benchmark universe for this binary: every requested
    source function keyed by its DWARF ``low_pc``. Storage identity is derived
    from that complete set, not from whichever subset one decompiler happened
    to recover. A source name that is ambiguous anywhere in the target set
    therefore always uses ``<name>@0x<low_pc>``.

    Backend addresses are normalized back to the canonical DWARF ``low_pc``
    (including historical PE-RVA and Thumb-bit variants), so address-keyed
    metrics and source recovery consume the same identity primitive. Output
    that cannot be mapped to a requested target is outside the gated benchmark
    universe and is dropped.
    """
    from decbench.decompilers.raw import common

    base = common.elf_min_vaddr(unstripped)

    name_counts: dict[str, int] = {}
    for target_name in addr2name.values():
        name_counts[target_name] = name_counts.get(target_name, 0) + 1
    ambiguous_names = {name for name, count in name_counts.items() if count > 1}

    def storage_key(name: str, address: int) -> str:
        if name in ambiguous_names:
            return f"{name}@0x{address:x}"
        return name

    def dwarf_target(raw_address: int) -> tuple[int, str] | None:
        candidates = (
            raw_address,
            raw_address & ~1,
            raw_address + base,
            (raw_address + base) & ~1,
        )
        seen: set[int] = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            target_name = addr2name.get(candidate)
            if target_name is not None:
                return candidate, target_name
        return None

    new_funcs: dict[str, object] = {}
    recovered_targets: set[int] = set()
    dropped_unmapped = 0

    for fd in list(result.functions.values()):
        target = dwarf_target(int(fd.address))
        if target is None:
            dropped_unmapped += 1
            continue

        target_address, target_name = target
        recovered_targets.add(target_address)
        old_name = fd.name
        if target_name != old_name:
            fd.decompiled_code = re.sub(
                r"\\b" + re.escape(old_name) + r"\\b",
                target_name,
                fd.decompiled_code,
            )
        fd.name = target_name
        fd.address = target_address

        key = storage_key(target_name, target_address)
        previous = new_funcs.get(key)
        if previous is None or len(fd.decompiled_code or "") >= len(
            getattr(previous, "decompiled_code", "") or ""
        ):
            new_funcs[key] = fd

    result.functions = new_funcs  # type: ignore[assignment]

    was_all_failure = result.decompiler.failed_functions == ["all"]
    missing = [
        storage_key(addr2name[address], address)
        for address in sorted(addr2name)
        if address not in recovered_targets
    ]
    if not (was_all_failure and not recovered_targets):
        result.decompiler.failed_functions = missing

    result.decompiler.extra = {
        **(result.decompiler.extra or {}),
        "function_identity": "dwarf-low-pc",
        "ambiguous_source_names": len(ambiguous_names),
        "dropped_unmapped_functions": dropped_unmapped,
    }
    result.binary_path = unstripped
'''
    path.write_text(text[:start] + replacement + text[end:])


def patch_source_extract() -> None:
    path = Path("decbench/utils/source_extract.py")
    text = path.read_text()
    needle = '''    if binary_path is None:\n        return None, "binary_not_found"\n    binary_path = Path(binary_path)\n'''
    replacement = '''    # Report/evaluation layers may carry DecBench's canonical storage key\n    # instead of the semantic source name. Decode it here so existing callers\n    # automatically get address-aware C++ source recovery.\n    if func_address is None:\n        storage_match = re.fullmatch(r"(.+)@0x([0-9a-fA-F]+)", func_name)\n        if storage_match is not None:\n            func_name = storage_match.group(1)\n            func_address = int(storage_match.group(2), 16)\n\n    if binary_path is None:\n        return None, "binary_not_found"\n    binary_path = Path(binary_path)\n'''
    if needle not in text:
        raise RuntimeError("source_extract insertion point not found")
    path.write_text(text.replace(needle, replacement, 1))


def patch_identity_workflow() -> None:
    path = Path(".github/workflows/cpp-function-identity-probe.yml")
    text = path.read_text()

    if "      - scripts/run_benchmark.py\n" not in text:
        text = text.replace(
            "      - scripts/probe_cpp_function_identity.py\n",
            "      - scripts/probe_cpp_function_identity.py\n      - scripts/run_benchmark.py\n",
            1,
        )
    if "      - tests/test_run_benchmark_identity.py\n" not in text:
        text = text.replace(
            "      - tests/test_function_identity.py\n",
            "      - tests/test_function_identity.py\n      - tests/test_run_benchmark_identity.py\n",
            1,
        )

    compile_marker = "            decbench/metrics/type_match.py\n"
    if "            scripts/run_benchmark.py\n" not in text:
        text = text.replace(
            compile_marker,
            "            decbench/metrics/type_match.py \\\n            scripts/run_benchmark.py\n",
            1,
        )

    text = text.replace(
        "      - name: Lint touched Python files\n        continue-on-error: true\n",
        "      - name: Lint touched Python files\n",
        1,
    )

    lint_marker = "            tests/test_function_identity.py\n"
    if "            tests/test_run_benchmark_identity.py\n" not in text:
        text = text.replace(
            lint_marker,
            "            tests/test_function_identity.py \\\n            tests/test_run_benchmark_identity.py\n",
            1,
        )

    focused_marker = "            tests/test_models.py\n"
    if "            tests/test_models.py \\\n            tests/test_run_benchmark_identity.py\n" not in text:
        text = text.replace(
            focused_marker,
            "            tests/test_models.py \\\n            tests/test_run_benchmark_identity.py\n",
            1,
        )

    path.write_text(text)


def main() -> None:
    patch_run_benchmark()
    patch_source_extract()
    patch_identity_workflow()


if __name__ == "__main__":
    main()
