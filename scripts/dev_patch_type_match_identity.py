#!/usr/bin/env python3
"""Apply the staged C++ address-identity migration to type_match.py.

This is a branch-local development harness: CI applies the patch to its checkout
and validates it before the generated full file is committed back to the branch.
"""

from __future__ import annotations

import argparse
from pathlib import Path

TARGET = Path("decbench/metrics/type_match.py")


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match, found {count}: {old[:80]!r}")
    return text.replace(old, new, 1)


def patch(text: str) -> str:
    text = replace_once(text, '    cache_version = "6"', '    cache_version = "7"')

    text = replace_once(
        text,
        "    return result\n\n\ndef _parse_function_die",
        '''    return result\n\n\ndef extract_ground_truth_types_by_address(\n    binary_path: Path,\n) -> dict[int, list[dict[str, Any]]]:\n    """Extract DWARF variable ground truth keyed by concrete function address.\n\n    This is the collision-safe companion to :func:`extract_ground_truth_types`.\n    It intentionally keeps the legacy name-keyed extractor for compatibility,\n    while allowing C++ overloads and same-named methods to remain distinct.\n    """\n    from decbench.utils import binfmt\n\n    result: dict[int, list[dict[str, Any]]] = {}\n\n    try:\n        dwarfinfo = binfmt.dwarf_info(binary_path)\n        if dwarfinfo is None:\n            return result\n\n        for CU in dwarfinfo.iter_CUs():\n            top_DIE = CU.get_top_DIE()\n            for DIE in top_DIE.iter_children():\n                if DIE.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in DIE.attributes:\n                    continue\n\n                _func_name, variables = _parse_function_die(DIE, dwarfinfo)\n                if variables:\n                    result[int(DIE.attributes["DW_AT_low_pc"].value)] = variables\n\n    except Exception as e:\n        logger.warning(\n            "Failed to extract address-keyed DWARF types from %s: %s",\n            binary_path,\n            e,\n        )\n\n    return result\n\n\ndef _parse_function_die''',
    )

    text = replace_once(
        text,
        '        self._ground_truth_cache: dict[str, dict[str, list[dict[str, Any]]]] = {}',
        '''        self._ground_truth_cache: dict[str, dict[str, list[dict[str, Any]]]] = {}\n        self._ground_truth_address_cache: dict[\n            str, dict[int, list[dict[str, Any]]]\n        ] = {}''',
    )

    text = replace_once(
        text,
        '''        if cache_key in self._ground_truth_cache:\n            gt_types = self._ground_truth_cache[cache_key]\n        else:\n            gt_types = extract_ground_truth_types(binary_path)\n            self._ground_truth_cache[cache_key] = gt_types\n\n        if not gt_types:\n            logger.warning(\n                "No DWARF ground truth types for %s. " "Binary may not have been compiled with -g.",\n                binary_path,\n            )\n\n        binary_shift = self._calibrate_binary_shift(decompilation, gt_types)\n\n        for func_name, func_decomp in decompilation.functions.items():\n            try:\n                gt_vars = gt_types.get(func_name, [])\n                if not gt_vars:\n                    continue\n\n                value = self.compute_for_function(\n                    func_decomp,\n                    ground_truth_vars=gt_vars,\n                    calibration_shift=binary_shift,\n                )\n                function_results[func_name] = value\n\n            except Exception as e:\n                errors.append(f"{func_name}: {str(e)}")''',
        '''        if cache_key in self._ground_truth_cache:\n            gt_types = self._ground_truth_cache[cache_key]\n        else:\n            gt_types = extract_ground_truth_types(binary_path)\n            self._ground_truth_cache[cache_key] = gt_types\n\n        if cache_key in self._ground_truth_address_cache:\n            gt_types_by_address = self._ground_truth_address_cache[cache_key]\n        else:\n            gt_types_by_address = extract_ground_truth_types_by_address(binary_path)\n            self._ground_truth_address_cache[cache_key] = gt_types_by_address\n\n        if not gt_types and not gt_types_by_address:\n            logger.warning(\n                "No DWARF ground truth types for %s. " "Binary may not have been compiled with -g.",\n                binary_path,\n            )\n\n        binary_shift = self._calibrate_binary_shift(\n            decompilation, gt_types, gt_types_by_address\n        )\n\n        for storage_key, func_decomp in decompilation.functions.items():\n            try:\n                gt_vars = gt_types_by_address.get(func_decomp.address, [])\n                if not gt_vars:\n                    gt_vars = gt_types.get(func_decomp.name, [])\n                if not gt_vars:\n                    continue\n\n                value = self.compute_for_function(\n                    func_decomp,\n                    ground_truth_vars=gt_vars,\n                    calibration_shift=binary_shift,\n                )\n                function_results[storage_key] = value\n\n            except Exception as e:\n                errors.append(f"{storage_key}: {str(e)}")''',
    )

    text = replace_once(
        text,
        '''    def _calibrate_binary_shift(\n        decompilation: DecompilationResult,\n        gt_types: dict[str, list[dict[str, Any]]],\n    ) -> int | None:\n        """Calibrate the offset shift across all functions of a binary.\n\n        Gathers per-function (ground-truth, decompiled) stack offset sets and\n        finds the single additive shift that aligns them best across the\n        binary. Returns ``None`` when there is nothing to calibrate against.\n        """\n        pairs: list[tuple[list[int], list[int]]] = []\n\n        for func_name, func_decomp in decompilation.functions.items():\n            gt_vars = gt_types.get(func_name, [])\n            if not gt_vars:\n                continue\n            func_gt = [o for gv in gt_vars for o in gv.get("rbp_offset", [])]\n            func_dec = [\n                o for o in (_effective_offset(v) for v in func_decomp.variables) if o is not None\n            ]\n            if func_gt and func_dec:\n                pairs.append((func_gt, func_dec))\n\n        return _calibrate_shift_multi(pairs)''',
        '''    def _calibrate_binary_shift(\n        decompilation: DecompilationResult,\n        gt_types: dict[str, list[dict[str, Any]]],\n        gt_types_by_address: dict[int, list[dict[str, Any]]],\n    ) -> int | None:\n        """Calibrate the offset shift across all functions of a binary.\n\n        Address-keyed ground truth is preferred so C++ overloads do not share a\n        calibration payload. The legacy name map remains a fallback for old or\n        unusual artifacts where an address cannot be resolved.\n        """\n        pairs: list[tuple[list[int], list[int]]] = []\n\n        for _storage_key, func_decomp in decompilation.functions.items():\n            gt_vars = gt_types_by_address.get(func_decomp.address, [])\n            if not gt_vars:\n                gt_vars = gt_types.get(func_decomp.name, [])\n            if not gt_vars:\n                continue\n            func_gt = [o for gv in gt_vars for o in gv.get("rbp_offset", [])]\n            func_dec = [\n                o for o in (_effective_offset(v) for v in func_decomp.variables) if o is not None\n            ]\n            if func_gt and func_dec:\n                pairs.append((func_gt, func_dec))\n\n        return _calibrate_shift_multi(pairs)''',
    )

    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    original = TARGET.read_text()
    patched = patch(original)
    TARGET.write_text(patched)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(patched)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
