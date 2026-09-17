#!/usr/bin/env python3
"""Preserve legacy name-only source lookup for unqualified storage keys."""

from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match in {path}, found {count}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "decbench/scoring/report_extras.py",
    '''        func = _lookup_function_by_storage_key(\n            decompile_results, project, opt_level, binary, func_name\n        )\n        if func is not None:\n            return function_source_ex(Path(bp), func.name, func.address)\n        semantic_name, address = parse_function_storage_key(func_name)\n        return function_source_ex(Path(bp), semantic_name, address)\n''',
    '''        func = _lookup_function_by_storage_key(\n            decompile_results, project, opt_level, binary, func_name\n        )\n        semantic_name, keyed_address = parse_function_storage_key(func_name)\n        if keyed_address is not None:\n            if func is not None:\n                return function_source_ex(Path(bp), func.name, func.address)\n            return function_source_ex(Path(bp), semantic_name, keyed_address)\n\n        # Preserve the historical name-only path for unique/plain keys. Some\n        # imported or synthetic results carry a backend address that is not a\n        # usable DWARF low_pc; address disambiguation is required only when the\n        # storage key itself is collision-qualified.\n        source_name = func.name if func is not None else semantic_name\n        return function_source_ex(Path(bp), source_name)\n''',
)

with Path("tests/test_cpp_identity_end_to_end.py").open("a") as f:
    f.write(
        '''\n\ndef test_report_source_lookup_keeps_plain_unique_name_only(\n    tmp_path: Path, monkeypatch\n) -> None:\n    result = _result(tmp_path)\n    nested = {"proj": {"O2": {"fixture": {"fixture-dec": result}}}}\n    seen: list[tuple[str, int | None]] = []\n\n    def fake_source(\n        _binary_path: Path | None, func_name: str, func_address: int | None = None\n    ) -> tuple[str | None, str]:\n        seen.append((func_name, func_address))\n        return "source", "source"\n\n    monkeypatch.setattr(source_extract, "function_source_ex", fake_source)\n    source, status = report_extras._lookup_source_ex(\n        nested, "proj", "O2", "fixture", "unique"\n    )\n\n    assert (source, status) == ("source", "source")\n    assert seen == [("unique", None)]\n'''
    )
