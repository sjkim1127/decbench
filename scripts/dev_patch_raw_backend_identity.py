#!/usr/bin/env python3
"""Stage collision-safe function identity across raw decompiler backends.

Branch-local validation harness.  It rewrites only the small name-keyed selection
and storage sites that lose C++ overloads; the generated files are committed only
after CI validates them.
"""

from __future__ import annotations

from pathlib import Path

FILES = {
    name: Path("decbench/decompilers/raw") / name
    for name in (
        "angr_raw.py",
        "binja_raw.py",
        "ida_raw.py",
        "kuna_raw.py",
        "glaurung_raw.py",
        "dewolf_raw.py",
        "manifold_raw.py",
    )
}


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}: {old[:100]!r}")
    return text.replace(old, new, 1)


def add_identity_import(text: str, *, label: str) -> str:
    marker = ")\n\n_l = logging.getLogger(__name__)"
    replacement = ")\nfrom decbench.utils.function_identity import insert_function\n\n_l = logging.getLogger(__name__)"
    return replace_once(text, marker, replacement, label=f"{label}: import")


def patch_angr(text: str) -> str:
    text = add_identity_import(text, label="angr")
    return replace_once(
        text,
        "                    decompiled_functions[func_name] = func_result",
        "                    insert_function(decompiled_functions, func_result)",
        label="angr: storage",
    )


def patch_binja(text: str) -> str:
    text = add_identity_import(text, label="binja")
    text = replace_once(
        text,
        '''            if functions is not None:\n                requested = {n for (n, _a) in functions}\n                enumerated = [(n, a) for (n, a) in enumerated if n in requested]''',
        '''            if functions is not None:\n                requested_addrs = {a for (_n, a) in functions}\n                enumerated = [(n, a) for (n, a) in enumerated if a in requested_addrs]''',
        label="binja: requested filter",
    )
    return replace_once(
        text,
        "                    decompiled_functions[func_name] = func_result",
        "                    insert_function(decompiled_functions, func_result)",
        label="binja: storage",
    )


def patch_ida(text: str) -> str:
    text = add_identity_import(text, label="ida")
    text = replace_once(
        text,
        '''                if functions is not None:\n                    requested = {n for (n, _a) in functions}\n                    enumerated = [(n, a) for (n, a) in enumerated if n in requested]''',
        '''                if functions is not None:\n                    requested_addrs = {a for (_n, a) in functions}\n                    enumerated = [(n, a) for (n, a) in enumerated if a in requested_addrs]''',
        label="ida: requested filter",
    )
    return replace_once(
        text,
        "                        decompiled_functions[func_name] = func_result",
        "                        insert_function(decompiled_functions, func_result)",
        label="ida: storage",
    )


def patch_dewolf(text: str) -> str:
    text = add_identity_import(text, label="dewolf")
    text = replace_once(
        text,
        '''        target_addrs = sorted(\n            a for a in (function_names or set()) if isinstance(a, int) and not isinstance(a, bool)\n        )''',
        '''        if functions is not None:\n            target_addrs = sorted({a for (_n, a) in functions})\n        else:\n            target_addrs = sorted(\n                a\n                for a in (function_names or set())\n                if isinstance(a, int) and not isinstance(a, bool)\n            )''',
        label="dewolf: requested addresses",
    )
    return replace_once(
        text,
        "                            decompiled_functions[name] = fd",
        "                            insert_function(decompiled_functions, fd)",
        label="dewolf: storage",
    )


def patch_kuna(text: str) -> str:
    text = add_identity_import(text, label="kuna")
    old = '''        records = {str(r.get("name") or ""): r for r in self._records(payload)}\n        enumerated = sorted(\n            (\n                (n, int(r.get("address") or 0))\n                for n, r in records.items()\n                if not common.should_skip_function(\n                    n, int(r.get("address") or 0), text_range, addr_targets\n                )\n            ),\n            key=lambda x: x[1],\n        )\n        if functions is not None:\n            requested = {n for (n, _a) in functions}\n            enumerated = [(n, a) for (n, a) in enumerated if n in requested]'''
    new = '''        records = list(self._records(payload))\n        records_by_address = {int(r.get("address") or 0): r for r in records}\n        enumerated = sorted(\n            (\n                (str(r.get("name") or ""), int(r.get("address") or 0))\n                for r in records\n                if not common.should_skip_function(\n                    str(r.get("name") or ""),\n                    int(r.get("address") or 0),\n                    text_range,\n                    addr_targets,\n                )\n            ),\n            key=lambda x: x[1],\n        )\n        if functions is not None:\n            requested_addrs = {a for (_n, a) in functions}\n            enumerated = [(n, a) for (n, a) in enumerated if a in requested_addrs]'''
    text = replace_once(text, old, new, label="kuna: record index")
    text = replace_once(
        text,
        "                fd = self._build_function(records[func_name], func_name, file_addr)",
        "                fd = self._build_function(records_by_address[file_addr], func_name, file_addr)",
        label="kuna: record lookup",
    )
    return replace_once(
        text,
        "                decompiled[func_name] = fd",
        "                insert_function(decompiled, fd)",
        label="kuna: storage",
    )


def patch_glaurung(text: str) -> str:
    text = add_identity_import(text, label="glaurung")
    old = '''        # 2. Index by name, filter to the benchmarkable + source-narrowed set.\n        by_name = {str(r.get("name") or ""): r for r in records}\n        enumerated = sorted(\n            (\n                (n, int(r.get("entry_va") or 0))\n                for n, r in by_name.items()\n                if not common.should_skip_function(n, int(r.get("entry_va") or 0), text_range)\n            ),\n            key=lambda x: x[1],\n        )\n        if functions is not None:\n            requested = {n for (n, _a) in functions}\n            enumerated = [(n, a) for (n, a) in enumerated if n in requested]'''
    new = '''        # 2. Index by address, filter to the benchmarkable + source-narrowed set.\n        by_address = {int(r.get("entry_va") or 0): r for r in records}\n        enumerated = sorted(\n            (\n                (str(r.get("name") or ""), int(r.get("entry_va") or 0))\n                for r in records\n                if not common.should_skip_function(\n                    str(r.get("name") or ""), int(r.get("entry_va") or 0), text_range\n                )\n            ),\n            key=lambda x: x[1],\n        )\n        if functions is not None:\n            requested_addrs = {a for (_n, a) in functions}\n            enumerated = [(n, a) for (n, a) in enumerated if a in requested_addrs]'''
    text = replace_once(text, old, new, label="glaurung: record index")
    text = replace_once(
        text,
        "                fd = self._build_function(by_name[func_name], func_name, file_addr)",
        "                fd = self._build_function(by_address[file_addr], func_name, file_addr)",
        label="glaurung: record lookup",
    )
    return replace_once(
        text,
        "                decompiled[func_name] = fd",
        "                insert_function(decompiled, fd)",
        label="glaurung: storage",
    )


def patch_manifold(text: str) -> str:
    text = add_identity_import(text, label="manifold")
    text = replace_once(
        text,
        '''        decompiled_functions: dict[str, FunctionDecompilation] = {}\n        unaddressed: list[str] = []\n        symbols: dict[str, int] | None = None''',
        '''        decompiled_functions: dict[str, FunctionDecompilation] = {}\n        unaddressed: list[str] = []\n        symbols: dict[str, int] | None = None\n        requested_addrs = {a for (_n, a) in functions} if functions is not None else None''',
        label="manifold: requested addresses",
    )
    old_assign = '''            if common.should_skip_function(name, file_addr, text_range):\n                continue\n            decompiled_functions[name] = FunctionDecompilation(\n                name=name,\n                address=file_addr,\n                decompiled_code=code,\n                line_count=len(code.splitlines()),\n                metadata=common.extract_metrics(code),\n            )'''
    new_assign = '''            if requested_addrs is not None and file_addr not in requested_addrs:\n                continue\n            if common.should_skip_function(name, file_addr, text_range):\n                continue\n            insert_function(\n                decompiled_functions,\n                FunctionDecompilation(\n                    name=name,\n                    address=file_addr,\n                    decompiled_code=code,\n                    line_count=len(code.splitlines()),\n                    metadata=common.extract_metrics(code),\n                ),\n            )'''
    text = replace_once(text, old_assign, new_assign, label="manifold: storage")
    old_narrow = '''        kept = common.narrow_to_source(\n            [(n, fd.address) for n, fd in decompiled_functions.items()],\n            function_names,\n            backend="manifold",\n            binary_name=binary_path.name,\n        )\n        keep_names = {n for n, _ in kept}\n        decompiled_functions = {n: fd for n, fd in decompiled_functions.items() if n in keep_names}'''
    new_narrow = '''        kept = common.narrow_to_source(\n            [(fd.name, fd.address) for fd in decompiled_functions.values()],\n            function_names,\n            backend="manifold",\n            binary_name=binary_path.name,\n        )\n        keep_addrs = {a for _n, a in kept}\n        decompiled_functions = {\n            key: fd for key, fd in decompiled_functions.items() if fd.address in keep_addrs\n        }'''
    return replace_once(text, old_narrow, new_narrow, label="manifold: narrowing")


PATCHERS = {
    "angr_raw.py": patch_angr,
    "binja_raw.py": patch_binja,
    "ida_raw.py": patch_ida,
    "kuna_raw.py": patch_kuna,
    "glaurung_raw.py": patch_glaurung,
    "dewolf_raw.py": patch_dewolf,
    "manifold_raw.py": patch_manifold,
}


def main() -> int:
    for name, path in FILES.items():
        original = path.read_text()
        patched = PATCHERS[name](original)
        path.write_text(patched)
        print(f"patched {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
