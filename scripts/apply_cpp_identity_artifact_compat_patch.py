#!/usr/bin/env python3
"""Make legacy decompiled-C artifacts collision-safe during reload."""

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
    "decbench/utils/results_tree.py",
    '''from decbench.utils import binfmt\n''',
    '''from decbench.utils import binfmt\nfrom decbench.utils.function_identity import parse_function_storage_key\n''',
)

replace_once(
    "decbench/utils/results_tree.py",
    '''FUNCTION_MARKER = re.compile(r"^// Function: (\\S+) @ (0x[0-9a-fA-F]+)\\s*$", re.M)\n''',
    '''FUNCTION_MARKER = re.compile(r"^// Function: (.+?) @ (0x[0-9a-fA-F]+)\\s*$", re.M)\n''',
)

replace_once(
    "decbench/utils/results_tree.py",
    '''def split_functions(c_path: Path) -> dict[str, tuple[int, str]]:\n    """``name -> (address, decompiled block)`` for one decompiled ``.c`` file."""\n    text = c_path.read_text(errors="replace")\n    out: dict[str, tuple[int, str]] = {}\n    matches = list(FUNCTION_MARKER.finditer(text))\n    for i, m in enumerate(matches):\n        start = m.end()\n        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)\n        out[m.group(1)] = (int(m.group(2), 16), text[start:end].strip())\n    return out\n''',
    '''def split_functions(c_path: Path) -> dict[str, tuple[int, str]]:\n    """``storage key -> (address, decompiled block)`` for one ``.c`` artifact.\n\n    New artifacts write collision-qualified storage keys directly. Historical\n    artifacts wrote only semantic names, so if two markers share a name at\n    different addresses, upgrade both to ``<name>@0x<address>`` while reading.\n    """\n    text = c_path.read_text(errors="replace")\n    out: dict[str, tuple[int, str]] = {}\n    matches = list(FUNCTION_MARKER.finditer(text))\n    for i, m in enumerate(matches):\n        start = m.end()\n        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)\n        marker_key = m.group(1)\n        address = int(m.group(2), 16)\n        code = text[start:end].strip()\n        semantic_name, encoded_address = parse_function_storage_key(marker_key)\n\n        if encoded_address is not None:\n            out[marker_key] = (address, code)\n            continue\n\n        same_name = [\n            (key, value)\n            for key, value in out.items()\n            if parse_function_storage_key(key)[0] == semantic_name\n        ]\n        duplicate = next(\n            (key for key, (existing_address, _code) in same_name if existing_address == address),\n            None,\n        )\n        if duplicate is not None:\n            out[duplicate] = (address, code)\n            continue\n        if not same_name:\n            out[semantic_name] = (address, code)\n            continue\n\n        for key, (existing_address, existing_code) in same_name:\n            if key == semantic_name:\n                del out[key]\n                out[f"{semantic_name}@0x{existing_address:x}"] = (\n                    existing_address,\n                    existing_code,\n                )\n        out[f"{semantic_name}@0x{address:x}"] = (address, code)\n    return out\n''',
)

replace_once(
    "decbench/utils/results_tree.py",
    '''def function_addresses(c_path: Path) -> dict[str, int]:\n    """``name -> address`` parsed from a decompiled ``.c`` header (``{}`` if absent)."""\n''',
    '''def function_addresses(c_path: Path) -> dict[str, int]:\n    """``storage key -> address`` parsed from a decompiled artifact."""\n''',
)

replace_once(
    "scripts/rebuild_function_data.py",
    '''import json\nimport re\nimport sys\n''',
    '''import json\nimport sys\n''',
)

replace_once(
    "scripts/rebuild_function_data.py",
    '''from decbench.utils.function_identity import parse_function_storage_key\nfrom decbench.utils.results_tree import resolve_binary\nfrom decbench.utils.source_extract import function_source, function_source_ex\n\nMARKER = re.compile(r"^// Function: (\\S+) @ (0x[0-9a-fA-F]+)\\s*$", re.M)\nPERFECT = {"ged": 0.0, "type_match": 1.0, "byte_match": 1.0}\nPER_TIER = 100\nHARDEST_PER = 12\n\n\ndef split_functions(c_path: Path) -> dict[str, str]:\n    """name -> decompiled block for one decompiled .c (code only)."""\n    text = c_path.read_text(errors="replace")\n    out: dict[str, str] = {}\n    ms = list(MARKER.finditer(text))\n    for i, m in enumerate(ms):\n        start = m.end()\n        end = ms[i + 1].start() if i + 1 < len(ms) else len(text)\n        out[m.group(1)] = text[start:end].strip()\n    return out\n''',
    '''from decbench.utils.function_identity import parse_function_storage_key\nfrom decbench.utils.results_tree import resolve_binary, split_functions\nfrom decbench.utils.source_extract import function_source, function_source_ex\n\nPERFECT = {"ged": 0.0, "type_match": 1.0, "byte_match": 1.0}\nPER_TIER = 100\nHARDEST_PER = 12\n''',
)

replace_once(
    "scripts/rebuild_function_data.py",
    '''            cf = self.root / opt / proj / "decompiled" / f"{dec}_{stem}.c"\n            self._dec_cache[key] = split_functions(cf) if cf.exists() else {}\n''',
    '''            cf = self.root / opt / proj / "decompiled" / f"{dec}_{stem}.c"\n            blocks = split_functions(cf) if cf.exists() else {}\n            self._dec_cache[key] = {\n                storage_key: code for storage_key, (_address, code) in blocks.items()\n            }\n''',
)

with Path("tests/test_cpp_identity_end_to_end.py").open("a") as f:
    f.write(
        '''\n\ndef test_legacy_c_artifact_duplicate_names_are_recovered_by_address(tmp_path: Path) -> None:\n    artifact = tmp_path / "legacy.c"\n    artifact.write_text(\n        "// Function: same @ 0x1000\\n"\n        "int same(int x) { return x + 1; }\\n\\n"\n        "// Function: same @ 0x2000\\n"\n        "double same(double x) { return x + 2.0; }\\n"\n    )\n\n    blocks = results_tree.split_functions(artifact)\n    assert set(blocks) == {"same@0x1000", "same@0x2000"}\n    assert blocks["same@0x1000"][0] == 0x1000\n    assert blocks["same@0x2000"][0] == 0x2000\n\n\ndef test_c_artifact_marker_supports_spaced_cpp_names(tmp_path: Path) -> None:\n    result = DecompilationResult(\n        binary_path=tmp_path / "fixture",\n        binary_name="fixture",\n        decompiler=DecompilerMetadata(decompiler_name="fixture-dec"),\n    )\n    result.add_function(\n        FunctionDecompilation(\n            name="operator new",\n            address=0x4000,\n            decompiled_code="void *operator_new(unsigned long n) { return (void *)n; }",\n        )\n    )\n    artifact = tmp_path / "operator.c"\n    result.to_c_file(artifact)\n\n    blocks = results_tree.split_functions(artifact)\n    assert set(blocks) == {"operator new"}\n    assert blocks["operator new"][0] == 0x4000\n'''
    )
