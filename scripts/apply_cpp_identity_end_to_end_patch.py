#!/usr/bin/env python3
"""Apply end-to-end C++ function identity fixes for CI validation."""

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
    "decbench/utils/function_identity.py",
    '''from __future__ import annotations\n\nfrom collections.abc import MutableMapping\n''',
    '''from __future__ import annotations\n\nimport re\nfrom collections.abc import MutableMapping\n''',
)

replace_once(
    "decbench/utils/function_identity.py",
    '''def function_storage_key(function: _FunctionLike) -> str:\n    """Collision-qualified storage key for one function."""\n    return f"{function.name}@0x{function.address:x}"\n\n\ndef insert_function(\n''',
    '''def function_storage_key(function: _FunctionLike) -> str:\n    """Collision-qualified storage key for one function."""\n    return f"{function.name}@0x{function.address:x}"\n\n\ndef parse_function_storage_key(storage_key: str) -> tuple[str, int | None]:\n    """Return ``(semantic_name, address)`` encoded by a benchmark storage key.\n\n    Unique functions keep the historical plain-name key and therefore return\n    ``None`` for the address. Collision-qualified keys are generated only by\n    DecBench and use ``<semantic-name>@0x<canonical-low-pc>``.\n    """\n    match = re.fullmatch(r"(.+)@0x([0-9a-fA-F]+)", storage_key)\n    if match is None:\n        return storage_key, None\n    return match.group(1), int(match.group(2), 16)\n\n\ndef insert_function(\n''',
)

replace_once(
    "decbench/models/decompilation.py",
    '''        with open(path, "w") as f:\n            for func in self.functions.values():\n                f.write(f"// Function: {func.name} @ 0x{func.address:x}\\n")\n                f.write(func.decompiled_code)\n                f.write("\\n\\n")\n''',
    '''        with open(path, "w") as f:\n            for storage_key, func in self.functions.items():\n                f.write(f"// Function: {storage_key} @ 0x{func.address:x}\\n")\n                f.write(func.decompiled_code)\n                f.write("\\n\\n")\n''',
)

replace_once(
    "decbench/metrics/byte_match.py",
    '''import logging\nimport re\nfrom pathlib import Path\n''',
    '''import logging\nimport re\nfrom collections import Counter\nfrom pathlib import Path\n''',
)

replace_once(
    "decbench/metrics/byte_match.py",
    '''        context_decls = derive_context_decls(\n            {name: fd.decompiled_code or "" for name, fd in decompilation.functions.items()}\n        )\n''',
    '''        # Storage keys may be address-qualified (``foo@0x...``), while\n        # prototype recovery needs the semantic C identifier. A same-name\n        # collision is intentionally omitted: choosing either overload's\n        # signature for calls to the other would conflate distinct functions.\n        name_counts = Counter(fd.name for fd in decompilation.functions.values())\n        context_decls = derive_context_decls(\n            {\n                fd.name: fd.decompiled_code or ""\n                for fd in decompilation.functions.values()\n                if name_counts[fd.name] == 1\n            }\n        )\n''',
)

replace_once(
    "decbench/scoring/report_extras.py",
    '''def _lookup_source_ex(\n    decompile_results: Any,\n    project: str,\n    opt_level: Any,\n    binary: str,\n    func_name: str,\n) -> tuple[str | None, str]:\n    """Best-effort source text + provenance/miss status for one function."""\n    bp = _lookup_binary_path(decompile_results, project, opt_level, binary)\n    if bp is None:\n        return None, "binary_not_found"\n    try:\n        from decbench.utils.source_extract import function_source_ex\n\n        return function_source_ex(Path(bp), func_name)\n    except Exception:\n        return None, "extract_failed"\n''',
    '''def _lookup_function_by_storage_key(\n    decompile_results: Any,\n    project: str,\n    opt_level: Any,\n    binary: str,\n    storage_key: str,\n) -> Any:\n    """Resolve a serialized metric/storage key back to its semantic function."""\n    if not decompile_results:\n        return None\n    try:\n        opt_results = decompile_results.get(project) or {}\n        binary_results = opt_results.get(opt_level)\n        if binary_results is None:\n            ov = _opt_value(opt_level)\n            for key, val in opt_results.items():\n                if _opt_value(key) == ov:\n                    binary_results = val\n                    break\n        if not binary_results:\n            return None\n        for dec_result in (binary_results.get(binary) or {}).values():\n            func = (getattr(dec_result, "functions", None) or {}).get(storage_key)\n            if func is not None:\n                return func\n    except Exception:\n        return None\n    return None\n\n\ndef _lookup_source_ex(\n    decompile_results: Any,\n    project: str,\n    opt_level: Any,\n    binary: str,\n    func_name: str,\n) -> tuple[str | None, str]:\n    """Best-effort source text + provenance/miss status for one function.\n\n    ``func_name`` is the benchmark storage key. For collision-qualified C++\n    keys, recover the semantic source name and canonical address before asking\n    the source extractor to disambiguate DWARF.\n    """\n    bp = _lookup_binary_path(decompile_results, project, opt_level, binary)\n    if bp is None:\n        return None, "binary_not_found"\n    try:\n        from decbench.utils.function_identity import parse_function_storage_key\n        from decbench.utils.source_extract import function_source_ex\n\n        func = _lookup_function_by_storage_key(\n            decompile_results, project, opt_level, binary, func_name\n        )\n        if func is not None:\n            return function_source_ex(Path(bp), func.name, func.address)\n        semantic_name, address = parse_function_storage_key(func_name)\n        return function_source_ex(Path(bp), semantic_name, address)\n    except Exception:\n        return None, "extract_failed"\n''',
)

replace_once(
    "scripts/reeval_bytematch.py",
    '''import json\nimport multiprocessing as mp\nimport os\nimport sys\nfrom pathlib import Path\n\nfrom decbench.utils.results_tree import OPT_LEVELS, resolve_binary, split_functions\n''',
    '''import json\nimport multiprocessing as mp\nimport os\nimport sys\nfrom collections import Counter\nfrom pathlib import Path\n\nfrom decbench.utils.function_identity import parse_function_storage_key\nfrom decbench.utils.results_tree import OPT_LEVELS, resolve_binary, split_functions\n''',
)

replace_once(
    "scripts/reeval_bytematch.py",
    '''    funcs = split_functions(Path(c_path))\n    context = derive_context_decls({n: c for n, (_a, c) in funcs.items()})\n    for name, (addr, code) in funcs.items():\n        fd = FunctionDecompilation(\n            name=name,\n            address=addr,\n            decompiled_code=code,\n            line_count=code.count("\\n") + 1,\n        )\n        try:\n            mv = metric.compute_for_function(fd, original_binary_path=binary, context_decls=context)\n        except Exception as e:  # noqa: BLE001\n            out[name] = {"value": 0.0, "compilable": False, "error": str(e)[:120]}\n            continue\n        md = mv.metadata or {}\n        # Abstain rather than score 0: the per-function call still returns 0 when no\n        # matching toolchain exists, and emitting it would tank the x86 compile rate.\n        # Omitting it makes rebuild_function_data drop byte_match for the function.\n        if md.get("skipped"):\n            continue\n        out[name] = {\n            "value": float(mv.value),\n            "compilable": bool(md.get("compilable", False)),\n            "dist": md.get("changed_lines"),\n        }\n''',
    '''    funcs = split_functions(Path(c_path))\n    semantic_names = {\n        storage_key: parse_function_storage_key(storage_key)[0] for storage_key in funcs\n    }\n    name_counts = Counter(semantic_names.values())\n    context = derive_context_decls(\n        {\n            semantic_names[storage_key]: code\n            for storage_key, (_addr, code) in funcs.items()\n            if name_counts[semantic_names[storage_key]] == 1\n        }\n    )\n    for storage_key, (addr, code) in funcs.items():\n        fd = FunctionDecompilation(\n            name=semantic_names[storage_key],\n            address=addr,\n            decompiled_code=code,\n            line_count=code.count("\\n") + 1,\n        )\n        try:\n            mv = metric.compute_for_function(fd, original_binary_path=binary, context_decls=context)\n        except Exception as e:  # noqa: BLE001\n            out[storage_key] = {"value": 0.0, "compilable": False, "error": str(e)[:120]}\n            continue\n        md = mv.metadata or {}\n        # Abstain rather than score 0: the per-function call still returns 0 when no\n        # matching toolchain exists, and emitting it would tank the x86 compile rate.\n        # Omitting it makes rebuild_function_data drop byte_match for the function.\n        if md.get("skipped"):\n            continue\n        out[storage_key] = {\n            "value": float(mv.value),\n            "compilable": bool(md.get("compilable", False)),\n            "dist": md.get("changed_lines"),\n        }\n''',
)

replace_once(
    "scripts/rebuild_function_data.py",
    '''from decbench.utils.results_tree import resolve_binary\nfrom decbench.utils.source_extract import function_source, function_source_ex\n''',
    '''from decbench.utils.function_identity import parse_function_storage_key\nfrom decbench.utils.results_tree import resolve_binary\nfrom decbench.utils.source_extract import function_source, function_source_ex\n''',
)

replace_once(
    "scripts/rebuild_function_data.py",
    '''            source, source_status = function_source_ex(binary, f.function)\n''',
    '''            semantic_name, func_address = parse_function_storage_key(f.function)\n            source, source_status = function_source_ex(binary, semantic_name, func_address)\n''',
)

replace_once(
    "scripts/rebuild_function_data.py",
    '''            binary = reader.binary(g.opt_level, g.project, g.binary)\n            out.append(\n''',
    '''            binary = reader.binary(g.opt_level, g.project, g.binary)\n            semantic_name, func_address = parse_function_storage_key(f.function)\n            out.append(\n''',
)

replace_once(
    "scripts/rebuild_function_data.py",
    '''                    source_code=function_source(binary, f.function) if binary else None,\n''',
    '''                    source_code=(\n                        function_source(binary, semantic_name, func_address) if binary else None\n                    ),\n''',
)

Path("tests/test_cpp_identity_end_to_end.py").write_text(
    '''"""End-to-end regressions for collision-qualified C++ function identity."""\n\nfrom __future__ import annotations\n\nimport importlib.util\nfrom pathlib import Path\n\nfrom decbench.metrics.byte_match import ByteMatchMetric\nfrom decbench.models.decompilation import (\n    DecompilationResult,\n    DecompilerMetadata,\n    FunctionDecompilation,\n)\nfrom decbench.models.metrics import MetricValue\nfrom decbench.scoring import report_extras\nfrom decbench.utils import results_tree, source_extract\nfrom decbench.utils.function_identity import parse_function_storage_key\n\n\ndef _result(tmp_path: Path) -> DecompilationResult:\n    result = DecompilationResult(\n        binary_path=tmp_path / "fixture",\n        binary_name="fixture",\n        decompiler=DecompilerMetadata(decompiler_name="fixture-dec"),\n    )\n    result.add_function(\n        FunctionDecompilation(\n            name="same",\n            address=0x1000,\n            decompiled_code="int same(int x) { return x + 1; }",\n        )\n    )\n    result.add_function(\n        FunctionDecompilation(\n            name="same",\n            address=0x2000,\n            decompiled_code="double same(double x) { return x + 2.0; }",\n        )\n    )\n    result.add_function(\n        FunctionDecompilation(\n            name="unique",\n            address=0x3000,\n            decompiled_code="int unique(void) { return 3; }",\n        )\n    )\n    return result\n\n\ndef _load_reeval_module():\n    path = Path(__file__).resolve().parents[1] / "scripts" / "reeval_bytematch.py"\n    spec = importlib.util.spec_from_file_location("reeval_identity_fixture", path)\n    assert spec is not None and spec.loader is not None\n    module = importlib.util.module_from_spec(spec)\n    spec.loader.exec_module(module)\n    return module\n\n\ndef test_parse_function_storage_key_preserves_legacy_and_collision_forms() -> None:\n    assert parse_function_storage_key("unique") == ("unique", None)\n    assert parse_function_storage_key("same@0x1a2b") == ("same", 0x1A2B)\n\n\ndef test_c_artifact_round_trip_preserves_collision_storage_keys(tmp_path: Path) -> None:\n    result = _result(tmp_path)\n    artifact = tmp_path / "fixture.c"\n    result.to_c_file(artifact)\n\n    blocks = results_tree.split_functions(artifact)\n    assert set(blocks) == {"same@0x1000", "same@0x2000", "unique"}\n    assert blocks["same@0x1000"][0] == 0x1000\n    assert blocks["same@0x2000"][0] == 0x2000\n    assert blocks["unique"][0] == 0x3000\n\n    text = artifact.read_text()\n    assert "// Function: same@0x1000 @ 0x1000" in text\n    assert "// Function: same@0x2000 @ 0x2000" in text\n    assert "// Function: unique @ 0x3000" in text\n\n\ndef test_sample_set_reader_keeps_collision_storage_keys(tmp_path: Path) -> None:\n    result = _result(tmp_path)\n    decompiled = tmp_path / "O2" / "proj" / "decompiled"\n    decompiled.mkdir(parents=True)\n    result.to_c_file(decompiled / "fixture-dec_fixture.c")\n\n    reader = report_extras.SampleSetReader(tmp_path)\n    blocks = reader.decompiled("O2", "proj", "fixture", "fixture-dec")\n    assert set(blocks) == {"same@0x1000", "same@0x2000", "unique"}\n\n\ndef test_report_source_lookup_uses_semantic_name_and_address(\n    tmp_path: Path, monkeypatch\n) -> None:\n    result = _result(tmp_path)\n    nested = {"proj": {"O2": {"fixture": {"fixture-dec": result}}}}\n    seen: list[tuple[Path, str, int | None]] = []\n\n    def fake_source(\n        binary_path: Path | None, func_name: str, func_address: int | None = None\n    ) -> tuple[str | None, str]:\n        assert binary_path is not None\n        seen.append((Path(binary_path), func_name, func_address))\n        return "source", "source"\n\n    monkeypatch.setattr(source_extract, "function_source_ex", fake_source)\n    source, status = report_extras._lookup_source_ex(\n        nested, "proj", "O2", "fixture", "same@0x1000"\n    )\n\n    assert (source, status) == ("source", "source")\n    assert seen == [(result.binary_path, "same", 0x1000)]\n\n\ndef test_report_source_lookup_parses_key_when_backend_result_is_missing(\n    tmp_path: Path, monkeypatch\n) -> None:\n    result = _result(tmp_path)\n    result.functions.pop("same@0x1000")\n    nested = {"proj": {"O2": {"fixture": {"fixture-dec": result}}}}\n    seen: list[tuple[str, int | None]] = []\n\n    def fake_source(\n        _binary_path: Path | None, func_name: str, func_address: int | None = None\n    ) -> tuple[str | None, str]:\n        seen.append((func_name, func_address))\n        return "source", "source"\n\n    monkeypatch.setattr(source_extract, "function_source_ex", fake_source)\n    report_extras._lookup_source_ex(nested, "proj", "O2", "fixture", "same@0x1000")\n    assert seen == [("same", 0x1000)]\n\n\ndef test_byte_match_context_uses_only_unambiguous_semantic_names(\n    tmp_path: Path, monkeypatch\n) -> None:\n    result = _result(tmp_path)\n    captured: dict[str, str] = {}\n\n    def fake_derive(function_codes: dict[str, str]) -> dict[str, str]:\n        captured.update(function_codes)\n        return {"unique": "int unique(void);"}\n\n    monkeypatch.setattr("decbench.metrics.fixup.derive_context_decls", fake_derive)\n    metric = ByteMatchMetric()\n\n    def fake_compute(*_args, **_kwargs) -> MetricValue:\n        return MetricValue(value=1.0)\n\n    monkeypatch.setattr(metric, "compute_for_function", fake_compute)\n    metric.compute_for_binary(result)\n\n    assert set(captured) == {"unique"}\n    assert "same@0x1000" not in captured\n    assert "same@0x2000" not in captured\n    assert "same" not in captured\n\n\ndef test_disk_bytematch_reeval_uses_semantic_names_but_keeps_storage_keys(\n    tmp_path: Path, monkeypatch\n) -> None:\n    result = _result(tmp_path)\n    artifact = tmp_path / "fixture.c"\n    result.to_c_file(artifact)\n    seen_names: list[str] = []\n    captured_context: dict[str, str] = {}\n\n    class FakeMetric:\n        def compute_for_function(self, fd, **_kwargs):\n            seen_names.append(fd.name)\n            return MetricValue(value=1.0, metadata={"compilable": True})\n\n    def fake_derive(function_codes: dict[str, str]) -> dict[str, str]:\n        captured_context.update(function_codes)\n        return {}\n\n    monkeypatch.setattr("decbench.metrics.byte_match.ByteMatchMetric", FakeMetric)\n    monkeypatch.setattr("decbench.metrics.fixup.derive_context_decls", fake_derive)\n\n    module = _load_reeval_module()\n    _key, values = module.eval_one(\n        ("O2", "proj", "fixture", "fixture-dec", str(result.binary_path), str(artifact))\n    )\n\n    assert set(values) == {"same@0x1000", "same@0x2000", "unique"}\n    assert seen_names.count("same") == 2\n    assert seen_names.count("unique") == 1\n    assert set(captured_context) == {"unique"}\n'''
)
