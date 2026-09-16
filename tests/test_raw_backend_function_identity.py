"""Raw-backend regressions for collision-safe C++ function identity."""

from __future__ import annotations

from pathlib import Path

from decbench.models.decompilation import FunctionDecompilation


RAW_DIR = Path(__file__).resolve().parent.parent / "decbench" / "decompilers" / "raw"


def _fake_function(name: str, address: int) -> FunctionDecompilation:
    return FunctionDecompilation(
        name=name,
        address=address,
        decompiled_code=f"int {name}(void) {{ return {address}; }}",
    )


def test_raw_backends_do_not_reintroduce_plain_name_storage() -> None:
    """Every migrated raw backend must route result insertion through the helper."""
    banned = {
        "angr_raw.py": ["decompiled_functions[func_name] = func_result"],
        "binja_raw.py": [
            "decompiled_functions[func_name] = func_result",
            "requested = {n for (n, _a) in functions}",
        ],
        "ida_raw.py": [
            "decompiled_functions[func_name] = func_result",
            "requested = {n for (n, _a) in functions}",
        ],
        "dewolf_raw.py": ["decompiled_functions[name] = fd"],
        "kuna_raw.py": [
            'records = {str(r.get("name") or ""): r',
            "decompiled[func_name] = fd",
            "records[func_name]",
            "requested = {n for (n, _a) in functions}",
        ],
        "glaurung_raw.py": [
            'by_name = {str(r.get("name") or ""): r',
            "decompiled[func_name] = fd",
            "by_name[func_name]",
            "requested = {n for (n, _a) in functions}",
        ],
        "manifold_raw.py": [
            "decompiled_functions[name] = FunctionDecompilation",
            "keep_names = {n for n, _ in kept}",
        ],
    }

    for filename, needles in banned.items():
        text = (RAW_DIR / filename).read_text()
        assert "from decbench.utils.function_identity import insert_function" in text
        for needle in needles:
            assert needle not in text, f"{filename} still contains name-keyed identity: {needle}"


def test_kuna_same_name_records_are_preserved_by_address(tmp_path, monkeypatch) -> None:
    from decbench.decompilers.raw import common
    from decbench.decompilers.raw.kuna_raw import RawKunaDecompiler

    backend = RawKunaDecompiler()
    records = [
        {"name": "same", "address": 0x1000, "code": "a"},
        {"name": "same", "address": 0x2000, "code": "b"},
    ]

    monkeypatch.setattr(backend, "is_available", lambda: True)
    monkeypatch.setattr(backend, "get_version", lambda: "test")
    monkeypatch.setattr(backend, "_run_decompile_all", lambda _path: {"functions": records})
    monkeypatch.setattr(backend, "_records", lambda _payload: records)
    monkeypatch.setattr(
        backend,
        "_build_function",
        lambda rec, name, address: _fake_function(name, address),
    )
    monkeypatch.setattr(common, "elf_text_ranges", lambda _path: object())
    monkeypatch.setattr(common, "addr_targets_of", lambda _names: None)
    monkeypatch.setattr(common, "should_skip_function", lambda *args, **kwargs: False)
    monkeypatch.setattr(common, "narrow_to_source", lambda rows, *args, **kwargs: rows)

    result = backend.decompile_binary(
        tmp_path / "fixture",
        functions=[("same", 0x1000), ("same", 0x2000)],
    )

    assert result.function_count == 2
    assert set(result.functions) == {"same@0x1000", "same@0x2000"}
    assert {f.address for f in result.functions.values()} == {0x1000, 0x2000}


def test_glaurung_same_name_records_are_preserved_by_address(tmp_path, monkeypatch) -> None:
    from decbench.decompilers.raw import common
    from decbench.decompilers.raw.glaurung_raw import RawGlaurungDecompiler

    backend = RawGlaurungDecompiler()
    records = [
        {"name": "same", "entry_va": 0x1000, "pseudocode": "a"},
        {"name": "same", "entry_va": 0x2000, "pseudocode": "b"},
    ]

    monkeypatch.setattr(backend, "_select_path", lambda: ("native", Path("/fake/glaurung")))
    monkeypatch.setattr(backend, "get_version", lambda: "test")
    monkeypatch.setattr(
        backend,
        "_run_decompile",
        lambda _path, function_names=None: records,
    )
    monkeypatch.setattr(
        backend,
        "_build_function",
        lambda rec, name, address: _fake_function(name, address),
    )
    monkeypatch.setattr(common, "elf_text_range", lambda _path: object())
    monkeypatch.setattr(common, "should_skip_function", lambda *args, **kwargs: False)
    monkeypatch.setattr(common, "narrow_to_source", lambda rows, *args, **kwargs: rows)

    result = backend.decompile_binary(
        tmp_path / "fixture",
        functions=[("same", 0x1000), ("same", 0x2000)],
    )

    assert result.function_count == 2
    assert set(result.functions) == {"same@0x1000", "same@0x2000"}
    assert {f.address for f in result.functions.values()} == {0x1000, 0x2000}
