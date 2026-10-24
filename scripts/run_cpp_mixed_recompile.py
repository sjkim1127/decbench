#!/usr/bin/env python3
"""Local mixed-platform recompilation qualification; never updates public metrics.

Plan freezes owned entries before producer execution. Original full-TU controls
must reproduce a function before a recovered-output comparison becomes eligible.
No source/debug types are injected into producer translation units.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import tarfile
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any

import capstone
import lief
from cpp_recompile_support import UnsupportedRecompileEvidence

from decbench.metrics.byte_match import _disassemble_bytes
from decbench.metrics.variable_features import function_definitions
from decbench.models.decompilation import DecompilationResult
from decbench.utils import binfmt
from decbench.utils.cfg_identity import native_sources
from decbench.utils.compilation_units import compilation_path
from decbench.utils.function_identity import dwarf_function_identities
from decbench.utils.native_code import NativeCodeResolver, die_ranges
from decbench.utils.producer_validation import inspect_producer

TOOLS = ("fission", "kuna", "ghidra", "angr")
PREFIX = """#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef unsigned char undefined; typedef unsigned char undefined1;
typedef unsigned short undefined2; typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned char byte; typedef unsigned char uchar;
typedef unsigned short ushort; typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long longlong; typedef unsigned long long ulonglong;
"""


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def read(path: Path) -> Any:
    return json.loads(path.read_text())


def invoke(command: list[str], directory: Path, log: Path, timeout: int = 120) -> dict:
    try:
        run = subprocess.run(command, cwd=directory, capture_output=True, timeout=timeout)
        result = {"argv": command, "exit_code": run.returncode, "timeout": False}
        log.write_bytes(run.stdout + run.stderr)
    except subprocess.TimeoutExpired as error:
        log.write_bytes((error.stdout or b"") + (error.stderr or b""))
        result = {"argv": command, "exit_code": None, "timeout": True}
    return {**result, "log_sha256": sha(log)}


def prepare(config: dict, output: Path) -> None:
    if output.exists():
        raise ValueError("new output directory required")
    sample = read(Path(config["sample"]))
    dataset = Path(config["dataset"])
    output.mkdir(parents=True)
    save(output / "config.json", config)
    for spec in config["platforms"]:
        cell = next(c for c in sample["cells"] if c["id"] == spec["cell"])
        original, stripped = (dataset / cell[k] for k in ("binary", "stripped"))
        for path, key in ((original, "binary_sha256"), (stripped, "stripped_sha256")):
            if sha(path) != cell[key]:
                raise ValueError("frozen corpus hash mismatch")
        if binfmt.executable_regions(original) != binfmt.executable_regions(stripped):
            raise ValueError("stripped executable regions differ")
        if binfmt.dwarf_info(stripped) is not None:
            raise ValueError("producer input contains debug information")
        source_archive = Path(spec["source_archive"])
        with tarfile.open(source_archive) as archive:
            files = {compilation_path(m.name.removeprefix("./")) for m in archive if m.isfile()}
        root = PurePosixPath(compilation_path(spec["owner_root"]))
        identities = dwarf_function_identities(original)
        sources = native_sources(original, {i.address for i in identities})
        by_address: dict[int, list] = defaultdict(list)
        for identity in identities:
            by_address[identity.address].append(identity)
        owned: list[dict] = []
        excluded: list[dict] = []
        for address, aliases in sorted(by_address.items()):
            native = sources.get(address, [])
            declarations = set()
            for row in native:
                for location in row.locations:
                    path = PurePosixPath(compilation_path(location.path))
                    if path.is_relative_to(root):
                        relative = str(path.relative_to(root))
                        if relative in files and not relative.startswith("third_party/"):
                            declarations.add(relative)
            entry = {
                "address": address,
                "name": aliases[0].name,
                "aliases": [asdict(i) for i in aliases],
                "native": [asdict(r) for r in native],
                "owned_files": sorted(declarations),
                "native_identity_ambiguous": len(native) != 1 or len(aliases) != 1,
            }
            (owned if declarations else excluded).append(entry)
        if len(owned) < spec["count"]:
            raise ValueError("insufficient proven project-owned entries")
        # Selection is fixed before producer output or original-control outcomes.
        ordered = sorted(
            owned,
            key=lambda r: hashlib.sha256(
                f"mixed-recompile-v1:{cell['binary_sha256']}:{r['address']:x}".encode()
            ).hexdigest(),
        )
        directory = output / spec["platform"]
        inputs = directory / "producer-input"
        inputs.mkdir(parents=True)
        isolated = inputs / "input.bin"
        isolated.write_bytes(stripped.read_bytes())
        inventory = {"owned": owned, "excluded": excluded}
        save(directory / "inventory.json", inventory)
        payload = {
            "schema": "cpp-whole-binary-plan-v1",
            "official_score": False,
            "cell": cell,
            "original": str(original),
            "input": str(isolated),
            "source_archive": str(source_archive),
            "source_archive_sha256": sha(source_archive),
            "preprocessed_archive": spec["preprocessed_archive"],
            "preprocessed_archive_sha256": sha(Path(spec["preprocessed_archive"])),
            "functions": sorted(ordered[: spec["count"]], key=lambda r: r["address"]),
            "selection": "SHA256(mixed-recompile-v1:image hash:hex address), before outputs",
            "inventory_sha256": sha(directory / "inventory.json"),
            "discovery": "oracle address guided; not blind discovery",
        }
        save(directory / "plan.json", payload)
        tus = directory / "original-control" / "sources"
        tus.mkdir(parents=True)
        extracted = []
        with tarfile.open(spec["preprocessed_archive"]) as archive:
            for index, name in enumerate(spec["tu_members"]):
                stream = archive.extractfile(name)
                if stream is None:
                    raise ValueError("missing original TU")
                path = tus / f"{index:02d}.ii"
                path.write_bytes(stream.read())
                extracted.append({"member": name, "file": str(path), "sha256": sha(path)})
        save(tus.parent / "inputs.json", extracted)
        print(
            json.dumps(
                {"platform": spec["platform"], "owned": len(owned), "selected": spec["count"]}
            ),
            flush=True,
        )


def controls(config: dict, output: Path, platform: str) -> None:
    spec = next(s for s in config["platforms"] if s["platform"] == platform)
    directory = output / platform / "original-control"
    if platform == "windows":
        raise ValueError("Windows control must use the native MSVC transport")
    objects, commands = [], []
    compiler = spec["compiler"]
    for index, item in enumerate(read(directory / "inputs.json")):
        source = Path(item["file"])
        if sha(source) != item["sha256"]:
            raise ValueError("original TU changed")
        obj = directory / f"{index:02d}.o"
        command = [compiler, *spec["control_flags"], "-c", str(source), "-o", str(obj)]
        result = invoke(command, directory, directory / f"compile-{index:02d}.log")
        commands.append(result)
        if result["exit_code"] != 0:
            save(directory / "commands.json", commands)
            return
        objects.append(str(obj))
    binary = directory / spec["control_binary"]
    command = [compiler, *spec["link_flags"], *objects, "-o", str(binary)]
    commands.append(invoke(command, directory, directory / "link.log"))
    if platform == "macos" and commands[-1]["exit_code"] == 0:
        commands.append(
            invoke(["xcrun", "dsymutil", str(binary)], directory, directory / "dsym.log")
        )
    save(directory / "commands.json", commands)


def catalog(path: Path, profile: str = "legacy", origins: dict | None = None) -> tuple[dict, dict]:
    identities = dwarf_function_identities(path)
    resolver = NativeCodeResolver(path)
    by_key: dict[Any, list] = defaultdict(list)
    by_address: dict[int, dict[str, Any]] = {}
    for identity in identities:
        try:
            code = resolver.resolve(identity.name, identity.address)
        except ValueError as error:
            # Existing native resolver's documented unavailable/ambiguous range boundary.
            by_address[identity.address] = {"error": str(error)}
            continue
        try:
            if len(code.ranges) != 1:
                raise UnsupportedRecompileEvidence("noncontiguous function")
            start, end = code.ranges[0]
            regions = [(a, b) for a, b in resolver.regions if a <= start < end <= a + len(b)]
            if len(regions) != 1:
                raise UnsupportedRecompileEvidence("ambiguous executable extent")
            base, data = regions[0]
            raw = data[start - base : end - base]
            mode = binfmt.capstone_arch_mode(resolver.info)
            if mode is None:
                raise UnsupportedRecompileEvidence("unsupported decoder")
            instructions = list(capstone.Cs(*mode).disasm(raw, start))
            if not instructions or sum(i.size for i in instructions) != len(raw):
                raise UnsupportedRecompileEvidence("partial instruction decoding")
            result = {
                "name": identity.name,
                "linkage": identity.linkage_name,
                "address": start,
                "raw": raw.hex(),
                "assembly": comparison_lines(path, raw, start, mode, profile),
            }
            key = (
                (origins or {}).get(identity.address)
                if origins is not None
                else identity.linkage_name or identity.name
            )
            result["origin"] = key if origins is not None else None
            by_key[key].append(result)
            by_address[identity.address] = result
        except UnsupportedRecompileEvidence as error:
            by_address[identity.address] = {"error": str(error)}
    return by_key, by_address


def comparison_lines(path: Path, raw: bytes, start: int, mode: tuple, profile: str) -> list[str]:
    if profile == "legacy":
        return _disassemble_bytes(raw, start, mode)
    if profile != "relocation-v2":
        raise ValueError("unknown comparison profile")
    from cpp_recompile_support import normalize

    return normalize(path, raw, start, mode)


def compare_controls(config: dict, output: Path, platform: str) -> None:
    spec = next(s for s in config["platforms"] if s["platform"] == platform)
    directory = output / platform
    plan = read(directory / "plan.json")
    original = Path(plan["original"])
    if sha(original) != plan["cell"]["binary_sha256"]:
        raise ValueError("original image changed")
    control = directory / "original-control" / spec["control_binary"]
    commands = (
        read(directory / "native-results.json")["original_commands"]
        if platform == "windows"
        else read(directory / "original-control" / "commands.json")
    )
    built = bool(commands) and all(c["exit_code"] == 0 for c in commands)
    profile = config.get("normalization_profile", "legacy")
    original_origins, control_origins = None, None
    if platform == "windows" and profile == "relocation-v2":
        from cpp_recompile_support import pdb_origins, pdb_units

        original_units, rebuilt_units = pdb_units(
            plan, spec, read(directory / "native-results.json")
        )
        original_origins = pdb_origins(original, original_units)
        control_origins = pdb_origins(control, rebuilt_units) if built and control.exists() else {}
    original_keys, original_addresses = catalog(original, profile, original_origins)
    control_keys, _ = (
        catalog(control, profile, control_origins) if built and control.exists() else ({}, {})
    )
    rows = []
    for function in plan["functions"]:
        row = {"address": function["address"], "name": function["name"], "qualified": False}
        value = original_addresses.get(function["address"])
        if function["native_identity_ambiguous"]:
            row["reason"] = "ambiguous original native identity"
        elif value is None or "error" in value:
            row["reason"] = "original extent unavailable or incompletely decoded"
        else:
            key = (
                value["origin"]
                if original_origins is not None
                else value["linkage"] or value["name"]
            )
            candidates = control_keys.get(key, [])
            if not candidates and original_origins is not None and key is not None:
                from cpp_recompile_support import definition_origin

                definition = definition_origin(Path(plan["preprocessed_archive"]), key)
                if definition is not None:
                    candidates = [
                        candidate
                        for records in control_keys.values()
                        for candidate in records
                        if candidate["origin"] is not None
                        and candidate["origin"][:3] == key[:3]
                        and definition_origin(
                            Path(plan["preprocessed_archive"]), candidate["origin"]
                        )
                        == definition
                    ]
                    row["definition_origin_evidence"] = definition
            if key is None or len(original_keys[key]) != 1 or len(candidates) != 1:
                row["reason"] = "original-control function identity absent or ambiguous"
            else:
                candidate = candidates[0]
                row.update(original=value, control=candidate)
                row["raw_equal"] = value["raw"] == candidate["raw"]
                row["qualified"] = value["assembly"] == candidate["assembly"]
                row["reason"] = (
                    "normalized original TU reproduced"
                    if row["qualified"]
                    else "original TU normalized assembly mismatch"
                )
                if not row["qualified"]:
                    info = binfmt.detect(original)
                    if info is None:
                        raise ValueError("original format disappeared")
                    mode = binfmt.capstone_arch_mode(info)
                    row["diagnostic_equal_when_both_rebased_to_zero"] = _disassemble_bytes(
                        bytes.fromhex(value["raw"]), 0, mode
                    ) == _disassemble_bytes(bytes.fromhex(candidate["raw"]), 0, mode)
        rows.append(row)
    save(
        directory / "original-control" / "qualification.json",
        {
            "rows": rows,
            "qualified": sum(r["qualified"] for r in rows),
            "requested": len(rows),
            "original_sha256": sha(original),
            "control_sha256": sha(control) if built and control.exists() else None,
            "normalization_profile": profile,
        },
    )


def producer_context(config: dict, output: Path, platform: str, tool: str) -> dict | None:
    if config.get("declaration_profile") is None:
        return None
    if config["declaration_profile"] not in {"producer-context-v2", "caller-contract-v3"}:
        raise ValueError("unknown declaration profile")
    from cpp_recompile_support import declaration_context

    spec = next(s for s in config["platforms"] if s["platform"] == platform)
    plan = read(output / platform / "plan.json")
    target = binfmt.detect(Path(plan["original"]))
    if target is None or target.bits != 64 or target.arch not in {"aarch64", "x86-64"}:
        raise ValueError("producer declaration transport is qualified only for these 64-bit ABIs")
    paths = (
        output / platform / "producers" / tool / "result.json",
        Path(spec["context_result_root"]) / tool / "result.json",
    )
    context = declaration_context(paths)
    context["profile"] = config["declaration_profile"]
    return context


def recovered_source(code: str, context: dict | None) -> tuple[str, str | None, dict]:
    if context is None:
        definitions = function_definitions(code)
        return PREFIX + "\n" + code, definitions[0].name if len(definitions) == 1 else None, {}
    from cpp_recompile_support import prepare_source

    return prepare_source(code, context, PREFIX)


def recover_sources(output: Path, platform: str, config: dict | None = None) -> None:
    directory = output / platform
    plan = read(directory / "plan.json")
    rows = []
    for tool in TOOLS:
        context = producer_context(config or {}, output, platform, tool)
        producer = directory / "producers" / tool
        completion = read(producer / "completion.json")
        result_path = producer / "result.json"
        if sha(result_path) != completion["result_sha256"]:
            raise ValueError("producer result changed")
        if sha(producer / "contract.json") != completion["contract_sha256"]:
            raise ValueError("producer contract changed")
        result = DecompilationResult.model_validate(read(result_path))
        by_address = {}
        for emitted in result.functions.values():
            if emitted.address in by_address:
                raise ValueError("ambiguous producer records")
            if emitted.address not in {r["address"] for r in plan["functions"]}:
                raise ValueError("foreign producer function")
            by_address[emitted.address] = emitted
        for requested in plan["functions"]:
            address = requested["address"]
            function = by_address.get(address)
            code = function.decompiled_code if function else ""
            definitions = function_definitions(code)
            prepared_source, function_name, declaration_evidence = recovered_source(code, context)
            row = {
                "id": f"{tool}-{address:x}",
                "address": address,
                "tool": tool,
                "producer_sha256": sha(result_path),
                "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
                "function": function_name,
                "definition_count": len(definitions),
                "nonempty": bool(code.strip()),
                "declaration_evidence": declaration_evidence,
            }
            target = directory / "recovered" / row["id"]
            target.mkdir(parents=True, exist_ok=True)
            # Fixed width aliases, no diagnostic repair and no changes to body.
            # ABI-affecting guesses remain visible compile failures/mismatches.
            source = target / "recovered.c"
            source.write_text(prepared_source)
            row["source_sha256"] = sha(source)
            rows.append(row)
    save(
        directory / "recovered" / "plan.json",
        {
            "schema": "cpp-mixed-scaffold-v1",
            "prefix": PREFIX,
            "rows": rows,
            "repair": (
                config.get("declaration_profile", "fixed prefix only")
                if config
                else "fixed prefix only"
            ),
        },
    )


def compile_recovered(config: dict, output: Path, platform: str) -> None:
    spec = next(s for s in config["platforms"] if s["platform"] == platform)
    directory = output / platform
    if platform == "windows":
        raise ValueError("use native MSVC transport")
    plan = read(directory / "recovered" / "plan.json")
    rows = []
    for row in plan["rows"]:
        target = directory / "recovered" / row["id"]
        source = target / "recovered.c"
        if sha(source) != row["source_sha256"]:
            raise ValueError("recovered source changed")
        command = [
            spec["compiler"],
            *spec["recovered_flags"],
            "-c",
            str(source),
            "-o",
            str(target / "recovered.o"),
        ]
        status = invoke(command, target, target / "compile.log", timeout=30)
        rows.append({**row, **status})
    save(directory / "recovered" / "compilation.json", {"rows": rows})


def object_code(path: Path, function: str, platform: str) -> bytes:
    if platform == "linux":
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection

        with path.open("rb") as stream:
            elf = ELFFile(stream)
            symtab = elf.get_section_by_name(".symtab")
            candidates = (
                [
                    s
                    for s in symtab.iter_symbols()
                    if s.name == function
                    and s["st_info"]["type"] == "STT_FUNC"
                    and s["st_size"] > 0
                ]
                if isinstance(symtab, SymbolTableSection)
                else []
            )
            if len(candidates) != 1 or not isinstance(candidates[0]["st_shndx"], int):
                raise UnsupportedRecompileEvidence("missing or ambiguous ELF function symbol/size")
            elf_symbol = candidates[0]
            elf_section = elf.get_section(elf_symbol["st_shndx"])
            start, end = elf_symbol["st_value"], elf_symbol["st_value"] + elf_symbol["st_size"]
            data = elf_section.data()
            if not elf_section["sh_flags"] & 4 or not 0 <= start < end <= len(data):
                raise UnsupportedRecompileEvidence("ELF function outside executable section")
            return data[start:end]
    if platform == "macos":
        fat = lief.MachO.parse(str(path))
        if fat is None or len(fat) != 1:
            raise UnsupportedRecompileEvidence("not one thin Mach-O object")
        obj = fat.at(0)
        symbols = [
            s
            for s in obj.symbols
            if s.name == "_" + function and s.type == lief.MachO.Symbol.TYPE.SECTION
        ]
        if len(symbols) != 1:
            raise UnsupportedRecompileEvidence("missing or ambiguous Mach-O function symbol")
        symbol = symbols[0]
        sections = [(i, s) for i, s in enumerate(obj.sections, 1) if s.name == "__text"]
        section = sections[0][1] if len(sections) == 1 else None
        dwarf = binfmt.dwarf_info(path)
        ranges = []
        if dwarf is not None:
            for cu in dwarf.iter_CUs():
                for die in cu.iter_DIEs():
                    if (
                        die.tag == "DW_TAG_subprogram"
                        and binfmt.die_str_attr(die, "DW_AT_name") == function
                    ):
                        ranges.append(die_ranges(die, dwarf))
        if section is None or len(ranges) != 1 or len(ranges[0]) != 1:
            raise UnsupportedRecompileEvidence("cannot prove exact Mach-O DWARF function extent")
        start, end = ranges[0][0]
        offset = start - section.virtual_address
        if (
            sections[0][0] != symbol.numberof_sections
            or start != symbol.value
            or not 0 <= offset < offset + end - start <= len(section.content)
        ):
            raise UnsupportedRecompileEvidence("Mach-O symbol/DWARF extent mismatch")
        return bytes(section.content)[offset : offset + end - start]
    coff = lief.COFF.parse(str(path))
    if coff is None:
        raise UnsupportedRecompileEvidence("not a COFF object")
    coff_symbols = [s for s in coff.symbols if s.name == function and s.section_idx > 0]
    if len(coff_symbols) != 1:
        raise UnsupportedRecompileEvidence("missing or ambiguous COFF function symbol")
    coff_symbol = coff_symbols[0]
    lengths = []
    for coff_section in coff.sections:
        if coff_section.name != ".debug$S":
            continue
        data = bytes(coff_section.content)
        if len(data) < 4 or struct.unpack_from("<I", data)[0] != 4:
            raise UnsupportedRecompileEvidence("unsupported CodeView signature")
        offset = 4
        while offset + 8 <= len(data):
            kind, size = struct.unpack_from("<II", data, offset)
            begin, end = offset + 8, offset + 8 + size
            if end > len(data):
                raise UnsupportedRecompileEvidence("truncated CodeView subsection")
            if kind == 0xF1:
                position = begin
                while position + 4 <= end:
                    length, record = struct.unpack_from("<HH", data, position)
                    record_end = position + 2 + length
                    if length < 2 or record_end > end:
                        raise UnsupportedRecompileEvidence("truncated CodeView symbol")
                    body = position + 4
                    if record in {0x110F, 0x1110, 0x1146, 0x1147}:
                        if body + 36 > record_end:
                            raise UnsupportedRecompileEvidence("truncated CodeView procedure")
                        name = data[body + 35 : record_end].split(b"\0", 1)[0].decode("utf-8")
                        if name == function:
                            # Relocated segment/offset fields must refer to this
                            # exact symbol; a coincidentally named length is insufficient.
                            relocations = {
                                (r.address, str(r.type), r.symbol.name if r.symbol else None)
                                for r in coff_section.relocations
                            }
                            expected = {
                                (body + 28, "TYPE.AMD64_SECREL", function),
                                (body + 32, "TYPE.AMD64_SECTION", function),
                            }
                            if not expected <= relocations:
                                raise UnsupportedRecompileEvidence(
                                    "unproven COFF procedure relocation"
                                )
                            lengths.append(struct.unpack_from("<I", data, body + 12)[0])
                    position = record_end
            offset = (end + 3) & ~3
    if len(lengths) != 1:
        raise UnsupportedRecompileEvidence("missing or ambiguous CodeView procedure extent")
    text_section = list(coff.sections)[coff_symbol.section_idx - 1]
    start, end = coff_symbol.value, coff_symbol.value + lengths[0]
    if not 0 <= start < end <= len(text_section.content):
        raise UnsupportedRecompileEvidence("COFF function extent outside section")
    return bytes(text_section.content)[start:end]


def report(config: dict, output: Path) -> None:
    rows = []
    for spec in config["platforms"]:
        platform = spec["platform"]
        directory = output / platform
        plan = read(directory / "plan.json")
        qualification = read(directory / "original-control" / "qualification.json")
        if qualification["original_sha256"] != sha(Path(plan["original"])):
            raise ValueError("original image changed after control")
        if qualification["control_sha256"] is not None and qualification["control_sha256"] != sha(
            directory / "original-control" / spec["control_binary"]
        ):
            raise ValueError("control changed after qualification")
        qualified = {r["address"]: r for r in qualification["rows"]}
        compilation = read(directory / "recovered" / "compilation.json")
        expected_population = {(tool, r["address"]) for tool in TOOLS for r in plan["functions"]}
        population = [(r["tool"], r["address"]) for r in compilation["rows"]]
        if len(population) != len(set(population)) or set(population) != expected_population:
            raise ValueError("recompilation population changed")
        producer_functions = {}
        contexts = {}
        for tool in TOOLS:
            contexts[tool] = producer_context(config, output, platform, tool)
            producer_result = DecompilationResult.model_validate(
                read(directory / "producers" / tool / "result.json")
            )
            completion = read(directory / "producers" / tool / "completion.json")
            if sha(directory / "producers" / tool / "result.json") != completion["result_sha256"]:
                raise ValueError("producer changed after completion")
            for emitted in producer_result.functions.values():
                producer_functions[(tool, emitted.address)] = emitted
        for row in compilation["rows"]:
            control = qualified[row["address"]]
            result = {**row, "platform": platform, "normalized_equal": False}
            function = producer_functions.get((row["tool"], row["address"]))
            code = function.decompiled_code if function else ""
            expected_source, expected_function, expected_evidence = recovered_source(
                code, contexts[row["tool"]]
            )
            source = directory / "recovered" / row["id"] / "recovered.c"
            if (
                hashlib.sha256(code.encode()).hexdigest() != row["code_sha256"]
                or sha(source) != row["source_sha256"]
                or source.read_text() != expected_source
                or row["function"] != expected_function
                or row.get("declaration_evidence", {}) != expected_evidence
            ):
                raise ValueError("recompilation source differs from frozen producer/scaffold")
            inspection = inspect_producer(
                function.decompiled_code if function else "",
                function.metadata if function else None,
            )
            result["producer_inspection"] = inspection.evidence()
            if not control["qualified"]:
                result.update(category="environment_unsupported", reason=control["reason"])
            elif not row["nonempty"] or row["definition_count"] != 1:
                result.update(
                    category="output_compile_failure",
                    reason="empty output or no single entry definition",
                )
            elif row["exit_code"] != 0:
                result.update(
                    category="output_compile_failure",
                    reason="timeout" if row["timeout"] else "compiler rejection",
                )
                result["failure_class"] = (
                    "confirmed_source_defect"
                    if inspection.invalid
                    else "context_or_dialect_not_resolved"
                )
            elif row["definition_count"] != 1 or not re.fullmatch(
                r"[A-Za-z_]\w*", row["function"] or ""
            ):
                result.update(
                    category="environment_unsupported", reason="producer entry identity unsupported"
                )
            else:
                try:
                    obj = (
                        directory
                        / "recovered"
                        / row["id"]
                        / ("recovered.obj" if platform == "windows" else "recovered.o")
                    )
                    data = object_code(obj, row["function"], platform)
                    info = binfmt.object_info(obj)
                    original_info = binfmt.detect(Path(read(directory / "plan.json")["original"]))
                    if original_info is None:
                        raise UnsupportedRecompileEvidence("original target unavailable")
                    mode = binfmt.capstone_arch_mode(original_info)
                    if mode is None:
                        raise UnsupportedRecompileEvidence("unsupported decoder")
                    if info is None or info.arch != (
                        "x86-64" if platform == "windows" else "aarch64"
                    ):
                        raise UnsupportedRecompileEvidence("object target mismatch")
                    decoded = list(capstone.Cs(*mode).disasm(data, 0))
                    if not decoded or sum(i.size for i in decoded) != len(data):
                        raise UnsupportedRecompileEvidence("partial recovered instruction decoding")
                    assembly = comparison_lines(
                        obj, data, 0, mode, config.get("normalization_profile", "legacy")
                    )
                    result.update(recovered_bytes=data.hex(), recovered_assembly=assembly)
                    result["normalized_equal"] = assembly == control["original"]["assembly"]
                    result.update(
                        category=(
                            "perfect_match" if result["normalized_equal"] else "compiled_mismatch"
                        ),
                        reason=config.get("normalization_profile", "legacy")
                        + " assembly comparison",
                    )
                except UnsupportedRecompileEvidence as error:
                    result.update(category="environment_unsupported", reason=str(error))
            rows.append(result)
    summary: dict[str, dict] = {}
    for platform in [s["platform"] for s in config["platforms"]] + ["all"]:
        summary[platform] = {}
        for tool in TOOLS:
            subset = [
                r
                for r in rows
                if r["tool"] == tool and (platform == "all" or r["platform"] == platform)
            ]
            summary[platform][tool] = {
                "requested": len(subset),
                **Counter(r["category"] for r in subset),
            }
    save(
        output / "REPORT.json",
        {
            "schema": (
                "cpp-mixed-recompilation-v2-experimental"
                if config.get("normalization_profile")
                else "cpp-mixed-recompilation-v1-experimental"
            ),
            "official_score": False,
            "execution_parity": False,
            "comparison": config.get("normalization_profile", "legacy")
            + " assembly shape, not literal byte identity or execution equivalence",
            "profile": (
                "producer-only consensus prototypes, bijective parsed-name transport, "
                "opaque pointer forwards; strict missing-call diagnostics; "
                "no layout/expression repairs"
                if config.get("declaration_profile")
                else "minimal fixed C scaffold; no diagnostic repair; "
                "partial declaration contracts "
                "remain unresolved, so compilation failures are not automatically producer defects"
            ),
            "normalization_profile": config.get("normalization_profile", "legacy"),
            "declaration_profile": config.get("declaration_profile", "minimal-c-scaffold"),
            **(
                {
                    "caller_binding_policy": "preserve emitted bindings and macros; external "
                    "context only for undeclared names; cross-output arity is diagnostic, "
                    "not proven type compatibility"
                }
                if config.get("declaration_profile") == "caller-contract-v3"
                else {}
            ),
            "summary": summary,
            "rows": rows,
        },
    )
    print(json.dumps(summary, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("plan", "controls", "compare-controls", "sources", "compile", "report")
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform", choices=("linux", "windows", "macos"))
    args = parser.parse_args()
    config = read(args.config)
    if args.command == "plan":
        prepare(config, args.output)
    elif args.command == "report":
        report(config, args.output)
    else:
        if args.platform is None:
            parser.error("--platform required")
        if args.command == "sources":
            recover_sources(args.output, args.platform, config)
        else:
            {
                "controls": controls,
                "compare-controls": compare_controls,
                "compile": compile_recovered,
            }[args.command](config, args.output, args.platform)


if __name__ == "__main__":
    main()
