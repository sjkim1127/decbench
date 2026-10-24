"""Evidence-bounded experimental transport; not a registered DecBench metric."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, TypedDict

import capstone
import lief
from capstone import arm64_const as a64

from decbench.metrics.byte_match import _disassemble_bytes
from decbench.metrics.fixup import _KNOWN_PROTOS
from decbench.metrics.variable_features import (
    _declarator_identifier,
    _function_name,
    _parse_source,
    _parser,
    _walk,
    function_definitions,
)
from decbench.models.decompilation import DecompilationResult
from decbench.utils import binfmt
from decbench.utils.cfg_identity import origin_source
from decbench.utils.compilation_units import compilation_path
from decbench.utils.producer_validation import inspect_producer


def text_name(value: str | bytes) -> str:
    return value.decode("utf-8", "strict") if isinstance(value, bytes) else value


class UnsupportedRecompileEvidence(Exception):
    """A recognized missing/ambiguous native extent or relocation proof."""


class ReferenceEvidence:
    """Native symbols, import slots and format-declared literal sections only."""

    def __init__(self, path: Path):
        self.names: dict[int, str] = {}
        self.imports: dict[int, set[str]] = defaultdict(set)
        self.literals: list[tuple[int, bytes]] = []
        self.relocated: dict[int, str] = {}
        self.branch_relocations: set[int] = set()
        self.page_relocations: set[int] = set()
        self.addend_relocations: set[int] = set()
        self.object_file = False
        info = binfmt.detect(path)
        if info is None:
            return
        candidates: dict[str, set[int]] = defaultdict(set)
        if info.fmt == "macho":
            fat = lief.MachO.parse(str(path))
            if fat is None or len(fat) != 1:
                raise UnsupportedRecompileEvidence("expected one thin Mach-O")
            image = fat.at(0)
            self.object_file = binfmt.object_info(path) is not None
            for symbol in image.symbols:
                if (
                    not symbol.raw_type & 0xE0
                    and symbol.raw_type & 0x0E == 0x0E
                    and not text_name(symbol.name).startswith("ltmp")
                ):
                    candidates[text_name(symbol.name)].add(symbol.value)
            for section in image.sections:
                if section.type == lief.MachO.Section.TYPE.CSTRING_LITERALS:
                    self.literals.append((section.virtual_address, bytes(section.content)))
            for name, addresses in candidates.items():
                if len(addresses) == 1:
                    address = next(iter(addresses))
                    # Multiple different names at an address are not guessed.
                    previous = self.names.get(address)
                    self.names[address] = (
                        "symbol:" + name if previous in (None, "symbol:" + name) else ""
                    )
            for binding in image.bindings:
                if binding.has_symbol:
                    self.imports[binding.address].add("import:" + text_name(binding.symbol.name))
            if self.object_file:
                for section in image.sections:
                    if section.name != "__text":
                        continue
                    for relocation in section.relocations:
                        location = section.virtual_address + relocation.address
                        if "ADDEND" in str(relocation.type):
                            self.addend_relocations.add(location)
                        if "BRANCH26" in str(relocation.type):
                            self.branch_relocations.add(location)
                        if "PAGEOFF12" not in str(relocation.type):
                            continue
                        self.page_relocations.add(location)
                        if not relocation.has_symbol:
                            continue
                        symbol = relocation.symbol
                        if symbol.type == lief.MachO.Symbol.TYPE.SECTION:
                            reference = self.at(symbol.value)
                        else:
                            reference = "import:" + text_name(symbol.name)
                        if reference:
                            previous = self.relocated.get(location)
                            self.relocated[location] = (
                                reference if previous in (None, reference) else ""
                            )
        elif info.fmt == "elf":
            elf_image = lief.ELF.parse(str(path))
            if elf_image is None:
                raise UnsupportedRecompileEvidence("expected ELF")
            self.object_file = binfmt.object_info(path) is not None
            for elf_symbol in elf_image.symbols:
                if (
                    elf_symbol.value
                    and elf_symbol.size
                    and elf_symbol.type == lief.ELF.Symbol.TYPE.OBJECT
                ):
                    candidates[text_name(elf_symbol.name)].add(elf_symbol.value)
            for name, addresses in candidates.items():
                if len(addresses) == 1:
                    address = next(iter(addresses))
                    previous = self.names.get(address)
                    self.names[address] = (
                        "symbol:" + name if previous in (None, "symbol:" + name) else ""
                    )
            for elf_relocation in elf_image.relocations:
                if elf_relocation.has_symbol and elf_relocation.symbol.name:
                    if not self.object_file:
                        self.imports[elf_relocation.address].add(
                            "import:" + text_name(elf_relocation.symbol.name)
                        )
                    elif "CALL26" in str(elf_relocation.type) or "JUMP26" in str(
                        elf_relocation.type
                    ):
                        self.branch_relocations.add(elf_relocation.address)

    def at(self, address: int) -> str | None:
        if address in self.imports:
            names = self.imports[address]
            return next(iter(names)) if len(names) == 1 else None
        literal_values = set()
        for base, data in self.literals:
            offset = address - base
            if not 0 <= offset < len(data) or (offset and data[offset - 1] != 0):
                continue
            end = data.find(b"\0", offset)
            if end < 0:
                continue
            payload = data[offset : end + 1]
            literal_values.add("cstring:" + hashlib.sha256(payload).hexdigest())
        if literal_values:
            return next(iter(literal_values)) if len(literal_values) == 1 else None
        return self.names.get(address) or None

    def consumer(self, instruction: int, target: int, immediate: int) -> str | None:
        if instruction in self.addend_relocations:
            return None
        if instruction in self.page_relocations:
            # Nonzero encoded addends need a full relocation-expression reader.
            # Never erase a possible object/field offset by treating it as zero.
            return self.relocated.get(instruction) if immediate == 0 else None
        return self.at(target)


@lru_cache(maxsize=32)
def references(path: Path) -> ReferenceEvidence:
    return ReferenceEvidence(path)


def normalize(path: Path, raw: bytes, start: int, mode: tuple) -> list[str]:
    """Keep branch registers/bits and local targets; erase only proven data relocations.

    Calls retain the legacy external-target blindness. This is an assembly-shape
    diagnostic, never execution equivalence. Unknown data references stay literal.
    """
    if mode[0] != capstone.CS_ARCH_ARM64:
        return _disassemble_bytes(raw, start, mode)
    decoder = capstone.Cs(*mode)
    decoder.detail = True
    instructions = list(decoder.disasm(raw, start))
    if not instructions or sum(i.size for i in instructions) != len(raw):
        raise UnsupportedRecompileEvidence("partial ARM64 instruction decoding")
    evidence = references(path.resolve())
    starts = {i.address: i.address - start for i in instructions}
    boundaries = {
        i.operands[-1].imm
        for i in instructions
        if i.group(capstone.CS_GRP_JUMP) and i.operands and i.operands[-1].type == a64.ARM64_OP_IMM
    }
    pages: dict[str, tuple[int, int]] = {}
    lines = [f"{i.mnemonic} {i.op_str}".strip() for i in instructions]

    def reg(instruction: Any, register: int) -> str:
        name = str(instruction.reg_name(register))
        return "x" + name[1:] if re.fullmatch(r"w\d+", name) else name

    for index, instruction in enumerate(instructions):
        if instruction.address in boundaries and instruction.address != start:
            pages.clear()
        operands = instruction.operands
        before = pages.copy()
        _, written = instruction.regs_access()
        for register in written:
            pages.pop(reg(instruction, register), None)
        if instruction.mnemonic == "adrp" and len(operands) == 2:
            pages[reg(instruction, operands[0].reg)] = (operands[1].imm, index)
        elif (
            instruction.mnemonic == "add"
            and len(operands) == 3
            and operands[2].type == a64.ARM64_OP_IMM
            and instruction.reg_name(operands[0].reg).startswith("x")
            and instruction.reg_name(operands[1].reg).startswith("x")
        ):
            source = reg(instruction, operands[1].reg)
            if source in before:
                page, producer = before[source]
                value = operands[2].imm << operands[2].shift.value
                target = evidence.consumer(instruction.address, page + value, value)
                if target:
                    destination = instructions[producer].reg_name(
                        instructions[producer].operands[0].reg
                    )
                    lines[producer] = f"adrp {destination}, PAGE"
                    lines[index] = (
                        f"add {instruction.reg_name(operands[0].reg)}, "
                        f"{instruction.reg_name(operands[1].reg)}, REF({target})"
                    )
        elif (
            instruction.mnemonic in {"ldr", "ldrsw", "ldrb", "ldrh"}
            and len(operands) == 2
            and operands[1].type == a64.ARM64_OP_MEM
            and not instruction.writeback
        ):
            source = reg(instruction, operands[1].mem.base)
            if source in before and not operands[1].mem.index:
                page, producer = before[source]
                target = evidence.consumer(
                    instruction.address, page + operands[1].mem.disp, operands[1].mem.disp
                )
                if target:
                    destination = instructions[producer].reg_name(
                        instructions[producer].operands[0].reg
                    )
                    lines[producer] = f"adrp {destination}, PAGE"
                    lines[index] = (
                        f"{instruction.mnemonic} {instruction.reg_name(operands[0].reg)}, "
                        f"[{instruction.reg_name(operands[1].mem.base)}, REF({target})]"
                    )
        if instruction.group(capstone.CS_GRP_CALL) or instruction.group(capstone.CS_GRP_JUMP):
            if operands and operands[-1].type == a64.ARM64_OP_IMM:
                target_address = operands[-1].imm
                if (
                    instruction.group(capstone.CS_GRP_CALL)
                    or instruction.address in evidence.branch_relocations
                ):
                    target = "EXTERNAL"
                elif target_address in starts:
                    target = f"LOCAL+{starts[target_address]:x}"
                elif start <= target_address < start + len(raw):
                    raise UnsupportedRecompileEvidence(
                        "branch target is not an instruction boundary"
                    )
                else:
                    target = "EXTERNAL"
                prefix = instruction.op_str.rsplit(",", 1)[0] + ", " if len(operands) > 1 else ""
                lines[index] = f"{instruction.mnemonic} {prefix}{target}"
            pages.clear()
        elif instruction.group(capstone.CS_GRP_RET):
            pages.clear()
    return [
        line
        for line, instruction in zip(lines, instructions, strict=True)
        if instruction.mnemonic != "nop"
    ]


def pdb_units(plan: dict, spec: dict, native_report: dict) -> tuple[dict[str, str], dict[str, str]]:
    """Bind full PDB module paths to the same original TU using recorded commands/hashes."""
    database = json.loads(Path(spec["original_compile_database"]).read_text())
    original: dict[str, str] = {}
    for entry in database:
        module = compilation_path(entry["output"], entry["directory"])
        source = compilation_path(entry["file"], entry["directory"])
        if module in original and original[module] != source:
            raise ValueError("ambiguous original compile database")
        original[module] = source
    archive_path = Path(plan["preprocessed_archive"])
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != plan["preprocessed_archive_sha256"]:
        raise ValueError("preprocessed archive changed")
    hashes: dict[str, set[str]] = defaultdict(set)
    with tarfile.open(archive_path) as archive:
        stream = archive.extractfile("preprocessed/source-map.json")
        if stream is None:
            raise ValueError("missing native TU source map")
        source_map = json.load(stream)
        for row in source_map:
            entries = [
                e
                for e in database
                if e["command"] == row["original_command"]
                and compilation_path(e["file"]) == compilation_path(row["source"])
            ]
            if len(entries) != 1:
                raise ValueError("source-map command is not a unique original compilation")
            member = "preprocessed/" + row["preprocessed"]
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("missing mapped TU")
            hashes[hashlib.sha256(stream.read()).hexdigest()].add(compilation_path(row["source"]))
    rebuilt: dict[str, str] = {}
    for command in native_report["original_commands"]:
        if "source_sha256" not in command:
            continue
        sources = hashes.get(command["source_sha256"], set())
        outputs = [a[3:] for a in command["argv"] if a.startswith("/Fo")]
        if len(sources) != 1 or len(outputs) != 1 or command["exit_code"] != 0:
            raise ValueError("unproven rebuilt TU binding")
        module, source = compilation_path(outputs[0]), next(iter(sources))
        if module in rebuilt and rebuilt[module] != source:
            raise ValueError("ambiguous rebuilt TU binding")
        rebuilt[module] = source
    return original, rebuilt


def pdb_origins(path: Path, units: dict[str, str]) -> dict[int, tuple[str, str, str, int]]:
    native = binfmt.pdb_info(path)
    if native is None:
        raise ValueError("missing matched native PDB")
    by_address: dict[int, list] = defaultdict(list)
    for function in native.functions:
        by_address[function.address].append(function)
    result = {}
    for address, rows in by_address.items():
        if len(rows) != 1:
            continue
        function = rows[0]
        unit = units.get(compilation_path(function.module))
        if unit and function.source_file and function.source_line > 0:
            result[address] = (
                function.name,
                unit,
                compilation_path(function.source_file),
                function.source_line,
            )
    return result


@lru_cache(maxsize=16)
def source_definitions(archive_path: Path) -> dict[str, list]:
    """Definition spans from the same hash-bound original preprocessed TU."""
    result: dict[str, list] = defaultdict(list)
    with tarfile.open(archive_path) as archive:
        stream = archive.extractfile("preprocessed/source-map.json")
        if stream is None:
            raise ValueError("missing source-map")
        for row in json.load(stream):
            stream = archive.extractfile("preprocessed/" + row["preprocessed"])
            if stream is None:
                raise ValueError("missing mapped source")
            origin = origin_source(stream.read().decode("utf-8-sig", "replace"))
            unit = compilation_path(row["source"])
            for definition in function_definitions(origin.text):
                if definition.has_error or definition.is_template:
                    continue
                locations = {
                    (compilation_path(location.path), location.line)
                    for physical, location in origin.origins.items()
                    if definition.start_line <= physical <= definition.end_line
                }
                key = (
                    unit,
                    definition.name,
                    definition.start_line,
                    definition.end_line,
                    hashlib.sha256(definition.code.encode()).hexdigest(),
                )
                result[unit].append((definition.name, locations, key))
    return result


def definition_origin(archive: Path, origin: tuple | list | None) -> tuple | None:
    if origin is None:
        return None
    name, unit, source, line = origin
    candidates = {
        key
        for full_name, locations, key in source_definitions(archive).get(unit, [])
        if name == full_name and (source, line) in locations
    }
    return next(iter(candidates)) if len(candidates) == 1 else None


_QUALIFIED = re.compile(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*")
_C_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
DECLARATION_PREFIX = """
typedef uint8_t __uint8; typedef uint16_t __uint16;
typedef uint32_t __uint32; typedef uint64_t __uint64;
#ifndef _MSC_VER
#define __int8 int8_t
#define __int16 int16_t
#define __int32 int32_t
#define __int64 int64_t
#endif
/* These legacy annotations have no distinct ABI on the qualified 64-bit targets.
   vectorcall is intentionally preserved because it may change argument passing. */
#define __cdecl
#define __stdcall
#define __fastcall
#define __thiscall
#ifdef _MSC_VER
#define __noreturn __declspec(noreturn)
#else
#define __noreturn __attribute__((noreturn))
#endif
"""


def c_name(name: str) -> str:
    if not _QUALIFIED.fullmatch(name):
        raise ValueError("unsupported C++ spelling transport")
    return name if "::" not in name else "dbcpp_" + hashlib.sha256(name.encode()).hexdigest()


class NameEdit(TypedDict):
    start: int
    end: int
    original: str
    replacement: str


def transport_names(code: str) -> tuple[str, list[NameEdit]]:
    """Rename only parsed ordinary qualified identifiers, never strings/comments."""
    source = code.encode()
    tree = _parse_source(source)
    edits: list[NameEdit] = []
    identifiers = {
        source[node.start_byte : node.end_byte].decode()
        for node in _walk(tree.root_node)
        if node.type == "identifier"
    }
    for node in _walk(tree.root_node):
        if node.type != "qualified_identifier" or node.has_error:
            continue
        parent = node.parent
        if parent is not None and parent.type == "qualified_identifier":
            continue
        text = source[node.start_byte : node.end_byte].decode()
        if "::" not in text or not _QUALIFIED.fullmatch(text):
            continue
        alias = c_name(text)
        if alias in identifiers:
            raise ValueError("generated C name collides with an emitted identifier")
        edits.append(
            {"start": node.start_byte, "end": node.end_byte, "original": text, "replacement": alias}
        )
    for edit in sorted(edits, key=lambda e: e["start"], reverse=True):
        source = source[: edit["start"]] + edit["replacement"].encode() + source[edit["end"] :]
    return source.decode(), edits


def signatures(code: str) -> list[tuple[str, str]]:
    """Read exact producer signatures, removing formal display names only."""
    if inspect_producer(code).invalid:
        return []
    source = code.encode()
    tree = _parse_source(source)
    result = []
    for node in _walk(tree.root_node):
        if node.type != "function_definition" or node.has_error:
            continue
        body = node.child_by_field_name("body")
        declarator = node.child_by_field_name("declarator")
        name = _function_name(node, source)
        if body is None or declarator is None or not _QUALIFIED.fullmatch(name):
            continue
        identifier = _declarator_identifier(declarator)
        if (
            identifier is None
            or source[identifier.start_byte : identifier.end_byte].decode() != name
        ):
            # Namespace wrappers and implicit class scope require a different contract.
            continue
        removals = []
        if any(
            child.type in {"string_literal", "char_literal"} and child.end_byte <= body.start_byte
            for child in _walk(node)
        ):
            continue
        for child in _walk(declarator):
            if child.type not in {"parameter_declaration", "optional_parameter_declaration"}:
                continue
            parameter = _declarator_identifier(child.child_by_field_name("declarator"))
            if parameter is not None and parameter.type == "identifier":
                removals.append((parameter.start_byte, parameter.end_byte))
        for child in _walk(node):
            if child.type == "comment" and child.end_byte <= body.start_byte:
                removals.append((child.start_byte, child.end_byte))
        head = source[node.start_byte : body.start_byte]
        for start, end in sorted(set(removals), reverse=True):
            head = head[: start - node.start_byte] + head[end - node.start_byte :]
        transported, _ = transport_names(head.decode() + ";")
        prototype = " ".join(transported.split())
        if prototype.startswith("static "):
            prototype = prototype[len("static ") :]
        prototype = re.sub(
            rf"\b{re.escape(c_name(name))}\s*\(\s*\)", c_name(name) + "(void)", prototype, count=1
        )
        check = re.sub(r"\b__(?:cdecl|stdcall|fastcall|thiscall|noreturn)\b", "", prototype)
        if (
            "#" not in prototype
            and len(prototype) < 4096
            and not _parser().parse(check.encode()).root_node.has_error
        ):
            result.append((name, prototype))
    return result


def declaration_context(paths: tuple[Path, ...]) -> dict:
    """Consensus is per tool/image; no ground-truth or other-tool signatures."""
    records: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    evidence = []
    producer = None
    image = None
    producer_contract = None
    for path in paths:
        payload = DecompilationResult.model_validate_json(path.read_text())
        current = payload.decompiler.decompiler_name, payload.decompiler.decompiler_version
        if producer is not None and current != producer:
            raise ValueError("cross-producer declaration context")
        # Each path is authenticated against its original completion/plan by the caller.
        producer = current
        completion = json.loads((path.parent / "completion.json").read_text())
        if hashlib.sha256(path.read_bytes()).hexdigest() != completion["result_sha256"]:
            raise ValueError("context result changed after completion")
        contract = json.loads((path.parent / "contract.json").read_text())
        if (
            hashlib.sha256((path.parent / "contract.json").read_bytes()).hexdigest()
            != completion["contract_sha256"]
        ):
            raise ValueError("context contract changed")
        comparable = {k: v for k, v in contract.items() if k != "plan_sha256"}
        if producer_contract is not None and comparable != producer_contract:
            raise ValueError("declaration context producer configuration differs")
        producer_contract = comparable
        plan = json.loads((path.parents[2] / "plan.json").read_text())
        if (
            hashlib.sha256((path.parents[2] / "plan.json").read_bytes()).hexdigest()
            != contract["plan_sha256"]
        ):
            raise ValueError("context plan changed")
        current_image = plan["cell"]["stripped_sha256"]
        if hashlib.sha256(Path(plan["input"]).read_bytes()).hexdigest() != current_image:
            raise ValueError("context stripped input changed")
        if image is not None and current_image != image:
            raise ValueError("cross-image declaration context")
        image = current_image
        addresses = [f.address for f in payload.functions.values()]
        if len(addresses) != len(set(addresses)) or not set(addresses) <= {
            f["address"] for f in plan["functions"]
        }:
            raise ValueError("ambiguous or foreign context procedure")
        evidence.append({"path": str(path), "sha256": completion["result_sha256"]})
        for function in payload.functions.values():
            for name, prototype in signatures(function.decompiled_code):
                records[name][prototype].append(
                    {"address": function.address, "result_sha256": completion["result_sha256"]}
                )
    for name in records:
        if "::" in name and c_name(name) in records:
            raise ValueError("transport alias collides with another emitted function")
    return {
        "files": evidence,
        "prototypes": {
            name: next(iter(variants)) for name, variants in records.items() if len(variants) == 1
        },
        "ambiguous": sorted(name for name, variants in records.items() if len(variants) != 1),
        "producer": producer,
        "input_sha256": image,
    }


def pointer_forwards(code: str) -> list[str]:
    """An emitted pointer permits an incomplete nominal declaration, never layout."""
    source = code.encode()
    tree = _parse_source(source)
    defined = set()
    for node in _walk(tree.root_node):
        if node.type != "type_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        identifier = (
            declarator
            if declarator is not None and declarator.type == "type_identifier"
            else _declarator_identifier(declarator)
        )
        if identifier is not None:
            defined.add(source[identifier.start_byte : identifier.end_byte].decode())
    defined.update({"size_t", "ptrdiff_t", "intptr_t", "uintptr_t", "bool"})
    defined.update(f"{prefix}int{width}_t" for prefix in ("", "u") for width in (8, 16, 32, 64))
    defined.update({"__int8", "__int16", "__int32", "__int64"})
    names = set()
    for node in _walk(tree.root_node):
        if node.type != "type_identifier" or node.parent is None:
            continue
        name = source[node.start_byte : node.end_byte].decode()
        parent = node.parent
        if (
            name in defined
            or parent.child_by_field_name("type") != node
            or not _C_IDENTIFIER.fullmatch(name)
        ):
            continue
        declarator = parent.child_by_field_name("declarator")
        while declarator is not None:
            if declarator.type in {"pointer_declarator", "abstract_pointer_declarator"}:
                names.add(name)
                break
            declarator = declarator.child_by_field_name("declarator")
    return sorted(names)


def prepare_source(code: str, context: dict, prefix: str) -> tuple[str, str | None, dict]:
    inspection = inspect_producer(code)
    definitions = function_definitions(code)
    evidence: dict[str, Any] = {
        "profile": context.get("profile", "producer-context-v2"),
        "context_files": context["files"],
        "declarations": {},
        "ambiguous": context["ambiguous"],
        "renames": [],
        "unresolved_calls": [],
        "original_sha256": hashlib.sha256(code.encode()).hexdigest(),
    }
    if inspection.invalid or len(definitions) != 1:
        evidence["status"] = "invalid_or_nonunique_entry_preserved"
        return (
            prefix + "\n" + code,
            definitions[0].name if len(definitions) == 1 else None,
            evidence,
        )
    function_name = definitions[0].name
    if not _QUALIFIED.fullmatch(function_name):
        evidence["status"] = "unsupported_entry_spelling"
        return prefix + "\n" + code, None, evidence
    transported, renames = transport_names(code)
    evidence["renames"] = renames
    blocked = set()
    if evidence["profile"] == "caller-contract-v3":
        from cpp_call_contracts import analyze_calls

        available = {
            name: prototype
            for name, prototype in _KNOWN_PROTOS.items()
            if name not in context["ambiguous"]
        }
        available.update(context["prototypes"])
        contracts = analyze_calls(code, available)
        evidence["call_contracts"] = contracts
        blocked = set(contracts["blocked_injection_names"])
    source = code.encode()
    tree = _parse_source(source)
    calls = set()
    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is not None:
                spelling = source[callee.start_byte : callee.end_byte].decode()
                if _QUALIFIED.fullmatch(spelling):
                    calls.add(spelling)
    declarations = []
    for name in sorted(calls):
        if name == function_name or name.startswith("__builtin_"):
            continue
        if name in blocked:
            continue
        prototype = context["prototypes"].get(name)
        origin = "same-producer consensus"
        if prototype is None and name not in context["ambiguous"] and name in _KNOWN_PROTOS:
            prototype, origin = _KNOWN_PROTOS[name], "existing libc contract"
        if prototype is None:
            evidence["unresolved_calls"].append(name)
        else:
            declarations.append(prototype)
            evidence["declarations"][name] = {"prototype": prototype, "origin": origin}
    initial = prefix + DECLARATION_PREFIX + "\n".join(declarations) + "\n" + transported
    forwards = pointer_forwards(initial)
    evidence["opaque_pointer_forwards"] = forwards
    evidence["status"] = "prepared_without_layout_or_body_repairs"
    return (
        prefix
        + DECLARATION_PREFIX
        + "\n".join(f"typedef struct {name} {name};" for name in forwards)
        + "\n"
        + "\n".join(declarations)
        + "\n"
        + transported,
        c_name(function_name),
        evidence,
    )
