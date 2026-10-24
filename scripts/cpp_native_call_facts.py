"""Bounded native call identity and declared facts; no default metric integration."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
from typing import Any

import capstone
from cpp_call_contracts import _arity, _function_declarator

from decbench.metrics.cpp_recovered_types import RecoveredTypeContext
from decbench.metrics.cpp_signature_evidence import native_signature, recovered_return
from decbench.metrics.cpp_type_facts import assess_recovery, extract_type_facts
from decbench.metrics.cpp_type_graph import TypeGraph, dwarf_graph, pdb_graph
from decbench.metrics.cpp_types import UnsupportedType
from decbench.metrics.variable_features import _declarator_identifier, _parse_source, _walk
from decbench.models.decompilation import FunctionDecompilation, LineMapping
from decbench.utils import binfmt
from decbench.utils.pdb_info import PdbFormatError, _unpack
from decbench.utils.producer_validation import inspect_producer


def decode_function(resolver: Any, name: str, address: int) -> list[Any]:
    try:
        code = resolver.resolve(name, address)
    except ValueError as error:
        raise UnsupportedType(str(error)) from error
    mode = binfmt.capstone_arch_mode(resolver.info)
    if mode is None:
        raise UnsupportedType("unsupported native decoder")
    decoder = capstone.Cs(*mode)
    decoder.detail = True
    instructions = []
    for start, end in code.ranges:
        regions = [(a, b) for a, b in resolver.regions if a <= start < end <= a + len(b)]
        if len(regions) != 1:
            raise UnsupportedType("native function has ambiguous executable bytes")
        base, region = regions[0]
        data = region[start - base : end - base]
        decoded = list(decoder.disasm(data, start))
        if sum(i.size for i in decoded) != len(data):
            raise UnsupportedType("native function is not completely decoded")
        instructions.extend(decoded)
    if len({i.address for i in instructions}) != len(instructions):
        raise UnsupportedType("overlapping native instruction ranges")
    return instructions


def native_calls(instructions: list[Any], entries: dict[int, list[Any]]) -> list[dict]:
    rows = []
    for instruction in instructions:
        if not instruction.group(capstone.CS_GRP_CALL):
            continue
        target = None
        if len(instruction.operands) == 1 and instruction.operands[0].type == capstone.CS_OP_IMM:
            target = instruction.operands[0].imm
        identities = entries.get(target, []) if target is not None else []
        row = {
            "pc": instruction.address,
            "bytes": bytes(instruction.bytes).hex(),
            "mnemonic": instruction.mnemonic,
            "operands": instruction.op_str,
            "encoded_target": target,
            "target_status": (
                "unique_native_entry"
                if len(identities) == 1
                else (
                    "ambiguous_native_entry"
                    if identities
                    else "indirect_target" if target is None else "unresolved_entry_or_stub"
                )
            ),
        }
        if len(identities) == 1:
            row["target_entry"] = target
        rows.append(row)
    return rows


def bind_calls(
    function: FunctionDecompilation, contracts: dict, instructions: list[Any], calls: list[dict]
) -> dict:
    """One source call ↔ one mapped native call, without printed-name matching."""
    if inspect_producer(function.decompiled_code, function.metadata).invalid:
        rejected = [
            {**call, "binding_status": "invalid_producer_output"} for call in contracts["calls"]
        ]
        return {
            "calls": rejected,
            "summary": {"invalid_producer_output": len(rejected)},
            "name_matching_used": False,
            "scoped_definition_mapping_used": False,
        }
    starts = {i.address for i in instructions}
    native = {c["pc"]: c for c in calls}
    explicit_maps = [
        LineMapping.model_validate(m) for m in function.metadata.get("call_mappings", [])
    ]
    for mapping in explicit_maps:
        if (
            mapping.call_site is None
            or mapping.defined_variables != []
            or mapping.addresses != [mapping.call_site.instruction_address]
        ):
            raise ValueError("call-only transport has an invalid ownership scope")
    source = function.decompiled_code.encode()
    candidates: list[dict] = []
    ownership: dict[int, list[int]] = defaultdict(list)
    for index, call in enumerate(contracts["calls"]):
        first = source.count(b"\n", 0, call["start_byte"]) + 1
        last = source.count(b"\n", 0, max(call["start_byte"], call["end_byte"] - 1)) + 1
        unscoped = [
            m
            for m in function.line_mappings
            if m.defined_variables is None and first <= m.line_number <= last
        ]
        explicit = [
            m
            for m in explicit_maps
            if m.call_site is not None
            and first == last == m.line_number
            and m.defined_variables == []
            and m.addresses == [m.call_site.instruction_address]
        ]
        pcs = {pc for m in [*unscoped, *explicit] for pc in m.addresses}
        invalid = sorted(pcs - starts)
        eligible = sorted(pcs & native.keys())
        for pc in eligible:
            ownership[pc].append(index)
        row = {
            **call,
            "call_index": index,
            "mapped_call_pcs": eligible,
            "invalid_mapped_pcs": invalid,
            "line_span": [first, last],
            "explicit_call_scope": bool(explicit),
        }
        if invalid:
            row["binding_status"] = "invalid_instruction_mapping"
        elif len(eligible) != 1:
            row["binding_status"] = (
                "missing_call_mapping" if not eligible else "ambiguous_call_mapping"
            )
        else:
            row["binding_status"] = "candidate"
        candidates.append(row)
    for row in candidates:
        if row["binding_status"] != "candidate":
            continue
        pc = row["mapped_call_pcs"][0]
        if len(ownership[pc]) != 1:
            row["binding_status"] = "shared_native_call_claim"
        else:
            row["binding_status"] = "unique_instruction_link"
            row["native"] = native[pc]
    return {
        "calls": candidates,
        "summary": dict(Counter(r["binding_status"] for r in candidates)),
        "name_matching_used": False,
        "scoped_definition_mapping_used": False,
    }


def _field_fact_count(facts: Any) -> int:
    return sum(any(part.startswith("field@") for part in f.path) for f in facts.facts)


def declared_signature(context: Any, address: int, model: str) -> dict:
    signature = native_signature(context, address, model)
    parameters: list[dict] = []
    reasons = []
    if context.dwarf is not None:
        candidates = {die.offset: die for die in context.index.get(address, [])}
        if len(candidates) != 1:
            raise UnsupportedType("native signature entry is ambiguous")
        function = next(iter(candidates.values()))
        children = list(function.iter_children())
        if binfmt.die_attr(function, "DW_AT_object_pointer", follow_abstract_origin=True):
            reasons.append("member_object_parameter")
        if binfmt.die_attr(function, "DW_AT_abstract_origin"):
            reasons.append("abstract_origin_formal_population")
        if any(c.tag == "DW_TAG_unspecified_parameters" for c in children):
            reasons.append("variadic_signature")
        cc = binfmt.die_attr(function, "DW_AT_calling_convention", follow_abstract_origin=True)
        if cc is not None and cc.value != 1:
            reasons.append("nondefault_calling_convention")
        formals = [c for c in children if c.tag == "DW_TAG_formal_parameter"]
        specification = function.attributes.get("DW_AT_specification")
        if not formals and specification is not None:
            declaration = function.get_DIE_from_attribute("DW_AT_specification")
            if any(c.tag == "DW_TAG_formal_parameter" for c in declaration.iter_children()):
                reasons.append("inherited_formal_population")
        for ordinal, formal in enumerate(formals):
            artificial = binfmt.die_attr(formal, "DW_AT_artificial", follow_abstract_origin=True)
            if artificial is not None and artificial.value:
                reasons.append("artificial_formal")
            try:
                graph = dwarf_graph(formal, model)
                parameters.append(
                    {
                        "ordinal": ordinal,
                        "graph": graph,
                        "debug_identity": f"dwarf:0x{formal.offset:x}",
                    }
                )
            except UnsupportedType as error:
                reasons.append("unsupported_formal_type")
                parameters.append({"ordinal": ordinal, "exclusion": str(error)})
    else:
        try:
            if context.pdb.types is None:
                raise UnsupportedType("PDB type records unavailable")
            function = context.pdb.at_address(address)
            record = (
                context.pdb.types.records.get(function.signature_type_index) if function else None
            )
            if record is None or record[0] != 0x1008:
                raise UnsupportedType("PDB nonmember procedure signature required")
            payload = record[1]
            if len(payload) < 12:
                raise PdbFormatError("truncated PDB procedure signature")
            _, convention, _, count, argument_list = _unpack("<IBBHI", payload)
            if convention != 0:
                reasons.append("nondefault_calling_convention")
            argument_record = context.pdb.types.records.get(argument_list)
            if (
                argument_record is None
                or argument_record[0] != 0x1201
                or len(argument_record[1]) < 4
            ):
                raise UnsupportedType("PDB explicit argument list unavailable")
            data = argument_record[1]
            actual = _unpack("<I", data)[0]
            if actual != count or len(data) < 4 + actual * 4:
                raise UnsupportedType("PDB argument count or extent is ambiguous")
            for ordinal in range(count):
                index = _unpack("<I", data, 4 + ordinal * 4)[0]
                if index == 0:
                    reasons.append("variadic_signature")
                    parameters.append({"ordinal": ordinal, "exclusion": "ellipsis"})
                    continue
                try:
                    parameters.append(
                        {
                            "ordinal": ordinal,
                            "graph": pdb_graph(context.pdb.types, index, model),
                            "debug_identity": f"pdb:argument:{ordinal}:0x{index:x}",
                        }
                    )
                except UnsupportedType as error:
                    reasons.append("unsupported_formal_type")
                    parameters.append({"ordinal": ordinal, "exclusion": str(error)})
        except (UnsupportedType, PdbFormatError) as error:
            reasons.append("pdb_formal_evidence_unavailable: " + str(error))
    allowed = {"signed", "unsigned", "char", "bool", "float", "pointer", "lref", "rref"}
    for parameter in parameters:
        parameter_graph = parameter.get("graph")
        if (
            parameter_graph is not None
            and parameter_graph.nodes[parameter_graph.root].kind not in allowed
        ):
            reasons.append("aggregate_or_special_formal_lowering")
    if signature.declared_return is None:
        reasons.append("unavailable_or_aggregate_return")
    return {
        "address": address,
        "parameters": parameters,
        "return_graph": signature.declared_return,
        "return_exclusion": signature.return_exclusion,
        "formal_order_eligible": not reasons,
        "formal_order_exclusions": sorted(set(reasons)),
        "abi_slots_verified": False,
    }


def _recovered_parameters(code: str, model: str) -> list[TypeGraph]:
    source = code.encode()
    tree = _parse_source(source)
    definitions = [n for n in _walk(tree.root_node) if n.type == "function_definition"]
    if len(definitions) != 1 or definitions[0].has_error:
        raise UnsupportedType("one error-free recovered definition required")
    declarator = _function_declarator(definitions[0].child_by_field_name("declarator"))
    if declarator is None:
        raise UnsupportedType("unsupported recovered function declarator")
    arity = _arity(declarator, source, definition=True)
    if arity["kind"] != "fixed":
        raise UnsupportedType("fixed recovered parameter list required")
    if arity["count"] == 0:
        return []
    parameters = declarator.child_by_field_name("parameters")
    if parameters is None:
        raise UnsupportedType("recovered parameter list missing")
    context = RecoveredTypeContext(code, model)
    graphs = []
    for parameter in parameters.named_children:
        if parameter.type == "comment":
            continue
        ty = parameter.child_by_field_name("type")
        if ty is None:
            raise UnsupportedType("recovered parameter type missing")
        qualifiers = [
            source[n.start_byte : n.end_byte].decode()
            for n in parameter.named_children
            if n.type == "type_qualifier"
        ]
        suffix = []
        variable = parameter.child_by_field_name("declarator")
        while variable is not None and variable.type in {
            "pointer_declarator",
            "reference_declarator",
        }:
            if any(c.type == "type_qualifier" for c in variable.named_children):
                raise UnsupportedType("qualified parameter indirection unsupported")
            suffix.append(
                "*"
                if variable.type == "pointer_declarator"
                else (
                    "&&"
                    if source[variable.start_byte : variable.end_byte].lstrip().startswith(b"&&")
                    else "&"
                )
            )
            child = variable.child_by_field_name("declarator")
            if child is None and len(variable.named_children) == 1:
                child = variable.named_children[0]
            variable = child
        if variable is not None and variable != _declarator_identifier(variable):
            raise UnsupportedType("array/function/member pointer parameter unsupported")
        spelling = " ".join([*qualifiers, source[ty.start_byte : ty.end_byte].decode()]) + "".join(
            suffix
        )
        graphs.append(context.graph(spelling))
    return graphs


def compare_signature(native: dict, function: FunctionDecompilation, model: str) -> dict:
    invalid = inspect_producer(function.decompiled_code, function.metadata).invalid
    result: dict[str, Any] = {
        "parameters": [],
        "formal_order_eligible": native["formal_order_eligible"],
        "formal_order_exclusions": native["formal_order_exclusions"],
        "abi_slots_verified": False,
        "actual_field_access_verified": False,
    }
    expected_return = native["return_graph"]
    actual_return = None
    exclusion = None
    if not invalid:
        try:
            actual_return = recovered_return(function.decompiled_code, model)
        except UnsupportedType as error:
            exclusion = str(error)
    if expected_return is not None:
        verdict = (
            "correct"
            if actual_return is not None
            and expected_return.project("abi") == actual_return.project("abi")
            else (
                "type_mismatch"
                if actual_return is not None
                else "invalid_producer_output" if invalid else "unsupported_recovered_type"
            )
        )
        result["return"] = {
            "oracle_eligible": True,
            "strict_agreement": verdict == "correct",
            "recovery_exclusion": exclusion,
            **assess_recovery(
                extract_type_facts(expected_return),
                extract_type_facts(actual_return) if actual_return else None,
                verdict,
            ),
        }
    else:
        result["return"] = {"oracle_eligible": False, "exclusion": native["return_exclusion"]}
    recovered = None
    parameter_exclusion = "invalid_producer_output" if invalid else None
    if not invalid and native["formal_order_eligible"]:
        try:
            recovered = _recovered_parameters(function.decompiled_code, model)
        except UnsupportedType as error:
            parameter_exclusion = str(error)
    result["parameter_recovery_exclusion"] = parameter_exclusion
    if native["formal_order_eligible"]:
        result["parameter_count_agreement"] = recovered is not None and len(recovered) == len(
            native["parameters"]
        )
        for parameter in native["parameters"]:
            expected = parameter["graph"]
            actual = (
                recovered[parameter["ordinal"]]
                if recovered is not None and result["parameter_count_agreement"]
                else None
            )
            ef = extract_type_facts(expected)
            af = extract_type_facts(actual) if actual is not None else None
            correct = actual is not None and expected.project("abi") == actual.project("abi")
            result["parameters"].append(
                {
                    "ordinal": parameter["ordinal"],
                    "strict_agreement": correct,
                    "declared_field_facts": _field_fact_count(ef),
                    **assess_recovery(
                        ef,
                        af,
                        (
                            "correct"
                            if correct
                            else (
                                "type_mismatch"
                                if actual is not None
                                else "invalid_producer_output" if invalid else "unmatched"
                            )
                        ),
                    ),
                }
            )
    return result


def serial_signature(native: dict) -> dict:
    return {
        **native,
        "return_graph": asdict(native["return_graph"]) if native["return_graph"] else None,
        "parameters": [
            {**p, **({"graph": asdict(p["graph"])} if "graph" in p else {})}
            for p in native["parameters"]
        ],
    }
