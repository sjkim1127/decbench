#!/usr/bin/env python3
"""Apply the validated ICF/DWARF concrete-address guard for CI validation."""

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f"expected exactly one match in {path}, found {text.count(old)}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "decbench/utils/binfmt.py",
    '''def tool_available(name: str) -> bool:\n    return shutil.which(name) is not None\n\n\n# Codegen-relevant flags carried over from the original build''',
    '''def tool_available(name: str) -> bool:\n    return shutil.which(name) is not None\n\n\ndef executable_address_status(path: Path, address: int) -> bool | None:\n    """Whether ``address`` belongs to a concrete executable ELF section.\n\n    ``False`` is returned only when executable sections are available and none\n    contains the address. ``None`` means the format/section table could not\n    provide a reliable answer. This distinction lets DWARF consumers reject\n    linker-produced sentinel ``low_pc == 0`` DIEs without breaking firmware\n    whose real ``.text`` legitimately starts at address zero.\n    """\n    info = detect(path)\n    if info is None or info.fmt != "elf":\n        return None\n    try:\n        from elftools.elf.elffile import ELFFile\n\n        with path.open("rb") as stream:\n            elf = ELFFile(stream)\n            saw_executable = False\n            for section in elf.iter_sections():\n                if section.header["sh_type"] == "SHT_NOBITS":\n                    continue\n                if not int(section.header["sh_flags"]) & 0x4:  # SHF_EXECINSTR\n                    continue\n                size = int(section.header["sh_size"])\n                if size <= 0:\n                    continue\n                saw_executable = True\n                start = int(section.header["sh_addr"])\n                if start <= address < start + size:\n                    return True\n            return False if saw_executable else None\n    except Exception:\n        return None\n\n\n# Codegen-relevant flags carried over from the original build''',
)

replace_once(
    "decbench/utils/binfmt.py",
    '''    owners: dict[int, tuple[str, str]] = {}\n    file_tables: dict[int, list] = {}\n    stem_index = build_stem_index(source_stems)\n    try:\n        for cu in dw.iter_CUs():\n            for die in cu.iter_DIEs():\n                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:\n                    continue\n                name = die_str_attr(''',
    '''    owners: dict[int, tuple[str, str]] = {}\n    file_tables: dict[int, list] = {}\n    stem_index = build_stem_index(source_stems)\n    zero_address_status = executable_address_status(path, 0)\n    try:\n        for cu in dw.iter_CUs():\n            for die in cu.iter_DIEs():\n                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:\n                    continue\n                address = int(die.attributes["DW_AT_low_pc"].value)\n                if address == 0 and zero_address_status is False:\n                    continue\n                name = die_str_attr(''',
)

replace_once(
    "decbench/utils/binfmt.py",
    '''                if matched is not None:\n                    owners[int(die.attributes["DW_AT_low_pc"].value)] = (name, matched)''',
    '''                if matched is not None:\n                    owners[address] = (name, matched)''',
)

replace_once(
    "decbench/utils/function_identity.py",
    '''    dwarf = binfmt.dwarf_info(binary_path)\n    if dwarf is None:\n        return []\n\n    by_address: dict[int, FunctionIdentity] = {}\n    for cu in dwarf.iter_CUs():''',
    '''    dwarf = binfmt.dwarf_info(binary_path)\n    if dwarf is None:\n        return []\n\n    zero_address_status = binfmt.executable_address_status(binary_path, 0)\n    by_address: dict[int, FunctionIdentity] = {}\n    for cu in dwarf.iter_CUs():''',
)

replace_once(
    "decbench/utils/function_identity.py",
    '''            linkage = binfmt.die_str_attr(die, "DW_AT_linkage_name")\n            if linkage is None:\n                linkage = binfmt.die_str_attr(die, "DW_AT_MIPS_linkage_name")\n\n            identity = FunctionIdentity(\n                address=int(die.attributes["DW_AT_low_pc"].value),\n                name=name,\n                linkage_name=linkage,\n            )''',
    '''            address = int(die.attributes["DW_AT_low_pc"].value)\n            if address == 0 and zero_address_status is False:\n                continue\n\n            linkage = binfmt.die_str_attr(die, "DW_AT_linkage_name")\n            if linkage is None:\n                linkage = binfmt.die_str_attr(die, "DW_AT_MIPS_linkage_name")\n\n            identity = FunctionIdentity(\n                address=address,\n                name=name,\n                linkage_name=linkage,\n            )''',
)
