# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Fail-closed textual analysis for already captured CBMC 6.11 dumps."""

from __future__ import annotations

import re
from dataclasses import dataclass

_ALLOC_ID = re.compile(r"AllocId\(([0-9]+), ThreadLocalIndex\)")
_SYMBOL_START = re.compile(r"^Symbol\.\.\.\.\.\.: (.*?)(?:\r?\n)?$")
_FIELD_LABEL = re.compile(r"^([A-Za-z ]+\.+:)")
_TYPE_LABEL = "Type........:"
_TAG_SYMBOL = re.compile(r"^tag-(.+)$")
_WRAPPER_SYMBOL = re.compile(r"^tag-.+::[^:]+$")
_AGGREGATE = re.compile(r"^struct (?P<tag>[^ {}]+) \{(?P<body>.*)\}$")
_STRUCT_FIELD = re.compile(
    r"^struct (?P<tag>[^\s{}]+) (?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<array>\[[0-9]+\])?$"
)
_BITVECTOR_FIELD = re.compile(
    r"^unsigned __CPROVER_bitvector\[(?P<bits>[0-9]+)\] "
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)$"
)
_PADDING_PRIMITIVE_FIELD = re.compile(
    r"^(?:unsigned )?(?:char|short int|int|long int|long long int) "
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)$"
)


def normalize(text: str) -> str:
    """Renumber exact AllocId(N, ThreadLocalIndex) tokens by first occurrence."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    numbers: dict[str, int] = {}

    def replace(match: re.Match[str]) -> str:
        number = match.group(1)
        if number not in numbers:
            numbers[number] = len(numbers)
        return f"AllocId({numbers[number]}, ThreadLocalIndex)"

    return _ALLOC_ID.sub(replace, text)


@dataclass(frozen=True)
class _Block:
    name: str
    lines: tuple[str, ...]
    type_index: int | None

    @property
    def type_text(self) -> str | None:
        if self.type_index is None:
            return None
        line = self.lines[self.type_index]
        prefix, sep, value = line.partition(":")
        if not sep or prefix + ":" != _TYPE_LABEL:
            return None
        value = value[1:] if value.startswith(" ") else value
        return value.rstrip("\r\n")


@dataclass(frozen=True)
class _Dump:
    prefix: tuple[str, ...]
    blocks: tuple[_Block, ...]


def _parse_dump(text: str) -> _Dump | None:
    """Parse records while retaining every byte of surrounding dump text."""
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if _SYMBOL_START.match(line)]
    if not starts:
        return None
    prefix = tuple(lines[: starts[0]])
    blocks: list[_Block] = []
    for j, start in enumerate(starts):
        end = starts[j + 1] if j + 1 < len(starts) else len(lines)
        block_lines = tuple(lines[start:end])
        match = _SYMBOL_START.match(block_lines[0])
        assert match is not None
        name = match.group(1)
        labels: set[str] = set()
        type_indices: list[int] = []
        for index, line in enumerate(block_lines[1:], 1):
            logical_line = line.rstrip("\r\n")
            label = _FIELD_LABEL.match(logical_line)
            if label:
                label_text = label.group(1)
                if label_text in labels:
                    return None
                labels.add(label_text)
                if label_text == _TYPE_LABEL:
                    type_indices.append(index)
        if len(type_indices) > 1:
            return None
        blocks.append(_Block(name, block_lines, type_indices[0] if type_indices else None))
    if len({block.name for block in blocks}) != len(blocks):
        return None
    return _Dump(prefix, tuple(blocks))


def _aggregate(type_text: str, expected_symbol: str) -> tuple[str, list[str]] | None:
    match = _AGGREGATE.fullmatch(type_text)
    tag = _TAG_SYMBOL.fullmatch(expected_symbol)
    if match is None or tag is None or match.group("tag") != tag.group(1):
        return None
    declarations = [part.strip() for part in match.group("body").split(";") if part.strip()]
    return match.group("tag"), declarations


def _aggregate_raw(type_text: str, expected_symbol: str) -> tuple[str, list[str]] | None:
    match = _AGGREGATE.fullmatch(type_text)
    tag = _TAG_SYMBOL.fullmatch(expected_symbol)
    if match is None or tag is None or match.group("tag") != tag.group(1):
        return None
    return match.group("tag"), match.group("body").split(";")


def _block_value(block: _Block, label: str) -> str | None:
    values = []
    for line in block.lines[1:]:
        logical = line.rstrip("\r\n")
        if logical.startswith(label):
            values.append(logical[len(label) :].lstrip(" "))
    return values[0] if len(values) == 1 else None


def _positive_padding(declaration: str) -> bool:
    bitvector = _BITVECTOR_FIELD.fullmatch(declaration)
    if bitvector is not None:
        return int(bitvector.group("bits")) > 0
    return _PADDING_PRIMITIVE_FIELD.fullmatch(declaration) is not None


def _field(declaration: str) -> tuple[str, str, str] | None:
    """Return (field name, raw struct tag, array suffix) for struct fields."""
    match = _STRUCT_FIELD.fullmatch(declaration)
    if match is None:
        return None
    return match.group("name"), match.group("tag"), match.group("array") or ""


def _is_zero_width_struct(raw_tag: str, dump: _Dump, seen: frozenset[str] = frozenset()) -> bool:
    if raw_tag in seen:
        return False
    symbol_name = "tag-" + raw_tag
    block = next((b for b in dump.blocks if b.name == symbol_name), None)
    if block is None or block.type_text is None:
        return False
    parsed = _aggregate(block.type_text, symbol_name)
    if parsed is None:
        return False
    _, declarations = parsed
    nested_seen = seen | {raw_tag}
    for declaration in declarations:
        field = _field(declaration)
        if field is not None:
            _, nested_tag, _ = field
            if not _is_zero_width_struct(nested_tag, dump, nested_seen):
                return False
            continue
        padding = _BITVECTOR_FIELD.fullmatch(declaration)
        if padding is not None and int(padding.group("bits")) == 0:
            continue
        return False
    return True


def _wrapper_transition(
    old_symbol: str, old_type: str, new_type: str, old_dump: _Dump
) -> tuple[bool, str]:
    if not _WRAPPER_SYMBOL.fullmatch(old_symbol):
        return False, "changed symbol is not a tag-<union>::<arm> wrapper"
    old_agg, new_agg = _aggregate(old_type, old_symbol), _aggregate(new_type, old_symbol)
    old_raw, new_raw = _aggregate_raw(old_type, old_symbol), _aggregate_raw(new_type, old_symbol)
    if old_agg is None or new_agg is None or old_raw is None or new_raw is None or old_agg[0] != new_agg[0]:
        return False, "wrapper struct type/tag is unknown"
    old_decls, new_decls = old_agg[1], new_agg[1]
    old_payloads: list[tuple[str, str, str]] = []
    new_payloads: list[tuple[str, str, str]] = []
    old_padding: list[str] = []
    new_padding: list[str] = []

    for declaration, payloads, padding in (
        *((d, old_payloads, old_padding) for d in old_decls),
        *((d, new_payloads, new_padding) for d in new_decls),
    ):
        field = _field(declaration)
        if field is not None:
            name, raw_tag, array_suffix = field
            if name.endswith("_padding"):
                padding.append(declaration)
            else:
                payloads.append((name, raw_tag, array_suffix))
            continue
        bitvector = _BITVECTOR_FIELD.fullmatch(declaration)
        if bitvector is not None and bitvector.group("name").endswith("_padding"):
            padding.append(declaration)
            continue
        primitive_padding = _PADDING_PRIMITIVE_FIELD.fullmatch(declaration)
        if primitive_padding is not None and primitive_padding.group("name").endswith("_padding"):
            padding.append(declaration)
            continue
        return False, "wrapper contains an unrecognized or unrelated component"

    if len(old_payloads) != 1 or len(new_payloads) != 1:
        return False, "wrapper must contain exactly one payload component"
    old_payload, new_payload = old_payloads[0], new_payloads[0]
    if old_payload[0] != new_payload[0] or old_padding != new_padding:
        return False, "payload identity or padded-wrapper fields changed"
    arm_name = old_symbol.rsplit("::", 1)[-1]
    if old_payload[0] != arm_name:
        return False, "payload field name does not match its union arm"
    if len(old_padding) != 1 or not old_padding[0].endswith("_padding"):
        return False, "B3 wrapper must have exactly one padding component"
    padding_decl = old_padding[0]
    padding_name = padding_decl.rsplit(" ", 1)[-1]
    if padding_name != old_payload[0] + "_padding" or not _positive_padding(padding_decl):
        return False, "wrapper padding is not the matching positive-width arm padding"
    if new_payload[1:] != ("Unit", ""):
        return False, "new payload is not Unit"
    if old_payload[2] and not re.fullmatch(r"\[[1-9][0-9]*\]", old_payload[2]):
        return False, "old array payload length is not a known positive constant"
    if not _is_zero_width_struct(old_payload[1], old_dump) or not _is_zero_width_struct("Unit", old_dump):
        return False, "old or Unit payload type is not proven zero-width from the symbol table"
    if old_payload[1:] == new_payload[1:]:
        return False, "wrapper payload type did not change"
    # Keep field ordering and every byte of the aggregate type identical except
    # for the payload declaration itself. This protects padding offsets and
    # rejects whitespace, punctuation, or unrelated field changes.
    raw_old, raw_new = old_raw[1], new_raw[1]
    stripped_old = [part.strip() for part in raw_old]
    stripped_new = [part.strip() for part in raw_new]
    old_payload_indices = [i for i, part in enumerate(stripped_old)
                           if (candidate := _field(part)) is not None and not candidate[0].endswith("_padding")]
    new_payload_indices = [i for i, part in enumerate(stripped_new)
                           if (candidate := _field(part)) is not None and not candidate[0].endswith("_padding")]
    if len(old_payload_indices) != 1 or new_payload_indices != old_payload_indices or len(raw_old) != len(raw_new):
        return False, "payload component position changed"
    payload_index = old_payload_indices[0]
    for index, (old_part, new_part) in enumerate(zip(raw_old, raw_new)):
        if index != payload_index:
            if old_part != new_part:
                return False, "wrapper text, field order, or padding changed outside payload"
            continue
        old_core = old_part.strip()
        new_core = new_part.strip()
        old_leading = old_part[: len(old_part) - len(old_part.lstrip())]
        old_trailing = old_part[len(old_part.rstrip()) :]
        new_leading = new_part[: len(new_part) - len(new_part.lstrip())]
        new_trailing = new_part[len(new_part.rstrip()) :]
        if old_leading != new_leading or old_trailing != new_trailing:
            return False, "payload declaration whitespace changed outside replacement"
        if old_leading + new_core + old_trailing != new_part:
            return False, "payload replacement altered surrounding type text"
    return True, "zero-width wrapper payload changed to Unit; wrapper padding is unchanged"


def _wrapper_differences(symbol_a: str, symbol_b: str) -> tuple[list[str] | None, str]:
    a, b = _parse_dump(symbol_a), _parse_dump(symbol_b)
    if a is None or b is None:
        return None, "symbol dump is malformed, duplicated, or lacks CBMC symbol records"
    if a.prefix != b.prefix or len(a.blocks) != len(b.blocks):
        return None, "dump prefix/suffix or symbol inventory changed"
    changed: list[str] = []
    for ba, bb in zip(a.blocks, b.blocks):
        if ba.name != bb.name or ba.type_index != bb.type_index:
            return None, "symbol order, names, or type-field inventory changed"
        if ba.lines == bb.lines:
            continue
        if ba.type_index is None:
            return None, f"non-type dump text changed for {ba.name}"
        ia = ib = ba.type_index
        if ba.lines[:ia] != bb.lines[:ib] or ba.lines[ia + 1 :] != bb.lines[ib + 1 :]:
            return None, f"dump text outside Type field changed for {ba.name}"
        old_type, new_type = ba.type_text, bb.type_text
        if old_type is None or new_type is None:
            return None, f"Type field is not a supported single-line value for {ba.name}"
        flags = _block_value(ba, "Flags.......:")
        if flags is None or "type" not in flags.split():
            return None, f"changed wrapper symbol lacks its type flag: {ba.name}"
        valid, reason = _wrapper_transition(ba.name, old_type, new_type, a)
        if not valid:
            return None, f"{ba.name}: {reason}"
        changed.append(ba.name)
    if not changed:
        return None, "symbol dumps differ outside recognized wrapper type fields"
    return changed, "all symbol changes are verified zero-width wrapper payload changes"


def control(symbol_a: str, symbol_b: str, functions_a: str, functions_b: str) -> dict:
    """Validate the designated [(); 2] -> Unit positive control."""
    if normalize(functions_a) != normalize(functions_b):
        return {"valid": False, "reason": "function dumps differ"}
    changed, reason = _wrapper_differences(normalize(symbol_a), normalize(symbol_b))
    if changed is None:
        return {"valid": False, "reason": reason}
    if len(changed) != 1:
        return {"valid": False, "reason": "control must change only ArrayUnion::zst_array"}
    a, b = _parse_dump(normalize(symbol_a)), _parse_dump(normalize(symbol_b))
    assert a is not None and b is not None
    old_block = next(block for block in a.blocks if block.name == changed[0])
    new_block = next(block for block in b.blocks if block.name == changed[0])
    pretty_name = _block_value(old_block, "Pretty name.:")
    base_name = _block_value(old_block, "Base name...:")
    flags = _block_value(old_block, "Flags.......:")
    expected_base_name = changed[0].removeprefix("tag-")
    if pretty_name is None or not pretty_name.endswith("::ArrayUnion::zst_array") or base_name != expected_base_name or flags is None or "type" not in flags.split():
        return {"valid": False, "reason": "control type symbol is not bound to ArrayUnion::zst_array by symbol metadata"}
    old = old_block.type_text
    new = new_block.type_text
    assert old is not None and new is not None
    parsed_old, parsed_new = _aggregate(old, changed[0]), _aggregate(new, changed[0])
    if parsed_old is None or parsed_new is None:
        return {"valid": False, "reason": "control wrapper type is unparseable"}
    old_payloads = [f for d in parsed_old[1] if (f := _field(d)) and not f[0].endswith("_padding")]
    new_payloads = [f for d in parsed_new[1] if (f := _field(d)) and not f[0].endswith("_padding")]
    if len(old_payloads) != 1 or len(new_payloads) != 1 or old_payloads[0][1:] != ("Unit", "[2]") or new_payloads[0][1:] != ("Unit", ""):
        return {"valid": False, "reason": "control payload is not exactly [(); 2] -> Unit"}
    return {"valid": True, "reason": "ArrayUnion::zst_array [(); 2] -> Unit; functions and other dump text match"}


def classify(symbol_a: str, symbol_b: str, functions_a: str, functions_b: str) -> dict:
    """Classify differences; only proven wrapper payload changes get WRAPPER_ONLY."""
    sa, sb = normalize(symbol_a), normalize(symbol_b)
    fa, fb = normalize(functions_a), normalize(functions_b)
    if sa == sb and fa == fb:
        return {"class": "EQUAL", "details": "normalized symbol and function dumps match"}
    changed, reason = ([], "normalized symbol dumps match") if sa == sb else _wrapper_differences(sa, sb)
    symbol_class = "EQUAL" if sa == sb else ("WRAPPER_ONLY" if changed is not None else "OTHER_CHANGES")
    if fa != fb:
        result = {"class": "FUNCTION_CHANGES", "details": "normalized function dumps differ",
                  "symbol_class": symbol_class, "symbol_details": reason}
        if changed is not None:
            result["symbols"] = changed
        return result
    if changed is not None:
        return {"class": "WRAPPER_ONLY", "details": reason, "symbols": changed}
    return {"class": "OTHER_CHANGES", "details": reason}
