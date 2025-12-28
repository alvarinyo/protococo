"""
Protococo Analyzer v1.0

Decodes and validates binary messages against protocol definitions.
"""

from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from coco_ast import (
    CocoFile, Message, Field,
    IntegerType, BytesType, StringType, PadType, BitFieldType,
    EnumTypeRef,
    LiteralSize, FieldRefSize, VariableSize, GreedySize, SizeExpr, FillToSize, UntilSize, BranchDeterminedSize,
    EnumValue, MatchClause,
    Endianness,
)


@dataclass
class FieldValue:
    """Wrapper for nested field values storing both hex and decoded representations."""
    hex: str
    val: Any


@dataclass
class DecodeResult:
    """Result of decoding a single field."""
    name: str
    hex_value: str
    decoded_value: Any
    is_valid: bool
    expected_hex: str | None = None  # For fixed-value fields
    errors: list[str] = None
    is_constrained: bool = False  # True if field has enum type or default value
    is_unbounded: bool = False  # True if field consumed remaining bytes without explicit size
    promoted_fields: dict[str, Any] = None # Fields from attached match to be splatted

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.promoted_fields is None:
            self.promoted_fields = {}


@dataclass
class ValidationResult:
    """Result of validating a complete message."""
    is_valid: bool
    message_name: str
    fields: list[DecodeResult]
    remaining_bytes: str = ""
    errors: list[str] = None
    protocol_chain: list[str] = None  # Chain of layer field names (e.g., ["eth", "ip", "tcp"])

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.protocol_chain is None:
            self.protocol_chain = []

    @property
    def total_matched_bytes(self) -> int:
        return sum(len(f.hex_value) // 2 for f in self.fields)

    @property
    def total_matched_fields(self) -> int:
        return len([f for f in self.fields if f.is_valid])

    @property
    def validated_constraints(self) -> int:
        """Count of constrained fields (enum or default value) that validated successfully."""
        return len([f for f in self.fields if f.is_valid and f.is_constrained])

    @property
    def total_structured_fields(self) -> int:
        """Count all leaf fields recursively, including nested structures.

        This gives higher scores to messages that parse bytes into structured
        fields rather than dumping them into a catch-all bytes[] field.
        """
        def count_fields(value) -> int:
            if isinstance(value, dict):
                total = 0
                for v in value.values():
                    if isinstance(v, FieldValue):
                        total += count_fields(v.val)
                    elif isinstance(v, dict):
                        total += count_fields(v)
                    else:
                        total += 1  # Leaf value
                return total
            elif isinstance(value, list):
                return sum(count_fields(item) for item in value)
            else:
                return 1  # Leaf value

        total = 0
        for field in self.fields:
            if isinstance(field.decoded_value, (dict, list)):
                total += count_fields(field.decoded_value)
            else:
                total += 1
        return total

    @property
    def minimal_array_elements(self) -> int:
        """Count array elements with single integer field (failed enum validation).

        In polymorphic arrays, elements matching the base type have just the
        discriminator field. If that field's value is an integer instead of an
        enum string (like 'TcpOptKind.NOP'), it indicates failed validation.

        This distinguishes garbage parsing from legitimate single-field elements:
        - Valid NOP option: {kind: 'TcpOptKind.NOP'} -> not counted
        - Garbage parse: {kind: 123} -> counted

        This is structural - checks value type, not field names.
        """
        def count_invalid_single_field(items: list) -> int:
            """Count array elements with 1 field whose value is an integer."""
            count = 0
            for item in items:
                if isinstance(item, dict) and len(item) == 1:
                    # Get the single field's value
                    val = next(iter(item.values()))
                    if isinstance(val, FieldValue):
                        val = val.val
                    # Count if the value is an integer (failed enum)
                    if isinstance(val, int):
                        count += 1
            return count

        def scan_value(value) -> int:
            """Recursively scan for invalid single-field array elements."""
            if isinstance(value, dict):
                total = 0
                for v in value.values():
                    if isinstance(v, FieldValue):
                        total += scan_value(v.val)
                    elif isinstance(v, (dict, list)):
                        total += scan_value(v)
                return total
            elif isinstance(value, list):
                # Count invalid single-field elements in this array
                minimal = count_invalid_single_field(value)
                # Also recurse into nested structures
                for item in value:
                    if isinstance(item, dict):
                        for v in item.values():
                            if isinstance(v, FieldValue):
                                minimal += scan_value(v.val)
                            elif isinstance(v, (dict, list)):
                                minimal += scan_value(v)
                return minimal
            return 0

        total = 0
        for field in self.fields:
            if isinstance(field.decoded_value, (dict, list)):
                total += scan_value(field.decoded_value)
        return total

    @property
    def has_unbounded_fields(self) -> bool:
        """Check if any field consumed remaining bytes without explicit size.

        Messages with unbounded fields (bytes[] with no size) require encapsulation
        from a lower layer to be meaningful. When parsed at root level without
        encapsulation, such messages are semantically incomplete.
        """
        def check_fields(fields: list[DecodeResult]) -> bool:
            for f in fields:
                if f.is_unbounded:
                    return True
            return False

        return check_fields(self.fields)


def extract_layer_subtree(result: ValidationResult, layer_name: str, decoder: 'Decoder') -> ValidationResult | None:
    """Extract subtree for a specific layer from a decoded result.

    Args:
        result: The full ValidationResult from decoding
        layer_name: Field name of the target layer (e.g., "dns", "ip")
        decoder: Decoder instance to re-decode the extracted layer

    Returns:
        New ValidationResult containing only the target layer's subtree,
        or None if layer_name not found in protocol_chain.
    """
    if not result.protocol_chain or layer_name not in result.protocol_chain:
        return None

    # If target is the root layer (first in chain), return as-is
    layer_idx = result.protocol_chain.index(layer_name)
    if layer_idx == 0:
        return result

    # Navigate through the nested structure following the protocol chain
    # Chain example: ["ethernet", "ip", "udp", "dns"] - to find "dns",
    # we traverse: fields -> ip -> udp -> dns
    path_to_target = result.protocol_chain[1:layer_idx + 1]  # Skip root, include target

    current = None
    # First, find the starting point in fields (the second layer in chain)
    for field in result.fields:
        if isinstance(field.decoded_value, dict):
            if path_to_target[0] in field.decoded_value:
                current = field.decoded_value[path_to_target[0]]
                break
            # Also check promoted_fields
            if field.promoted_fields and path_to_target[0] in field.promoted_fields:
                current = field.promoted_fields[path_to_target[0]]
                break

    if current is None:
        return None

    # Navigate remaining path
    for field_name in path_to_target[1:]:
        if isinstance(current, FieldValue):
            current = current.val
        if not isinstance(current, dict) or field_name not in current:
            return None
        current = current[field_name]

    # Extract the FieldValue for the target layer
    if isinstance(current, FieldValue):
        layer_hex = current.hex
    else:
        return None

    # Re-decode the extracted layer hex using the decoder to get proper message type and formatting
    # Use identify_message to auto-detect the message type
    candidates = decoder.identify_message(layer_hex)
    if candidates:
        # Return the best match (first candidate)
        return candidates[0]

    # Fallback: if identify_message fails, return None
    return None


class Decoder:
    """Decodes binary messages using protocol definitions."""

    def __init__(self, coco_file: CocoFile, follow_offset_jumps: bool = True):
        self.coco_file = coco_file
        self.default_endian = coco_file.endian
        self.follow_offset_jumps = follow_offset_jumps  # Whether to follow @ offset references
        self._protocol_chain = []  # Tracks layer field names during decoding
        self.data = b""            # Current message data
        self.bit_offset = 0        # Current bit position
        self.layer_stack = []      # Start bit offsets of nested layers
        self.jump_depth = 0        # Current recursive jump depth
        self.MAX_JUMP_DEPTH = 20   # Safety limit
        self.jumped_offsets = set() # Track visited bit offsets to detect loops

    @contextmanager
    def _jump_to(self, target_bits: int):
        """Context manager for temporary bit_offset jumps with loop detection."""
        if target_bits in self.jumped_offsets:
            raise ValueError(f"Circular reference detected: jump to bit {target_bits} already visited")
        if self.jump_depth >= self.MAX_JUMP_DEPTH:
            raise ValueError("Max jump depth exceeded")
            
        saved_offset = self.bit_offset
        self.bit_offset = target_bits
        self.jump_depth += 1
        self.jumped_offsets.add(target_bits)
        try:
            yield
        finally:
            self.bit_offset = saved_offset
            self.jump_depth -= 1
            self.jumped_offsets.discard(target_bits)

    @contextmanager
    def _layer_anchor(self, msg_name: str, start_bits: int):
        """Context manager for managing the layer stack (anchors for @ jumps)."""
        is_layer = self._is_layer_message(msg_name)
        if is_layer:
            self.layer_stack.append(start_bits)
        try:
            yield
        finally:
            if is_layer:
                self.layer_stack.pop()

    def _read_bits(self, n: int) -> int | None:
        """Read n bits from current bit_offset and advance it."""
        if n == 0:
            return 0
            
        byte_idx = self.bit_offset // 8
        bit_in_byte = self.bit_offset % 8
        
        # Check bounds
        if byte_idx >= len(self.data):
            return None
            
        # Read enough bytes to satisfy n bits
        needed_bytes = (bit_in_byte + n + 7) // 8
        if byte_idx + needed_bytes > len(self.data):
            return None
            
        chunk = self.data[byte_idx : byte_idx + needed_bytes]
        val = int.from_bytes(chunk, byteorder='big')
        
        # Shift and mask to get the desired bits (Big Endian packing)
        total_bits_in_chunk = len(chunk) * 8
        shift = total_bits_in_chunk - bit_in_byte - n
        mask = (1 << n) - 1
        result = (val >> shift) & mask
        
        self.bit_offset += n
        return result

    def _is_aligned(self) -> bool:
        """Check if current bit_offset is byte-aligned."""
        return self.bit_offset % 8 == 0

    def _is_layer_message(self, msg_name: str) -> bool:
        """Check if message or any of its bases is marked as layer."""
        msg = self.coco_file.get_message(msg_name)
        while msg:
            if msg.is_layer:
                return True
            if msg.parent:
                msg = self.coco_file.get_message(msg.parent)
            else:
                break
        return False

    def _get_chain_name(self, msg_name: str) -> str:
        """Get short name for protocol chain display.

        Strips common suffixes like _frame, _packet, _segment for cleaner output.
        E.g., ethernet_frame -> ethernet, ipv4_packet -> ipv4
        """
        for suffix in ('_frame', '_packet', '_segment', '_datagram', '_message'):
            if msg_name.endswith(suffix):
                return msg_name[:-len(suffix)]
        return msg_name

    def _resolve_offset_of(self, field: Field, offset_value: int, context: dict) -> tuple[Any, str, bool]:
        """Resolve an offset_of attribute by jumping to offset and decoding target type.

        Args:
            field: Field with offset_of attribute
            offset_value: The decoded offset value (in bytes)
            context: Current decoding context

        Returns:
            Tuple of (decoded_value, hex_value, is_valid)
        """
        if not field.attributes or not field.attributes.offset_of:
            return None, "", False

        if not self.follow_offset_jumps:
            return None, "", False

        target_type_name = field.attributes.offset_of

        # Look up target type
        target_msg = self.coco_file.get_message(target_type_name)
        target_enum = self.coco_file.get_enum(target_type_name)

        if not target_msg and not target_enum:
            return None, "", False

        # Calculate target bit offset (layer-relative)
        anchor = self.layer_stack[-1] if self.layer_stack else 0
        target_bits = anchor + (offset_value * 8)

        try:
            with self._jump_to(target_bits):
                if target_msg:
                    # Decode as message
                    resolved_value, consumed_bits = self._decode_embedded_message(target_msg, context)
                    byte_start = target_bits // 8
                    byte_end = (target_bits + consumed_bits + 7) // 8
                    hex_val = self.data[byte_start:byte_end].hex()
                    return resolved_value, hex_val, True
                elif target_enum:
                    # Decode as enum
                    base_type = IntegerType(base=target_enum.base_type)
                    int_val, ok = self.decode_integer(base_type)
                    if not ok:
                        return None, "", False
                    member = target_enum.get_member_by_value(int_val)
                    resolved_value = f"{target_enum.name}.{member.name}" if member else int_val
                    hex_val = format(int_val, f'0{base_type.byte_size*2}x')
                    return resolved_value, hex_val, True
        except (ValueError, IndexError):
            return None, "", False

        return None, "", False

    def get_constant_value(self, name: str) -> int | str | None:
        """Look up a constant by name."""
        const = self.coco_file.get_constant(name)
        return const.value if const else None

    def get_enum(self, name: str):
        """Look up an enum by name."""
        return self.coco_file.get_enum(name)

    def resolve_message(self, msg: Message) -> list[Field]:
        """Resolve a message's fields, including inherited fields and overrides."""
        if msg.parent is None:
            # Base message - just return fields
            return list(msg.fields)

        # Get parent message
        parent = self.coco_file.get_message(msg.parent)
        if parent is None:
            raise ValueError(f"Parent message '{msg.parent}' not found")

        # Recursively resolve parent
        parent_fields = self.resolve_message(parent)

        # Apply overrides
        fields = list(parent_fields)
        for override in msg.overrides:
            path = override.path
            fields = self._apply_override(fields, path, override)

        # Add child's own new fields (not inherited from parent)
        fields.extend(msg.fields)

        return fields

    def _apply_override(self, fields: list[Field], path: list[str], override) -> list[Field]:
        """Apply an override at the given path in the field hierarchy."""
        if not path:
            return fields

        field_name = path[0]
        remaining_path = path[1:]

        result = []
        for f in fields:
            if f.name == field_name:
                if not remaining_path:
                    # Apply override at this level
                    if hasattr(override, 'value'):
                        # Value override
                        result.append(Field(
                            name=f.name,
                            type=f.type,
                            size=f.size,
                            default_value=override.value,
                            match_clause=f.match_clause,
                            attributes=f.attributes,
                            bitfield_body=f.bitfield_body,
                            structure_body=override.fields if hasattr(override, 'fields') else f.structure_body,
                        ))
                    else:
                        # Structure override
                        result.append(Field(
                            name=f.name,
                            type=f.type,
                            size=f.size,
                            default_value=f.default_value,
                            match_clause=f.match_clause,
                            attributes=f.attributes,
                            bitfield_body=f.bitfield_body,
                            structure_body=override.fields,
                        ))
                else:
                    # Need to recurse into structure_body or embedded message
                    if f.structure_body:
                        new_structure = self._apply_override(list(f.structure_body), remaining_path, override)
                        result.append(Field(
                            name=f.name,
                            type=f.type,
                            size=f.size,
                            default_value=f.default_value,
                            match_clause=f.match_clause,
                            attributes=f.attributes,
                            bitfield_body=f.bitfield_body,
                            structure_body=new_structure,
                        ))
                    elif isinstance(f.type, EnumTypeRef):
                        # Check if this is an embedded message type
                        msg_def = self.coco_file.get_message(f.type.enum_name)
                        if msg_def:
                            # Expand the embedded message's fields and apply override
                            embedded_fields = self.resolve_message(msg_def)
                            new_structure = self._apply_override(embedded_fields, remaining_path, override)
                            result.append(Field(
                                name=f.name,
                                type=f.type,
                                size=f.size,
                                default_value=f.default_value,
                                match_clause=f.match_clause,
                                attributes=f.attributes,
                                bitfield_body=f.bitfield_body,
                                structure_body=new_structure,
                            ))
                        else:
                            # Not a message type, can't apply nested override
                            result.append(f)
                    else:
                        # Can't apply nested override - no structure_body
                        result.append(f)
            else:
                result.append(f)

        return result

    def decode_integer(self, int_type: IntegerType) -> tuple[int, bool]:
        """Decode an integer from the current bit position."""
        bit_size = int_type.bit_size
        endian = int_type.endian or self.default_endian

        if endian == Endianness.LITTLE:
            # For Little Endian, we read byte-by-byte and assemble
            if bit_size % 8 != 0:
                return 0, False  # LE usually implies byte alignment
            
            byte_count = bit_size // 8
            raw_bytes = bytearray()
            for _ in range(byte_count):
                b = self._read_bits(8)
                if b is None:
                    return 0, False
                raw_bytes.append(b)
            value = int.from_bytes(raw_bytes, byteorder='little', signed=int_type.is_signed)
            return value, True
        else:
            # Big Endian (default for network bits)
            value = self._read_bits(bit_size)
            if value is None:
                return 0, False
            
            # Handle signedness if needed (for BE)
            if int_type.is_signed:
                if value & (1 << (bit_size - 1)):
                    value -= (1 << bit_size)
            
            return value, True

    def decode_field(self, field: Field, context: dict) -> DecodeResult:
        """Decode a single field from the current bit position."""
        start_bit_offset = self.bit_offset
        field_type = field.type
        errors = []

        # Handle virtual fields (e.g. standalone matches)
        if field_type is None:
            if field.match_clause:
                decoded_value = self._decode_match(field.match_clause, context)
                return DecodeResult(
                    name=field.name,
                    hex_value="",
                    decoded_value=decoded_value,
                    is_valid=True
                )
            return DecodeResult(name=field.name, hex_value="", decoded_value=None, is_valid=True)

        # --- Strict Alignment Validation ---
        is_byte_oriented = isinstance(field_type, (IntegerType, BytesType, StringType, PadType, EnumTypeRef))
        
        if is_byte_oriented and not self._is_aligned():
            errors.append(f"Alignment Error: Field '{field.name}' ({field_type}) must be byte-aligned. Current bit offset: {self.bit_offset}")
            return DecodeResult(
                name=field.name,
                hex_value="",
                decoded_value=None,
                is_valid=False,
                errors=errors
            )

        # Special handling for branch-determined size [*]
        if isinstance(field.size, BranchDeterminedSize):
            if not field.match_clause:
                return DecodeResult(
                    name=field.name, hex_value="", decoded_value=None, is_valid=False,
                    errors=["Branch-determined size requires a match clause"]
                )
            
            # Decode match clause and let it determine how many bits to consume
            decoded_value = self._decode_match(field.match_clause, context)
            promoted_fields = decoded_value if isinstance(decoded_value, dict) else {}
            
            end_bit_offset = self.bit_offset
            byte_start = start_bit_offset // 8
            byte_end = (end_bit_offset + 7) // 8
            hex_value = self.data[byte_start:byte_end].hex()
            
            return DecodeResult(
                name=field.name,
                hex_value=hex_value,
                decoded_value=decoded_value,
                is_valid=True,
                promoted_fields=promoted_fields
            )

        # Determine field size
        size_bytes = self._get_field_size(field, context, (len(self.data) * 8 - self.bit_offset) // 8)

        if size_bytes is None and not isinstance(field.size, (VariableSize, GreedySize)):
            return DecodeResult(
                name=field.name, hex_value="", decoded_value=None, is_valid=False,
                errors=["Could not determine field size"]
            )

        size_bits = (size_bytes * 8) if size_bytes is not None else (len(self.data) * 8 - self.bit_offset)
        
        # Capture hex value before consuming
        byte_start = self.bit_offset // 8
        byte_end = (self.bit_offset + size_bits + 7) // 8
        hex_value = self.data[byte_start:byte_end].hex()

        decoded_value = None
        is_valid = True

        # Decode based on type
        if isinstance(field_type, IntegerType):
            decoded_value, ok = self.decode_integer(field_type)
            if not ok:
                is_valid = False
                errors.append("Failed to decode integer")
            else:
                # For bit-level integers, use value-based hex
                if field_type.bit_size < 8:
                    hex_value = format(decoded_value, 'x')

            if isinstance(field.type, EnumTypeRef):
                enum_def = self.get_enum(field.type.enum_name)
                if enum_def:
                    member = enum_def.get_member_by_value(decoded_value)
                    if member:
                        decoded_value = f"{enum_def.name}.{member.name}"
                    else:
                        is_valid = False
                        errors.append(f"Value {decoded_value} not in enum {enum_def.name}")

        elif isinstance(field_type, BitFieldType):
            bit_count = field_type.bit_count
            int_val = self._read_bits(bit_count)
            if int_val is None:
                is_valid = False
                errors.append(f"Not enough bits for bitfield: need {bit_count}")
            else:
                decoded_value = self._decode_bitfield(int_val, field, (bit_count + 7) // 8)

        elif isinstance(field_type, EnumTypeRef):
            enum_def = self.get_enum(field_type.enum_name)
            msg_def = self.coco_file.get_message(field_type.enum_name)

            if msg_def and field.size is not None:
                decoded_value, consumed_bits = self._decode_message_array(msg_def, field, context)
                hex_value = self.data[byte_start : (start_bit_offset + consumed_bits + 7) // 8].hex()
            elif msg_def and field.size is None:
                if self._is_layer_message(msg_def.name):
                    self._protocol_chain.append(field.name)
                
                if field.structure_body:
                    decoded_value, structure_valid = self._decode_structure(
                        field.structure_body, context, track_validity=True
                    )
                    if not structure_valid:
                        is_valid = False
                else:
                    decoded_value, consumed_bits = self._decode_embedded_message(msg_def, context)
                
                hex_value = self.data[byte_start : (self.bit_offset + 7) // 8].hex()
            elif enum_def:
                base_type = IntegerType(base=enum_def.base_type)
                int_val, ok = self.decode_integer(base_type)
                if ok:
                    member = enum_def.get_member_by_value(int_val)
                    if member:
                        decoded_value = f"{enum_def.name}.{member.name}"
                    else:
                        decoded_value = int_val
                        is_valid = False
                        errors.append(f"Value {int_val} not in enum {enum_def.name}")
                else:
                    is_valid = False
                    errors.append("Failed to decode enum value")
            else:
                errors.append(f"Type '{field_type.enum_name}' not found")
                is_valid = False

        elif isinstance(field_type, BytesType):
            consumed_val = self._read_bits(size_bits)
            if consumed_val is None:
                is_valid = False
                errors.append(f"Not enough bits for bytes field: need {size_bits}")
                hex_value = ""
            else:
                hex_value = format(consumed_val, f'0{(size_bits+7)//8*2}x')
            decoded_value = hex_value

        elif isinstance(field_type, StringType):
            byte_count = size_bits // 8
            raw_bytes = bytearray()
            for _ in range(byte_count):
                b = self._read_bits(8)
                if b is None:
                    is_valid = False
                    errors.append(f"Not enough bits for string: needed {byte_count} bytes")
                    break
                raw_bytes.append(b)
            
            try:
                if field_type.is_cstr:
                    null_idx = raw_bytes.find(b'\x00')
                    decoded_value = raw_bytes[:null_idx].decode('ascii', errors='replace') if null_idx >= 0 else raw_bytes.decode('ascii', errors='replace')
                else:
                    decoded_value = raw_bytes.decode('ascii', errors='replace')
            except Exception as e:
                decoded_value = raw_bytes.hex()
                errors.append(f"Failed to decode string: {e}")

        elif isinstance(field_type, PadType):
            self.bit_offset += size_bits
            decoded_value = None

        promoted_fields = {}

        # --- Sub-Structure Parsing (Match / Structure Body) ---
        if field.match_clause or field.structure_body:
            if isinstance(field_type, BytesType):
                end_bits = self.bit_offset
                self.bit_offset = start_bit_offset
                
                if field.match_clause:
                    # Attached match on bytes field
                    match_res = self._decode_match(field.match_clause, context)
                    if isinstance(match_res, dict):
                        promoted_fields = match_res
                    # Base field (bytes) decoded_value remains as raw hex
                else:
                    decoded_value = self._decode_structure(field.structure_body, context)
                
                self.bit_offset = max(end_bits, self.bit_offset)
            else:
                if field.match_clause:
                    # Attached match on non-bytes field (e.g. u16 or bitfield)
                    temp_context = dict(context)
                    temp_context[field.name] = decoded_value
                    if isinstance(decoded_value, dict):
                        self._flatten_to_context(field.name, decoded_value, temp_context)
                    
                    match_res = self._decode_match(field.match_clause, temp_context)
                    if isinstance(match_res, dict):
                        promoted_fields = match_res
                    # Base field (int/bitfield) decoded_value remains as-is
                else:
                    decoded_value = self._decode_structure(field.structure_body, context)

        # --- Post-Processing ---
        if field.default_value is not None and not isinstance(field_type, PadType):
            expected_value = field.default_value
            if isinstance(expected_value, str):
                const_val = self.get_constant_value(expected_value)
                if const_val is not None: expected_value = const_val

            if isinstance(expected_value, int) and isinstance(field_type, IntegerType):
                numeric_val = decoded_value
                if isinstance(decoded_value, str) and '.' in decoded_value:
                    enum_def = self.get_enum(field_type.enum_name)
                    if enum_def:
                        m = enum_def.get_member_by_name(decoded_value.split('.')[1])
                        if m: numeric_val = m.value
                
                if numeric_val != expected_value:
                    is_valid = False
                    errors.append(f"Value mismatch: expected {expected_value}, got {numeric_val}")

            elif isinstance(expected_value, EnumValue):
                expected_str = f"{expected_value.enum_name}.{expected_value.member_name}"
                if decoded_value != expected_str:
                    is_valid = False
                    errors.append(f"Enum mismatch: expected {expected_str}, got {decoded_value}")

        # --- Handle offset_of Attribute ---
        if field.attributes and field.attributes.offset_of and isinstance(decoded_value, int):
            resolved_val, resolved_hex, resolved_ok = self._resolve_offset_of(field, decoded_value, context)
            if resolved_ok:
                # Add resolved value to promoted fields
                promoted_fields[f"{field.name}_resolved"] = FieldValue(resolved_hex, resolved_val)

        is_constrained = (field.default_value is not None) or (isinstance(field.type, EnumTypeRef) and self.get_enum(field.type.enum_name))

        return DecodeResult(
            name=field.name, hex_value=hex_value, decoded_value=decoded_value,
            is_valid=is_valid, errors=errors, is_constrained=is_constrained,
            promoted_fields=promoted_fields
        )

    def _get_message_fixed_size(self, msg: Message, context: dict) -> int | None:
        fields = self.resolve_message(msg)
        total = 0
        local_context = dict(context)
        for field in fields:
            field_size = self._get_field_size(field, local_context, 0)
            if field_size is None: return None
            total += field_size
        return total

    def _message_has_constraints(self, msg: Message) -> bool:
        fields = self.resolve_message(msg)
        for field in fields:
            if field.default_value is not None: return True
            if isinstance(field.type, EnumTypeRef):
                if self.get_enum(field.type.enum_name): return True
                embedded_msg = self.coco_file.get_message(field.type.enum_name)
                if embedded_msg and self._message_has_constraints(embedded_msg): return True
        return False

    def _get_field_size(self, field: Field, context: dict, remaining_bits: int) -> int | None:
        field_type = field.type
        if isinstance(field_type, IntegerType): return field_type.byte_size
        if isinstance(field_type, EnumTypeRef):
            enum_def = self.get_enum(field_type.enum_name)
            if enum_def: return IntegerType(base=enum_def.base_type).byte_size
            msg_def = self.coco_file.get_message(field_type.enum_name)
            if msg_def:
                if field.size is not None:
                    if isinstance(field.size, LiteralSize): return remaining_bits // 8
                    elif isinstance(field.size, FieldRefSize):
                        ref_value = self._resolve_field_path(field.size.field_path, context)
                        return remaining_bits // 8 if ref_value is not None else None
                    elif isinstance(field.size, SizeExpr):
                        return self._eval_size_expr(field.size, context)
                    return remaining_bits // 8
                elif field.structure_body:
                    total = sum(self._get_field_size(f, context, 0) or 0 for f in field.structure_body)
                    return total
                else:
                    fixed_size = self._get_message_fixed_size(msg_def, context)
                    return fixed_size if fixed_size is not None else (remaining_bits // 8 if remaining_bits > 0 else None)
            return 1
        if isinstance(field_type, BitFieldType): return (field_type.bit_count + 7) // 8
        size = field.size
        if size is None: return remaining_bits // 8
        if isinstance(size, LiteralSize): return size.value
        if isinstance(size, FieldRefSize):
            ref_value = self._resolve_field_path(size.field_path, context)
            return int(ref_value) if ref_value is not None else None
        if isinstance(size, SizeExpr): return self._eval_size_expr(size, context)
        if isinstance(size, GreedySize): return remaining_bits // 8
        if isinstance(size, FillToSize):
            consumed_bytes = context.get('__consumed_bytes__', 0)
            return max(0, size.target_size - consumed_bytes)
        if isinstance(size, UntilSize):
            term_val = size.terminator
            if isinstance(term_val, EnumValue):
                enum_def = self.get_enum(term_val.enum_name)
                terminator_byte = next((m.value for m in enum_def.members if m.name == term_val.member_name), None) if enum_def else None
            else: terminator_byte = term_val
            if terminator_byte is None: return None
            byte_offset = (self.bit_offset + 7) // 8
            term_idx = self.data[byte_offset:].find((terminator_byte & 0xFF).to_bytes(1, 'big'))
            return term_idx + 1 if term_idx >= 0 else None
        if isinstance(size, VariableSize):
            if isinstance(field_type, StringType) and field_type.is_cstr:
                byte_offset = (self.bit_offset + 7) // 8
                null_idx = self.data[byte_offset:].find(b'\x00')
                if null_idx >= 0: return null_idx + 1
            return remaining_bits // 8 if remaining_bits > 0 else None
        return remaining_bits // 8 if remaining_bits > 0 else None

    def _eval_size_expr(self, expr: SizeExpr, context: dict) -> int | None:
        left_val = self._eval_size_operand(expr.left, context)
        right_val = self._eval_size_operand(expr.right, context)
        if left_val is None or right_val is None: return None
        if expr.op == '+': return left_val + right_val
        elif expr.op == '-': return max(0, left_val - right_val)
        elif expr.op == '*': return left_val * right_val
        return None

    def _eval_size_operand(self, operand, context: dict) -> int | None:
        if isinstance(operand, LiteralSize): return operand.value
        elif isinstance(operand, FieldRefSize):
            ref_value = self._resolve_field_path(operand.field_path, context)
            return int(ref_value) if ref_value is not None else None
        elif isinstance(operand, SizeExpr): return self._eval_size_expr(operand, context)
        return None

    def _resolve_field_path(self, field_path: list[str], context: dict) -> int | None:
        if not field_path: return None
        full_path = ".".join(field_path)
        if full_path in context: return context[full_path]
        if len(field_path) == 1:
            val = context.get(field_path[0])
            if isinstance(val, FieldValue): val = val.val
            return val
        current = context
        for part in field_path:
            if isinstance(current, FieldValue): current = current.val
            if isinstance(current, dict) and part in current: current = current[part]
            else: return None
        if isinstance(current, FieldValue): current = current.val
        return current if isinstance(current, (int, float)) else None

    def _flatten_to_context(self, prefix: str, data: dict, context: dict) -> None:
        for key, value in data.items():
            full_key = f"{prefix}.{key}"
            actual_val = value.val if isinstance(value, FieldValue) else value
            if isinstance(actual_val, dict): self._flatten_to_context(full_key, actual_val, context)
            elif isinstance(actual_val, (int, float, str)): context[full_key] = actual_val

    def _decode_bitfield(self, int_val: int, field: Field, byte_count: int = 1) -> dict | int:
        if not field.bitfield_body or not isinstance(field.type, BitFieldType): return int_val
        total_bits = field.type.bit_count
        result, current_bit = {}, total_bits
        for bf in field.bitfield_body.fields:
            current_bit -= bf.bit_count
            mask = (1 << bf.bit_count) - 1
            value = (int_val >> current_bit) & mask
            result[bf.name] = FieldValue(format(value, 'x') if value > 0 else '0', value)
        return result

    def _resolve_path(self, path: str, context: dict):
        parts = path.split('.')
        value = context
        for part in parts:
            if isinstance(value, FieldValue): value = value.val
            if isinstance(value, dict): value = value.get(part)
            else: return None
            if value is None: return None
        if isinstance(value, FieldValue): value = value.val
        return value

    def _decode_match(self, match_clause: MatchClause, context: dict) -> dict:
        discriminator_value = self._resolve_path(match_clause.discriminator, context)
        matching_branch, default_branch = None, None
        for branch in match_clause.branches:
            if branch.pattern is None: default_branch = branch
            elif isinstance(branch.pattern, EnumValue):
                enum_str = f"{branch.pattern.enum_name}.{branch.pattern.member_name}"
                if discriminator_value == enum_str: matching_branch = branch; break
                enum_def = self.get_enum(branch.pattern.enum_name)
                if enum_def:
                    member = enum_def.get_member_by_name(branch.pattern.member_name)
                    if member and discriminator_value == member.value: matching_branch = branch; break
            elif branch.pattern == discriminator_value: matching_branch = branch; break
        branch = matching_branch or default_branch
        return self._decode_structure(branch.fields, context) if branch and branch.fields else {}

    def _decode_fields(self, fields: list[Field], context: dict) -> tuple[dict, list[DecodeResult], bool]:
        result_dict, results_list, all_valid = {}, [], True
        for field in fields:
            if field.type is None and field.match_clause:
                discriminator_value = self._resolve_path(field.match_clause.discriminator, context)
                matching_branch, default_branch = None, None
                for branch in field.match_clause.branches:
                    if branch.pattern is None: default_branch = branch
                    elif isinstance(branch.pattern, EnumValue):
                        if discriminator_value == f"{branch.pattern.enum_name}.{branch.pattern.member_name}": matching_branch = branch; break
                        enum_def = self.get_enum(branch.pattern.enum_name)
                        if enum_def:
                            member = enum_def.get_member_by_name(branch.pattern.member_name)
                            if member and discriminator_value == member.value: matching_branch = branch; break
                    elif branch.pattern == discriminator_value: matching_branch = branch; break
                branch = matching_branch or default_branch
                if branch and branch.fields:
                    sub_dict, sub_list, sub_valid = self._decode_fields(branch.fields, context)
                    result_dict.update(sub_dict)
                    results_list.extend(sub_list)
                    if not sub_valid: all_valid = False
                    for k, v in sub_dict.items():
                        actual_val = v.val if isinstance(v, FieldValue) else v
                        context[k] = actual_val
                        if isinstance(actual_val, dict): self._flatten_to_context(k, actual_val, context)
                continue

            decode_result = self.decode_field(field, context)

            # --- SPLATTING & Transparency ---
            # If the field has an attached match clause, we promote its results
            # to be siblings AND skip adding the base field to result_dict.
            if field.match_clause is not None:
                if decode_result.promoted_fields:
                    # Only add promoted fields, not the base field
                    for sub_name, sub_val in decode_result.promoted_fields.items():
                        if sub_name == field.name: continue
                        result_dict[sub_name] = sub_val
                        actual_val = sub_val.val if isinstance(sub_val, FieldValue) else sub_val
                        context[sub_name] = actual_val
                        if isinstance(actual_val, dict): self._flatten_to_context(sub_name, actual_val, context)
                        results_list.append(DecodeResult(name=sub_name, hex_value=sub_val.hex if isinstance(sub_val, FieldValue) else "", decoded_value=actual_val, is_valid=True))
                else:
                    # Match clause exists but no promoted fields - add base field
                    result_dict[field.name] = FieldValue(decode_result.hex_value, decode_result.decoded_value)
                    results_list.append(decode_result)
            else:
                # No match: add the field normally
                result_dict[field.name] = FieldValue(decode_result.hex_value, decode_result.decoded_value)
                results_list.append(decode_result)

                # Also add any promoted fields (from offset_of attributes)
                if decode_result.promoted_fields:
                    for sub_name, sub_val in decode_result.promoted_fields.items():
                        result_dict[sub_name] = sub_val
                        actual_val = sub_val.val if isinstance(sub_val, FieldValue) else sub_val
                        context[sub_name] = actual_val

            # Update context for the base field
            context[field.name] = decode_result.decoded_value
            if isinstance(decode_result.decoded_value, dict): self._flatten_to_context(field.name, decode_result.decoded_value, context)
            if not decode_result.is_valid: all_valid = False
        return result_dict, results_list, all_valid

    def _decode_structure(self, fields: list[Field], parent_context: dict, track_validity: bool = False) -> dict | tuple[dict, bool]:
        context = dict(parent_context)
        result_dict, _, all_valid = self._decode_fields(fields, context)
        return (result_dict, all_valid) if track_validity else result_dict

    def _decode_embedded_message(self, msg_def: Message, context: dict) -> tuple[dict, int]:
        """Decode a single embedded message."""
        start_bits = self.bit_offset

        with self._layer_anchor(msg_def.name, start_bits):
            fields = self.resolve_message(msg_def)
            result_dict, _, _ = self._decode_fields(fields, dict(context))

        return result_dict, self.bit_offset - start_bits

    def _decode_message_array(self, msg_def: Message, field: Field, context: dict) -> tuple[list, int]:
        start_bits = self.bit_offset
        result = []
        count = None
        if isinstance(field.size, LiteralSize): count = field.size.value
        elif isinstance(field.size, FieldRefSize): count = self._resolve_field_path(field.size.field_path, context) or 0
        subtypes = self.coco_file.get_subtypes(msg_def.name)
        candidate_types = sorted(subtypes, key=lambda m: -self._get_inheritance_depth(m.name)) if subtypes else [msg_def]
        element_idx = 0
        while self.bit_offset < len(self.data) * 8:
            if count is not None and element_idx >= count: break
            best_result, best_bits, original_offset = None, 0, self.bit_offset
            for candidate in candidate_types:
                trial_decoder = Decoder(self.coco_file)
                trial_decoder.data = self.data
                trial_decoder.bit_offset = original_offset
                trial_decoder.default_endian = self.default_endian
                trial_decoder.follow_offset_jumps = self.follow_offset_jumps
                trial_decoder.layer_stack = list(self.layer_stack)
                try:
                    # Pass a copy of the context to the trial decoder
                    trial_res = trial_decoder.validate_message(candidate, allow_remaining=True, context=dict(context))
                    if trial_res.is_valid:
                        consumed = trial_decoder.bit_offset - original_offset
                        if consumed == 0:
                            continue
                            
                        if best_result is None or trial_res.validated_constraints > best_result.validated_constraints:
                            best_result, best_bits = trial_res, consumed
                except Exception as e:
                    continue
            if best_result:
                element_dict = {f_res.name: FieldValue(f_res.hex_value, f_res.decoded_value) for f_res in best_result.fields}
                result.append(element_dict)
                self.bit_offset = original_offset + best_bits
                element_idx += 1
            else: break
        return result, self.bit_offset - start_bits

    def validate_message(self, msg: Message, hex_str: str = None, allow_remaining: bool = False, context: dict = None) -> ValidationResult:
        if hex_str is not None:
            hex_str = hex_str.lower().replace(" ", "")
            try: self.data = bytes.fromhex(hex_str)
            except ValueError: self.data = b""
            self.bit_offset = 0
        if not self.layer_stack:
            self.layer_stack = [0]
        self.jump_depth = 0
        self.jumped_offsets = set()
        fields = self.resolve_message(msg)
        
        self._protocol_chain = []
        if msg.is_layer: self._protocol_chain.append(self._get_chain_name(msg.name))
        
        # Use provided context (trials) or fresh one
        active_context = context if context is not None else {}
        result_dict, results_list, all_valid = self._decode_fields(fields, active_context)
        remaining_bits = (len(self.data) * 8) - self.bit_offset
        return ValidationResult(is_valid=all_valid, message_name=msg.name, fields=results_list, remaining_bytes=self.data[self.bit_offset // 8:].hex() if remaining_bits > 0 else "", protocol_chain=list(self._protocol_chain))

    def validate_by_name(self, message_name: str, hex_str: str) -> ValidationResult:
        msg = self.coco_file.get_message(message_name)
        if msg is None: return ValidationResult(is_valid=False, message_name=message_name, fields=[], errors=[f"Message '{message_name}' not found"])
        return self.validate_message(msg, hex_str)

    def identify_message(self, hex_str: str) -> list[ValidationResult]:
        results = []
        for msg in self.coco_file.messages:
            result = self.validate_message(msg, hex_str)
            results.append(result)
        results.sort(key=lambda r: (not r.is_valid, r.has_unbounded_fields, len(r.remaining_bytes), -r.validated_constraints, r.minimal_array_elements, -r.total_structured_fields, -r.total_matched_bytes, -self._get_inheritance_depth(r.message_name) if r.is_valid else 0))
        return results

    def _get_inheritance_depth(self, message_name: str) -> int:
        depth, msg = 0, self.coco_file.get_message(message_name)
        while msg and msg.parent:
            depth += 1
            msg = self.coco_file.get_message(msg.parent)
        return depth


def validate_message(coco_file: CocoFile, message_name: str, hex_str: str) -> ValidationResult:
    return Decoder(coco_file).validate_by_name(message_name, hex_str)


def identify_message(coco_file: CocoFile, hex_str: str) -> list[ValidationResult]:
    return Decoder(coco_file).identify_message(hex_str)