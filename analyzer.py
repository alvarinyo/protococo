"""
Protococo Analyzer v1.0

Decodes and validates binary messages against protocol definitions.
"""

from collections import OrderedDict
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

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


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


class Decoder:
    """Decodes binary messages using protocol definitions."""

    def __init__(self, coco_file: CocoFile):
        self.coco_file = coco_file
        self.default_endian = coco_file.endian
        self._protocol_chain = []  # Tracks layer field names during decoding
        self.data = b""            # Current message data
        self.bit_offset = 0        # Current bit position

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
        """Decode a single field from the current bit position.

        Args:
            field: Field definition
            context: Dict of already-decoded field values (for size references)

        Returns:
            DecodeResult with decoded value and validity
        """
        field_type = field.type
        errors = []
        start_bit_offset = self.bit_offset

        # --- Strict Alignment Validation ---
        # u8, u16, bytes, string, pad, and enums are byte-oriented
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
        # The match clause determines the size by consuming bits
        if isinstance(field.size, BranchDeterminedSize):
            if not field.match_clause:
                return DecodeResult(
                    name=field.name,
                    hex_value="",
                    decoded_value=None,
                    is_valid=False,
                    errors=["Branch-determined size [*] requires a match clause"]
                )
            # Decode match clause and let it determine how many bits to consume
            decoded_value = self._decode_match(field.match_clause, context)
            end_bit_offset = self.bit_offset
            consumed_bits = end_bit_offset - start_bit_offset
            
            # Extract hex value for display
            byte_start = start_bit_offset // 8
            byte_end = (end_bit_offset + 7) // 8
            hex_value = self.data[byte_start:byte_end].hex()
            
            return DecodeResult(
                name=field.name,
                hex_value=hex_value,
                decoded_value=decoded_value,
                is_valid=True,
                errors=[]
            )

        # Determine field size (usually in bits for bit-stream)
        # Note: _get_field_size needs refactor to return bits
        size_bytes = self._get_field_size(field, context, (len(self.data) * 8 - self.bit_offset) // 8)

        # Check if size was determined
        if size_bytes is None and not isinstance(field.size, (VariableSize, GreedySize)):
            return DecodeResult(
                name=field.name,
                hex_value="",
                decoded_value=None,
                is_valid=False,
                errors=["Could not determine field size"]
            )

        # TODO: Handle UntilSize and VariableString with bit-precision
        # For now, we continue with byte-based sizing for complex types
        
        size_bits = (size_bytes * 8) if size_bytes is not None else (len(self.data) * 8 - self.bit_offset)
        
        # Capture hex value before consuming
        byte_start = self.bit_offset // 8
        byte_end = (self.bit_offset + size_bits + 7) // 8
        hex_value = self.data[byte_start:byte_end].hex()

        decoded_value = None
        is_valid = True
        expected_hex = None

        # Decode based on type
        if isinstance(field_type, IntegerType):
            decoded_value, ok = self.decode_integer(field_type)
            if not ok:
                is_valid = False
                errors.append("Failed to decode integer")

            # Check enum type reference
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
            # bits[N] reads N bits and decodes them into a dict
            bit_count = field_type.bit_count
            int_val = self._read_bits(bit_count)
            if int_val is None:
                is_valid = False
                errors.append(f"Not enough bits for bitfield: need {bit_count}")
            else:
                decoded_value = self._decode_bitfield(int_val, field, (bit_count + 7) // 8)

        elif isinstance(field_type, EnumTypeRef):
            # Could be enum field, message array, or single embedded message
            enum_def = self.get_enum(field_type.enum_name)
            msg_def = self.coco_file.get_message(field_type.enum_name)

            if msg_def and field.size is not None:
                # Message array
                decoded_value, consumed_bits = self._decode_message_array(msg_def, field, context)
                # hex_value already captures enough, but let's be precise
                hex_value = self.data[byte_start : (start_bit_offset + consumed_bits + 7) // 8].hex()
            elif msg_def and field.size is None:
                # Single embedded message
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
                # Enum field
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
            # bytes[N] - consume bits and return as hex
            consumed_val = self._read_bits(size_bits)
            hex_value = format(consumed_val, f'0{(size_bits+7)//8*2}x') if consumed_val is not None else ""
            decoded_value = hex_value
            
            if field.match_clause:
                # Sub-structure parsing
                # For nested matches, we might need to reset bit_offset if it was a sub-parse
                # but currently _decode_match expects to work from current position
                current_bits = self.bit_offset
                self.bit_offset = start_bit_offset # Rewind to start of bytes for match
                decoded_value = self._decode_match(field.match_clause, context)
                self.bit_offset = current_bits # Restore
            elif field.structure_body:
                current_bits = self.bit_offset
                self.bit_offset = start_bit_offset
                decoded_value = self._decode_structure(field.structure_body, context)
                self.bit_offset = current_bits

        elif isinstance(field_type, StringType):
            # Read bytes and decode
            byte_count = size_bits // 8
            raw_bytes = bytearray()
            for _ in range(byte_count):
                b = self._read_bits(8)
                if b is None: break
                raw_bytes.append(b)
            
            try:
                if field_type.is_cstr:
                    null_idx = raw_bytes.find(b'\x00')
                    if null_idx >= 0:
                        decoded_value = raw_bytes[:null_idx].decode('ascii', errors='replace')
                    else:
                        decoded_value = raw_bytes.decode('ascii', errors='replace')
                else:
                    decoded_value = raw_bytes.decode('ascii', errors='replace')
            except Exception as e:
                decoded_value = raw_bytes.hex()
                errors.append(f"Failed to decode string: {e}")

        elif isinstance(field_type, PadType):
            # Consume and discard
            self.bit_offset += size_bits
            decoded_value = None

        # --- Post-Processing ---
        # Check fixed value
        if field.default_value is not None and not isinstance(field_type, PadType):
            # Logic similar to before but using decoded_value
            expected_value = field.default_value
            if isinstance(expected_value, str):
                const_val = self.get_constant_value(expected_value)
                if const_val is not None: expected_value = const_val

            if isinstance(expected_value, int) and isinstance(field_type, IntegerType):
                # Use int comparison
                # We need the numeric value if decoded_value is an enum string
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

        # Constraint check logic...
        is_constrained = (field.default_value is not None) or (isinstance(field.type, EnumTypeRef) and self.get_enum(field.type.enum_name))
        
        return DecodeResult(
            name=field.name,
            hex_value=hex_value,
            decoded_value=decoded_value,
            is_valid=is_valid,
            errors=errors,
            is_constrained=is_constrained,
        )

    def _get_message_fixed_size(self, msg: Message, context: dict) -> int | None:
        """Calculate the fixed size of a message in bytes.

        Returns None if the message has variable-length fields that can't be resolved.
        """
        fields = self.resolve_message(msg)
        total = 0
        local_context = dict(context)

        for field in fields:
            field_size = self._get_field_size(field, local_context, 0)
            if field_size is None:
                return None  # Can't determine size
            total += field_size

        return total

    def _message_has_constraints(self, msg: Message) -> bool:
        """Check if a message has any constrained fields (enum or default value)."""
        fields = self.resolve_message(msg)
        for field in fields:
            if field.default_value is not None:
                return True
            if isinstance(field.type, EnumTypeRef):
                if self.get_enum(field.type.enum_name):
                    return True
                # Check if it's an embedded message with constraints
                embedded_msg = self.coco_file.get_message(field.type.enum_name)
                if embedded_msg and self._message_has_constraints(embedded_msg):
                    return True
        return False

    def _get_field_size(self, field: Field, context: dict, remaining_bits: int) -> int | None:
        """Determine the size of a field in bytes."""
        field_type = field.type

        # Fixed-size types
        if isinstance(field_type, IntegerType):
            return field_type.byte_size

        if isinstance(field_type, EnumTypeRef):
            enum_def = self.get_enum(field_type.enum_name)
            if enum_def:
                base_type = IntegerType(base=enum_def.base_type)
                return base_type.byte_size
            # Check if it's a message type
            msg_def = self.coco_file.get_message(field_type.enum_name)
            if msg_def:
                if field.size is not None:
                    # Message array - evaluate size expression for byte count
                    if isinstance(field.size, LiteralSize):
                        # Literal is element count, not byte count - use remaining
                        return remaining_bits // 8
                    elif isinstance(field.size, FieldRefSize):
                        # Field ref could be element count or byte count
                        ref_value = self._resolve_field_path(field.size.field_path, context)
                        if ref_value is not None:
                            return remaining_bits // 8
                        return None  # Can't resolve size
                    elif isinstance(field.size, SizeExpr):
                        # Size expression is byte count
                        byte_count = self._eval_size_expr(field.size, context)
                        if byte_count is not None:
                            return byte_count
                        return None  # Can't resolve size expression
                    else:
                        # VariableSize - consume remaining
                        return remaining_bits // 8
                elif field.structure_body:
                    # Embedded message with overridden structure - calculate from structure_body
                    total = 0
                    for f in field.structure_body:
                        f_size = self._get_field_size(f, context, 0)
                        if f_size is None:
                            return None
                        total += f_size
                    return total
                else:
                    # Single embedded message - try fixed size, fall back to remaining
                    fixed_size = self._get_message_fixed_size(msg_def, context)
                    if fixed_size is not None:
                        return fixed_size
                    # Message has variable-length fields - consume remaining
                    return remaining_bits // 8 if remaining_bits > 0 else None
            return 1  # Default to 1 byte

        if isinstance(field_type, BitFieldType):
            return (field_type.bit_count + 7) // 8  # bits[N] is N bits, return bytes needed

        # Variable-size types - check size spec
        size = field.size
        if size is None:
            return remaining_bits // 8  # Consume rest

        if isinstance(size, LiteralSize):
            return size.value

        if isinstance(size, FieldRefSize):
            ref_value = self._resolve_field_path(size.field_path, context)
            if ref_value is not None:
                return int(ref_value)
            return None

        if isinstance(size, SizeExpr):
            return self._eval_size_expr(size, context)

        if isinstance(size, GreedySize):
            # Greedy size - consume all remaining bits
            return remaining_bits // 8

        if isinstance(size, FillToSize):
            # Fill to minimum size - consume bytes until total message size reaches target
            consumed_bytes = context.get('__consumed_bytes__', 0)
            needed_bytes = size.target_size - consumed_bytes
            return max(0, needed_bytes)

        if isinstance(size, UntilSize):
            # Evaluate the terminator value
            term_val = size.terminator
            if isinstance(term_val, EnumValue):
                enum_def = self.get_enum(term_val.enum_name)
                if enum_def:
                    member = next((m for m in enum_def.members if m.name == term_val.member_name), None)
                    terminator_byte = member.value if member else None
                else:
                    return None
            elif isinstance(term_val, int):
                terminator_byte = term_val
            else:
                return None

            if terminator_byte is None:
                return None

            # Align to byte for scanning
            byte_offset = (self.bit_offset + 7) // 8
            raw_bytes = self.data[byte_offset:]
            
            # Search for terminator byte
            term_idx = raw_bytes.find((terminator_byte & 0xFF).to_bytes(1, 'big'))
            if term_idx >= 0:
                return term_idx + 1
            return None

        if isinstance(size, VariableSize):
            if isinstance(field_type, StringType) and field_type.is_cstr:
                byte_offset = (self.bit_offset + 7) // 8
                raw_bytes = self.data[byte_offset:]
                null_idx = raw_bytes.find(b'\x00')
                if null_idx >= 0:
                    return null_idx + 1
            return remaining_bits // 8 if remaining_bits > 0 else None

        return remaining_bits // 8 if remaining_bits > 0 else None

    def _eval_size_expr(self, expr: SizeExpr, context: dict) -> int | None:
        """Evaluate a size expression to an integer value."""
        left_val = self._eval_size_operand(expr.left, context)
        right_val = self._eval_size_operand(expr.right, context)

        if left_val is None or right_val is None:
            return None

        if expr.op == '+':
            return left_val + right_val
        elif expr.op == '-':
            return max(0, left_val - right_val)  # Don't allow negative sizes
        elif expr.op == '*':
            return left_val * right_val
        return None

    def _eval_size_operand(self, operand, context: dict) -> int | None:
        """Evaluate a size operand (LiteralSize, FieldRefSize, or SizeExpr)."""
        if isinstance(operand, LiteralSize):
            return operand.value
        elif isinstance(operand, FieldRefSize):
            ref_value = self._resolve_field_path(operand.field_path, context)
            if ref_value is not None:
                return int(ref_value)
            return None
        elif isinstance(operand, SizeExpr):
            return self._eval_size_expr(operand, context)
        return None

    def _resolve_field_path(self, field_path: list[str], context: dict) -> int | None:
        """Resolve a field path like ['hdr', 'total_length'] to a value from context."""
        if not field_path:
            return None

        # Try the full dotted path first (for backward compatibility with flat keys)
        full_path = ".".join(field_path)
        if full_path in context:
            return context[full_path]

        # For simple paths, just look up directly
        if len(field_path) == 1:
            val = context.get(field_path[0])
            # Extract from FieldValue if present
            if isinstance(val, FieldValue):
                val = val.val
            return val

        # For nested paths, traverse the context
        # E.g., ['hdr', 'total_length'] -> look for context['hdr']['total_length']
        current = context
        for part in field_path:
            # Extract actual value from FieldValue if present
            if isinstance(current, FieldValue):
                current = current.val
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        # Extract final value from FieldValue if present
        if isinstance(current, FieldValue):
            current = current.val
        return current if isinstance(current, (int, float)) else None

    def _flatten_to_context(self, prefix: str, data: dict, context: dict) -> None:
        """Flatten a nested dict into dotted-path context entries.

        E.g., _flatten_to_context('hdr', {'total_length': 37}, context)
        adds context['hdr.total_length'] = 37
        """
        for key, value in data.items():
            full_key = f"{prefix}.{key}"
            # Extract actual value from FieldValue if present
            actual_val = value.val if isinstance(value, FieldValue) else value
            if isinstance(actual_val, dict):
                self._flatten_to_context(full_key, actual_val, context)
            elif isinstance(actual_val, (int, float, str)):
                # Store int, float, and string values (including enum decoded values)
                context[full_key] = actual_val

    def _encode_integer(self, value: int, int_type: IntegerType) -> str:
        """Encode an integer to hex string."""
        byte_size = int_type.byte_size
        endian = int_type.endian or self.default_endian

        if endian == Endianness.LITTLE:
            raw_bytes = value.to_bytes(byte_size, byteorder='little', signed=int_type.is_signed)
        else:
            raw_bytes = value.to_bytes(byte_size, byteorder='big', signed=int_type.is_signed)

        return raw_bytes.hex()

    def _decode_bitfield(self, int_val: int, field: Field, byte_count: int = 1) -> dict:
        """Decode a bitfield into individual fields.

        Args:
            int_val: Integer value of the bitfield
            field: Field definition with bitfield_body
            byte_count: Number of bytes (for hex formatting)
        """
        hex_width = byte_count * 2
        full_hex = format(int_val, f'0{hex_width}x')
        if not field.bitfield_body:
            return {"raw": FieldValue(full_hex, int_val)}

        result = {}
        bit_offset = 0
        for bf in field.bitfield_body.fields:
            mask = (1 << bf.bit_count) - 1
            value = (int_val >> bit_offset) & mask
            # For individual bits/sub-fields, hex is just the masked value
            bit_hex = format(value, 'x') if value > 0 else '0'
            result[bf.name] = FieldValue(bit_hex, value)
            bit_offset += bf.bit_count

        return result

    def _resolve_path(self, path: str, context: dict):
        """Resolve a dotted path like 'header.protocol' in the context."""
        parts = path.split('.')
        value = context
        for part in parts:
            # Extract actual value from FieldValue if present
            if isinstance(value, FieldValue):
                value = value.val
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
            if value is None:
                return None
        # Extract final value from FieldValue if present
        if isinstance(value, FieldValue):
            value = value.val
        return value

    def _decode_match(self, match_clause: MatchClause, context: dict) -> dict:
        """Decode a matched field based on discriminator value."""
        # Resolve dotted path discriminator (e.g., "header.protocol")
        discriminator_value = self._resolve_path(match_clause.discriminator, context)

        # Find matching branch
        matching_branch = None
        default_branch = None

        for branch in match_clause.branches:
            if branch.pattern is None:
                default_branch = branch
            elif isinstance(branch.pattern, EnumValue):
                # Check enum value match
                enum_str = f"{branch.pattern.enum_name}.{branch.pattern.member_name}"
                if discriminator_value == enum_str:
                    matching_branch = branch
                    break
                # Also check raw integer value
                enum_def = self.get_enum(branch.pattern.enum_name)
                if enum_def:
                    member = enum_def.get_member_by_name(branch.pattern.member_name)
                    if member and discriminator_value == member.value:
                        matching_branch = branch
                        break
            elif branch.pattern == discriminator_value:
                matching_branch = branch
                break

        branch = matching_branch or default_branch
        if branch and branch.fields:
            return self._decode_structure(branch.fields, context)

        return {}

    def _decode_structure(self, fields: list[Field], parent_context: dict, track_validity: bool = False) -> dict | tuple[dict, bool]:
        """Decode a nested structure.

        Returns:
            dict of FieldValue objects, or (dict, is_valid) if track_validity=True
        """
        result = {}
        context = dict(parent_context)
        all_valid = True

        for field in fields:
            # Track consumed bits for fill_to size calculation
            # Note: context uses bytes for compatibility with existing fill_to logic
            context['__consumed_bytes__'] = self.bit_offset // 8

            decode_result = self.decode_field(field, context)
            # Store both hex and decoded value for display flexibility
            result[field.name] = FieldValue(decode_result.hex_value, decode_result.decoded_value)
            # Context still uses plain values for size references and match lookups
            context[field.name] = decode_result.decoded_value
            # Flatten dict values for dotted path lookups
            if isinstance(decode_result.decoded_value, dict):
                self._flatten_to_context(field.name, decode_result.decoded_value, context)

            if not decode_result.is_valid:
                all_valid = False

        if track_validity:
            return result, all_valid
        return result

    def _decode_embedded_message(self, msg_def: Message, context: dict) -> tuple[dict, int]:
        """Decode a single embedded message.

        Returns:
            Tuple of (decoded message dict, consumed bit count)
        """
        start_bits = self.bit_offset
        fields = self.resolve_message(msg_def)
        result = {}
        local_context = dict(context)

        for field in fields:
            decode_result = self.decode_field(field, local_context)
            result[field.name] = FieldValue(decode_result.hex_value, decode_result.decoded_value)

            # Update local context
            val = decode_result.decoded_value
            if isinstance(val, (int, float, str)):
                local_context[field.name] = val
            elif isinstance(val, dict):
                local_context[field.name] = val
                self._flatten_to_context(field.name, val, local_context)

        consumed_bits = self.bit_offset - start_bits
        return result, consumed_bits

    def _decode_message_array(self, msg_def: Message, field: Field, context: dict) -> tuple[list, int]:
        """Decode an array of messages."""
        start_bits = self.bit_offset
        result = []

        # Determine count
        count = None
        if isinstance(field.size, LiteralSize):
            count = field.size.value
        elif isinstance(field.size, FieldRefSize):
            count = self._resolve_field_path(field.size.field_path, context) or 0

        # Get subtypes for polymorphic parsing
        subtypes = self.coco_file.get_subtypes(msg_def.name)
        candidate_types = sorted(subtypes, key=lambda m: -self._get_inheritance_depth(m.name)) if subtypes else [msg_def]
        fallback_type = msg_def if subtypes else None

        element_idx = 0
        while self.bit_offset < len(self.data) * 8:
            if count is not None and element_idx >= count:
                break

            # Try each candidate type and pick the best match
            best_result = None
            best_bits = 0
            original_offset = self.bit_offset

            for candidate in candidate_types:
                # Use a separate Decoder instance for trials to avoid corrupting state
                trial_decoder = Decoder(self.coco_file)
                trial_decoder.data = self.data
                trial_decoder.bit_offset = original_offset
                trial_decoder.default_endian = self.default_endian
                
                try:
                    trial_res = trial_decoder.validate_message(candidate, allow_remaining=True)
                    if trial_res.is_valid:
                        consumed = trial_decoder.bit_offset - original_offset
                        if consumed == 0:
                            continue
                            
                        if best_result is None or trial_res.validated_constraints > best_result.validated_constraints:
                            best_result = trial_res
                            best_bits = consumed
                except Exception:
                    continue

            if best_result:
                element_dict = {f.name: FieldValue(f.hex_value, f.decoded_value) for f in best_result.fields}
                result.append(element_dict)
                self.bit_offset = original_offset + best_bits
                element_idx += 1
            else:
                break

        return result, self.bit_offset - start_bits

    def validate_message(self, msg: Message, hex_str: str = None, allow_remaining: bool = False) -> ValidationResult:
        """Validate a binary message against a message definition.

        Args:
            msg: Message definition
            hex_str: Optional hex string to validate. If None, uses self.data.
            allow_remaining: If True, don't fail on remaining bytes

        Returns:
            ValidationResult with field-by-field results
        """
        if hex_str is not None:
            hex_str = hex_str.lower().replace(" ", "")
            try:
                self.data = bytes.fromhex(hex_str)
            except ValueError:
                self.data = b""
            self.bit_offset = 0
            
        fields = self.resolve_message(msg)

        # Reset protocol chain for this validation
        self._protocol_chain = []

        # Add root layer message to chain
        if msg.is_layer:
            self._protocol_chain.append(self._get_chain_name(msg.name))

        results = []
        context = {}
        all_valid = True

        for field in fields:
            # Track consumed bits for fill_to size calculation
            context['__consumed_bytes__'] = self.bit_offset // 8

            # Check if we have enough bits left
            # Special case for 0-length fields
            skip_no_bytes_check = isinstance(field.size, (GreedySize, FillToSize, BranchDeterminedSize))
            
            # Check if this is a message array with count=0
            if not skip_no_bytes_check and isinstance(field.type, EnumTypeRef):
                m_def = self.coco_file.get_message(field.type.enum_name)
                if m_def and field.size is not None:
                    count = None
                    if isinstance(field.size, LiteralSize):
                        count = field.size.value
                    elif isinstance(field.size, FieldRefSize):
                        count = self._resolve_field_path(field.size.field_path, context) or 0
                    if count == 0:
                        skip_no_bytes_check = True

            if self.bit_offset >= len(self.data) * 8 and not skip_no_bytes_check:
                results.append(DecodeResult(
                    name=field.name,
                    hex_value="",
                    decoded_value=None,
                    is_valid=False,
                    errors=["No bits remaining"]
                ))
                all_valid = False
                continue

            result = self.decode_field(field, context)
            results.append(result)

            # Update context with decoded value
            if isinstance(result.decoded_value, (int, float)):
                context[field.name] = result.decoded_value
            elif isinstance(result.decoded_value, dict):
                context[field.name] = result.decoded_value
                self._flatten_to_context(field.name, result.decoded_value, context)
            elif isinstance(result.decoded_value, str) and result.decoded_value.startswith("0x"):
                pass
            
            # For enum fields, store raw integer too
            if isinstance(field.type, EnumTypeRef) and result.hex_value:
                enum_def = self.get_enum(field.type.enum_name)
                if enum_def:
                    base_type = IntegerType(base=enum_def.base_type)
                    # Use a fresh decoder to avoid state corruption
                    temp_decoder = Decoder(self.coco_file)
                    temp_decoder.data = bytes.fromhex(result.hex_value)
                    int_val, _ = temp_decoder.decode_integer(base_type)
                    context[field.name] = int_val

            if not result.is_valid:
                all_valid = False

        remaining_bits = (len(self.data) * 8) - self.bit_offset
        remaining_hex = self.data[self.bit_offset // 8:].hex() if remaining_bits > 0 else ""

        return ValidationResult(
            is_valid=all_valid,
            message_name=msg.name,
            fields=results,
            remaining_bytes=remaining_hex,
            protocol_chain=list(self._protocol_chain),
        )

    def validate_by_name(self, message_name: str, hex_str: str) -> ValidationResult:
        """Validate a hex message by message name."""
        msg = self.coco_file.get_message(message_name)
        if msg is None:
            return ValidationResult(
                is_valid=False,
                message_name=message_name,
                fields=[],
                errors=[f"Message '{message_name}' not found"]
            )
        return self.validate_message(msg, hex_str)

    def identify_message(self, hex_str: str) -> list[ValidationResult]:
        """Try to identify which message type matches the hex string.

        Returns list of validation results, sorted by best match.
        """
        results = []

        for msg in self.coco_file.messages:
            result = self.validate_message(msg, hex_str)
            results.append(result)

        # Sort by: valid first, penalize unbounded fields at root, penalize remaining bytes,
        # then by validated constraints, then penalize invalid nested elements, then by structured fields,
        # then by matched bytes, then by inheritance depth
        results.sort(key=lambda r: (
            not r.is_valid,
            r.has_unbounded_fields,       # Penalize messages with unbounded bytes[] at root level
            len(r.remaining_bytes),       # Strongly prefer complete parses (fewer remaining bytes is better)
            -r.validated_constraints,     # Prefer messages with more validated enum/default fields
            r.minimal_array_elements,     # Penalize messages with many single-field array elements
            -r.total_structured_fields,   # Prefer messages that parse into more leaf fields
            -r.total_matched_bytes,
            -self._get_inheritance_depth(r.message_name) if r.is_valid else 0,  # Only prefer children when valid
        ))

        return results

    def _get_inheritance_depth(self, message_name: str) -> int:
        """Get the inheritance depth of a message (0 = base, 1 = one parent, etc.)."""
        depth = 0
        msg = self.coco_file.get_message(message_name)
        while msg and msg.parent:
            depth += 1
            msg = self.coco_file.get_message(msg.parent)
        return depth


def validate_message(coco_file: CocoFile, message_name: str, hex_str: str) -> ValidationResult:
    """Convenience function to validate a message."""
    decoder = Decoder(coco_file)
    return decoder.validate_by_name(message_name, hex_str)


def identify_message(coco_file: CocoFile, hex_str: str) -> list[ValidationResult]:
    """Convenience function to identify a message."""
    decoder = Decoder(coco_file)
    return decoder.identify_message(hex_str)
